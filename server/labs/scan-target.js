// Scan target for the Module 6 / 6.3.2 TCP/UDP Port Scanning Theory lab.
//
// A real listening target (not scan-output theater): genuine TCP acceptors
// plus UDP responders, so connect-style Netcat scans observe true
// open/closed behavior — closed TCP ports RST, closed UDP ports return
// ICMP unreachable, open ports complete or reply.
//
// Canonical port spec (kept HERE, not in lab.json, so the API's target
// listing can never leak the answers):
//   TCP open: 53, 88, 135, 139, 9389   (lowest 53, highest-in-1-10000 9389;
//                                        88/135/139 pre-position the 6.3.3 DC
//                                        reuse without affecting this lab)
//   UDP open: 123 (NTP), 161 (SNMP-like responder)
// Display convention: the target IP always ends in .151 (see orchestrator).
// Service banners/versions are intentionally absent: the source material
// does not establish them, and this lab is about port state, not banners.
import dgram from "node:dgram";
import net from "node:net";
import { fileURLToPath } from "node:url";

export const SCAN_SLUG = "m6-6-3-2-port-scanning";
export const SCAN_TCP_PORTS = [53, 88, 135, 139, 9389];
export const SCAN_UDP_PORTS = [123, 161];
// Canonical order used by the host_endpoint port-map encoding.
export const SCAN_PORT_ORDER = [
  ...SCAN_TCP_PORTS.map((port) => ({ proto: "tcp", port })),
  ...SCAN_UDP_PORTS.map((port) => ({ proto: "udp", port })),
];
export const SCAN_DISPLAY_OCTET = 151;

// Minimal NTP server reply (48 bytes, mode 4). Sent in response to ANY
// datagram so empty Netcat probes deterministically detect an open port.
export function ntpReply() {
  const b = Buffer.alloc(48);
  b[0] = 0x24; // LI=0, VN=4, Mode=4 (server)
  b[1] = 1; // stratum 1
  const now = Date.now() / 1000 + 2208988800; // unix -> NTP epoch
  b.writeUInt32BE(Math.floor(now), 40);
  b.writeUInt32BE(Math.floor((now % 1) * 0xffffffff), 44);
  return b;
}

// Minimal SNMP GetResponse (valid BER). Fixed sysDescr binding; request-id
// echoed back as zero. Any datagram — including Netcat's empty probe —
// gets a reply, which is what makes the port detectably open.
export function snmpReply() {
  const sysDescr = Buffer.from("Axiom lab target", "utf8");
  const oid = Buffer.from([0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]);
  const val = Buffer.concat([Buffer.from([0x04, sysDescr.length]), sysDescr]);
  const vb = Buffer.concat([Buffer.from([0x30, oid.length + val.length]), oid, val]);
  const vblist = Buffer.concat([Buffer.from([0x30, vb.length]), vb]);
  const pduBody = Buffer.concat([
    Buffer.from([0x02, 0x01, 0x00]), // request-id 0
    Buffer.from([0x02, 0x01, 0x00]), // error-status 0
    Buffer.from([0x02, 0x01, 0x00]), // error-index 0
    vblist,
  ]);
  const pdu = Buffer.concat([Buffer.from([0xa2, pduBody.length]), pduBody]);
  const community = Buffer.from("public", "utf8");
  const msgBody = Buffer.concat([
    Buffer.from([0x02, 0x01, 0x01]), // version 1 (SNMPv2c)
    Buffer.concat([Buffer.from([0x04, community.length]), community]),
    pdu,
  ]);
  return Buffer.concat([Buffer.from([0x30, msgBody.length]), msgBody]);
}

// Start every listener on one loopback interface. With no explicit ports,
// all listeners bind ephemeral loopback ports and the caller maps them.
export function startScanTarget({ host = "127.0.0.1", tcpPorts = null, udpPorts = null } = {}) {
  return new Promise((resolve, reject) => {
    const tcpWanted = tcpPorts || SCAN_TCP_PORTS.map(() => 0);
    const udpWanted = udpPorts || SCAN_UDP_PORTS.map(() => 0);
    const tcpServers = [];
    const udpSockets = [];
    const conns = new Set();
    const close = async () => {
      for (const c of conns) { try { c.destroy(); } catch {} }
      conns.clear();
      for (const s of tcpServers) await new Promise((r) => s.close(r)).catch(() => {});
      for (const s of udpSockets) { try { s.close(); } catch {} }
    };
    const udp = udpWanted.map((want, i) => new Promise((res, rej) => {
      const sock = dgram.createSocket("udp4");
      sock.on("message", (msg, rinfo) => {
        try {
          const reply = SCAN_UDP_PORTS[i] === 123 ? ntpReply() : snmpReply();
          sock.send(reply, rinfo.port, rinfo.address, () => {});
        } catch { /* never crash the target */ }
      });
      sock.on("error", () => {});
      sock.bind(want, host, () => {
        udpSockets.push(sock);
        res(sock.address().port);
      });
      sock.on("error", rej);
    }));
    const tcp = tcpWanted.map((want) => new Promise((res, rej) => {
      const srv = net.createServer((conn) => {
        conns.add(conn);
        conn.on("close", () => conns.delete(conn));
        conn.on("error", () => {});
        conn.setTimeout(10000);
        conn.on("data", () => {});
        conn.on("timeout", () => conn.destroy());
      });
      srv.on("error", rej);
      srv.listen(want, host, () => {
        tcpServers.push(srv);
        res(srv.address().port);
      });
    }));
    Promise.all([...udp, ...tcp]).then(([u0, u1, t0, t1, t2, t3, t4]) => {
      // Order follows SCAN_PORT_ORDER regardless of bind completion order.
      resolve({
        tcp: { 53: t0, 88: t1, 135: t2, 139: t3, 9389: t4 },
        udp: { 123: u0, 161: u1 },
        close,
      });
    }).catch(async (e) => { await close(); reject(e); });
  });
}

// Standalone target entrypoint (used by the Docker image).
const invokedAsMain = (() => {
  try { return process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]; } catch { return false; }
})();
if (invokedAsMain) {
  const fixed = process.env.SCAN_FIXED_PORTS === "1";
  startScanTarget({
    host: "0.0.0.0",
    tcpPorts: fixed ? SCAN_TCP_PORTS : null,
    udpPorts: fixed ? SCAN_UDP_PORTS : null,
  })
    .then(() => console.log("axiom-lab-scan listening (tcp 53,88,135,139,9389 udp 123,161)"))
    .catch((e) => { console.error("scan target failed to start", e?.message || e); process.exit(1); });
}
