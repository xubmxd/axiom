// Target services for the Module 6 / 6.3.3 Port Scanning with Nmap lab.
//
// One module describes every target personality; the Docker image and the
// local sandbox both run it, so observable behavior is identical on every
// provider. Roles take runtime values (flags) as arguments — nothing
// answer-bearing is baked in.
//
// Roles:
//   smtp   — TCP/25 bare acceptor (open-port discovery target, .8)
//   whois  — TCP/43 minimal WHOIS responder (service-discovery target, .251)
//   dc     — TCP 53/88/135/139 bare acceptors (port-ordering target, .151)
//   vm1    — TCP/59811 flag service + TCP/80 HTTP with an embedded flag
//            ("Under Construction" title; flag on /index.html)
import net from "node:net";
import { fileURLToPath } from "node:url";
import { buildWhoisResponse } from "./whois-data.js";

export const NMAP_SLUG = "m6-6-3-3-nmap";
// Canonical display octets for the multi-target lab group.
export const NMAP_OCTETS = { smtp: 8, whois: 251, dc: 151, vm1: 100 };

function listenTcp(host, port, onConn, conns) {
  return new Promise((resolve, reject) => {
    const srv = net.createServer((conn) => {
      conns.add(conn);
      conn.on("close", () => conns.delete(conn));
      conn.on("error", () => {});
      conn.setTimeout(10000);
      conn.on("timeout", () => conn.destroy());
      onConn(conn);
    });
    srv.on("error", reject);
    srv.listen(port, host, () => resolve(srv));
  });
}

// Bare acceptor: completes TCP handshakes, holds briefly, never banners.
// Port STATE is the exercise; versions are deliberately unclaimed.
function acceptAndHold(conn) {
  conn.on("data", () => {});
  setTimeout(() => { try { conn.end(); } catch {} }, 5000).unref?.();
}

function whoisConn(conn) {
  let buf = "";
  const kill = setTimeout(() => conn.destroy(), 8000);
  conn.on("data", (d) => {
    buf += d.toString("utf8");
    if (buf.includes("\n") || buf.length > 1024) {
      clearTimeout(kill);
      const q = buf.split(/\r?\n/)[0].trim();
      try { conn.end(buildWhoisResponse(q)); } catch {}
    }
  });
}

function flagConn(flag) {
  return (conn) => {
    try { conn.write(`flag: ${flag}\n`); } catch {}
    conn.on("data", () => {});
    setTimeout(() => { try { conn.end(); } catch {} }, 2000).unref?.();
  };
}

function httpConn(flag) {
  const body = [
    `<!DOCTYPE html>`,
    `<html>`,
    `<head><title>Under Construction</title></head>`,
    `<body>`,
    `<h1>Under Construction</h1>`,
    `<p>This site is under construction. Please check back soon.</p>`,
    `<!-- flag: ${flag} -->`,
    `</body>`,
    `</html>`,
    ``,
  ].join("\n");
  return (conn) => {
    let buf = "";
    const kill = setTimeout(() => conn.destroy(), 8000);
    conn.on("data", (d) => {
      buf += d.toString("utf8");
      if (buf.includes("\r\n\r\n") || buf.includes("\n\n") || buf.length > 4096) {
        clearTimeout(kill);
        const head = `HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n`;
        try { conn.end(head + body); } catch {}
      }
    });
  };
}

// role: "smtp" | "whois" | "dc" | "vm1"
// opts: { host, ports } — ports override per role for loopback mapping:
//   smtp: { tcp25 }, whois: { tcp43 }, dc: { tcp53, tcp88, tcp135, tcp139 },
//   vm1: { tcp59811, tcp80 }. Omitted entries bind ephemeral ports.
// flags: { q4, q5 } — per-instance secret values served by vm1.
export async function startRole(role, { host = "127.0.0.1", ports = {}, flags = {} } = {}) {
  const conns = new Set();
  const servers = [];
  const P = (k, dflt) => ports[k] ?? dflt;
  if (role === "smtp") {
    servers.push(await listenTcp(host, P("tcp25", 25), acceptAndHold, conns));
  } else if (role === "whois") {
    servers.push(await listenTcp(host, P("tcp43", 43), whoisConn, conns));
  } else if (role === "dc") {
    for (const [key, fixed] of [["tcp53", 53], ["tcp88", 88], ["tcp135", 135], ["tcp139", 139]]) {
      servers.push(await listenTcp(host, P(key, fixed), acceptAndHold, conns));
    }
  } else if (role === "vm1") {
    servers.push(await listenTcp(host, P("tcp59811", 59811), flagConn(flags.q4 || "AXIOM{unprovisioned}"), conns));
    servers.push(await listenTcp(host, P("tcp80", 80), httpConn(flags.q5 || "AXIOM{unprovisioned}"), conns));
  } else {
    throw new Error(`Unknown target role: ${role}`);
  }
  return {
    role,
    ports: servers.map((s) => s.address().port),
    close: async () => {
      for (const c of conns) { try { c.destroy(); } catch {} }
      conns.clear();
      for (const s of servers) await new Promise((r) => s.close(r)).catch(() => {});
    },
  };
}

// Standalone entrypoint (used by the Docker image).
//   TARGET_ROLE=smtp|whois|dc|vm1  TARGET_HOST=0.0.0.0 [fixed ports]
//   FLAG_Q4 / FLAG_Q5 provide the per-instance secrets for vm1.
const invokedAsMain = (() => {
  try { return process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]; } catch { return false; }
})();
if (invokedAsMain) {
  const role = process.env.TARGET_ROLE || "";
  const fixed = process.env.TARGET_FIXED_PORTS === "1";
  const pick = (env, dflt) => (fixed ? dflt : 0);
  const ports =
    role === "smtp" ? { tcp25: pick(0, 25) }
    : role === "whois" ? { tcp43: pick(0, 43) }
    : role === "dc" ? { tcp53: pick(0, 53), tcp88: pick(0, 88), tcp135: pick(0, 135), tcp139: pick(0, 139) }
    : role === "vm1" ? { tcp59811: pick(0, 59811), tcp80: pick(0, 80) }
    : null;
  if (!ports) {
    console.error("TARGET_ROLE must be smtp|whois|dc|vm1");
    process.exit(1);
  }
  startRole(role, {
    host: process.env.TARGET_HOST || "0.0.0.0",
    ports,
    flags: { q4: process.env.FLAG_Q4 || "", q5: process.env.FLAG_Q5 || "" },
  })
    .then(() => console.log(`axiom-lab-nmap target role=${role} listening`))
    .catch((e) => { console.error("nmap target failed to start", e?.message || e); process.exit(1); });
}
