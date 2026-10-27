// Minimal DNS client for the lab terminal, readiness probes, and tests.
//
// Speaks real wire-format DNS to the lab target over UDP with TCP fallback
// (truncated UDP responses retry over TCP). Never used against external
// infrastructure — only the instance's own endpoint.
import dgram from "node:dgram";
import net from "node:net";
import { QTYPE } from "./dns-server.js";

const TYPE_NAMES = Object.fromEntries(Object.entries(QTYPE).map(([k, v]) => [v, k]));

function encodeName(n) {
  const parts = n.toLowerCase().replace(/\.+$/, "").split(".").filter(Boolean);
  const bufs = parts.map((lb) => {
    const b = Buffer.from(lb, "utf8");
    return Buffer.concat([Buffer.from([b.length]), b]);
  });
  return Buffer.concat([...bufs, Buffer.from([0])]);
}

function buildQuery(name, type, id) {
  const qn = encodeName(name);
  const pkt = Buffer.alloc(12 + qn.length + 4);
  pkt.writeUInt16BE(id, 0);
  pkt.writeUInt16BE(0x0100, 2); // RD
  pkt.writeUInt16BE(1, 4);
  qn.copy(pkt, 12);
  pkt.writeUInt16BE(QTYPE[type] ?? 1, 12 + qn.length);
  pkt.writeUInt16BE(1, 12 + qn.length + 2);
  return pkt;
}

function readName(buf, off) {
  const labels = [];
  let jumped = false;
  let end = off;
  let guard = 0;
  while (guard++ < 64) {
    const len = buf[off];
    if ((len & 0xc0) === 0xc0) {
      const ptr = ((len & 0x3f) << 8) | buf[off + 1];
      if (!jumped) end = off + 2;
      off = ptr;
      jumped = true;
      continue;
    }
    if (len === 0) { if (!jumped) end = off + 1; break; }
    if (off + 1 + len > buf.length) throw new Error("bad name");
    labels.push(buf.slice(off + 1, off + 1 + len).toString("utf8"));
    off += 1 + len;
  }
  return { name: labels.join("."), end };
}

function parseRdata(buf, off, rdlen, type) {
  if (type === 1 && rdlen === 4) return [...buf.slice(off, off + 4)].join(".");
  // Absolute domain names keep their trailing dot, matching real-tool output.
  if (type === 2 || type === 5) return readName(buf, off).name + ".";
  if (type === 6) {
    const m = readName(buf, off);
    const r = readName(buf, m.end);
    const o = r.end;
    return {
      mname: m.name + ".", rname: r.name + ".",
      serial: buf.readUInt32BE(o), refresh: buf.readUInt32BE(o + 4),
      retry: buf.readUInt32BE(o + 8), expire: buf.readUInt32BE(o + 12),
      minimum: buf.readUInt32BE(o + 16),
    };
  }
  if (type === 15) return { preference: buf.readUInt16BE(off), exchange: readName(buf, off + 2).name + "." };
  if (type === 16) {
    const out = [];
    let p = off;
    const end = off + rdlen;
    while (p < end) {
      const l = buf[p];
      out.push(buf.slice(p + 1, p + 1 + l).toString("utf8"));
      p += 1 + l;
    }
    return out;
  }
  if (type === 28 && rdlen === 16) {
    const g = [];
    for (let i = 0; i < 16; i += 2) g.push(buf.readUInt16BE(off + i).toString(16));
    return g.join(":").replace(/(^|:)0(:0)+(:|$)/, "$1::$3").replace(/:{3,}/, "::");
  }
  return buf.slice(off, off + rdlen).toString("hex");
}

export function parseResponse(buf) {
  if (buf.length < 12) throw new Error("short response");
  const rcode = buf[3] & 0x0f;
  const tc = (buf[2] & 0x02) !== 0;
  const an = buf.readUInt16BE(6), ns = buf.readUInt16BE(8), ar = buf.readUInt16BE(10);
  const qd = buf.readUInt16BE(4);
  let off = 12;
  for (let i = 0; i < qd; i++) {
    const q = readName(buf, off);
    off = q.end + 4;
  }
  const section = (n) => {
    const out = [];
    for (let i = 0; i < n; i++) {
      const nm = readName(buf, off);
      const type = buf.readUInt16BE(nm.end);
      const ttl = buf.readUInt32BE(nm.end + 4);
      const rdlen = buf.readUInt16BE(nm.end + 8);
      const data = parseRdata(buf, nm.end + 10, rdlen, type);
      out.push({ name: nm.name, type: TYPE_NAMES[type] || `TYPE${type}`, ttl, data });
      off = nm.end + 10 + rdlen;
    }
    return out;
  };
  return { rcode, tc, answers: section(an), authority: section(ns), additional: section(ar) };
}

function udpQuery(host, port, pkt, timeoutMs) {
  return new Promise((resolve, reject) => {
    const sock = dgram.createSocket("udp4");
    const timer = setTimeout(() => { sock.close(); reject(new Error("DNS query timed out.")); }, timeoutMs);
    sock.on("error", (e) => { clearTimeout(timer); sock.close(); reject(e); });
    sock.on("message", (msg) => { clearTimeout(timer); sock.close(); resolve(msg); });
    sock.send(pkt, port, host, (e) => { if (e) { clearTimeout(timer); sock.close(); reject(e); } });
  });
}

function tcpQuery(host, port, pkt, timeoutMs) {
  return new Promise((resolve, reject) => {
    const sock = new net.Socket();
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => { sock.destroy(); reject(new Error("DNS query timed out.")); }, timeoutMs);
    sock.on("error", (e) => { clearTimeout(timer); reject(e); });
    sock.connect(port, host, () => {
      const pre = Buffer.alloc(2); pre.writeUInt16BE(pkt.length);
      sock.write(Buffer.concat([pre, pkt]));
    });
    sock.on("data", (d) => {
      buf = Buffer.concat([buf, d]);
      if (buf.length >= 2 && buf.length >= 2 + buf.readUInt16BE(0)) {
        clearTimeout(timer);
        const out = buf.slice(2, 2 + buf.readUInt16BE(0));
        sock.destroy();
        resolve(out);
      }
    });
  });
}

let nextId = 1;

export async function dnsQuery(host, port, name, type = "A", { timeoutMs = 5000, tcp = null } = {}) {
  const t = String(type).toUpperCase();
  const id = (nextId = (nextId % 65534) + 1);
  const pkt = buildQuery(name, t, id);
  const useTcp = tcp === true;
  const raw = useTcp ? await tcpQuery(host, port, pkt, timeoutMs) : await udpQuery(host, port, pkt, timeoutMs);
  const res = parseResponse(raw);
  if (!useTcp && res.tc) {
    // Truncated UDP reply: retry the same query over TCP.
    const rawTcp = await tcpQuery(host, port, pkt, timeoutMs);
    return { ...parseResponse(rawTcp), viaTcp: true };
  }
  return res;
}

export async function waitForDns(host, port, name = "megacorpone.com", { tries = 30, delayMs = 1000 } = {}) {
  let last = null;
  for (let i = 0; i < tries; i++) {
    try {
      const out = await dnsQuery(host, port, name, "MX", { timeoutMs: 4000 });
      if (out.rcode === 0 && out.answers.length > 0) return out;
      last = new Error("Unexpected DNS response.");
    } catch (e) { last = e; }
    await new Promise((r) => setTimeout(r, delayMs));
  }
  throw last || new Error("Target DNS service did not become ready.");
}
