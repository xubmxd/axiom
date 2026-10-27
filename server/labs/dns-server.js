// Authoritative DNS service for the Module 6 / 6.3.1 DNS Enumeration lab.
//
// A real, standards-compliant DNS server (not a canned-response script):
// it parses wire-format queries and serves the zones from dns-zones.js
// over both UDP and TCP port 53. The same module backs the local-process
// provider and ships inside the Docker target image, so observable
// behavior is identical on every provider.
//
// Supported: A, NS, CNAME, SOA, MX, TXT, AAAA (NODATA), ANY. AXFR and
// out-of-zone names are REFUSED, like a real auth-only server. Unknown
// in-zone names answer NXDOMAIN with the zone SOA in authority.
import dgram from "node:dgram";
import net from "node:net";
import { fileURLToPath } from "node:url";
import { DNS_ZONES } from "./dns-zones.js";

export const QTYPE = { A: 1, NS: 2, CNAME: 5, SOA: 6, MX: 15, TXT: 16, AAAA: 28, AXFR: 252, ANY: 255 };
const QNAME = Object.fromEntries(Object.entries(QTYPE).map(([k, v]) => [v, k]));

const APEXES = Object.keys(DNS_ZONES);

function expand(name, apex) {
  return name === "@" ? apex : `${name}.${apex}`.toLowerCase();
}

function zoneOf(fqdn) {
  const n = fqdn.toLowerCase().replace(/\.+$/, "");
  const hit = APEXES.filter((a) => n === a || n.endsWith(`.${a}`)).sort((a, b) => b.length - a.length)[0];
  return hit || null;
}

function recordsAt(apex, fqdn) {
  const n = fqdn.toLowerCase().replace(/\.$/, "");
  const short = n === apex ? "@" : n.endsWith(`.${apex}`) ? n.slice(0, -(apex.length + 1)) : null;
  if (short === null) return null;
  return DNS_ZONES[apex].filter((r) => (r.name === "@" ? apex : `${r.name}.${apex}`) === n)
    .map((r) => ({ ...r, fqdn: n }));
}

function apexSoa(apex) {
  return { ...DNS_ZONES[apex].find((r) => r.name === "@" && r.type === "SOA"), fqdn: apex };
}

// Pure resolution: { rcode, answers, authority, additional } as record
// objects. qtype may be a name ("MX") or an unknown numeric type (which
// matches nothing → NODATA, per RFC 3597-style handling). Exported for
// tests; the socket layer only serializes this.
export function resolveQuestion(qname, qtype) {
  const fqdn = qname.toLowerCase().replace(/\.+$/, "");
  // Reverse-DNS space answers NXDOMAIN (fast, cacheable): scanners doing
  // bulk PTR lookups must never stall on refused responses.
  if (fqdn.endsWith(".in-addr.arpa") || fqdn.endsWith(".ip6.arpa") || fqdn === "in-addr.arpa" || fqdn === "ip6.arpa") {
    return { rcode: 3, answers: [], authority: [], additional: [] };
  }
  const qt = typeof qtype === "number" ? (QNAME[qtype] || `TYPE${qtype}`) : String(qtype).toUpperCase();
  const apex = zoneOf(fqdn);
  if (!apex) return { rcode: 5, answers: [], authority: [], additional: [] }; // REFUSED: not authoritative
  if (qt === "AXFR") return { rcode: 5, answers: [], authority: [], additional: [] }; // REFUSED: no zone transfers
  const at = recordsAt(apex, fqdn);
  if (!at.length) return { rcode: 3, answers: [], authority: [apexSoa(apex)], additional: [] }; // NXDOMAIN
  const answers = qt === "ANY" ? at : at.filter((r) => r.type === qt);
  if (!answers.length) return { rcode: 0, answers: [], authority: [apexSoa(apex)], additional: [] }; // NODATA
  const additional = [];
  for (const r of answers) {
    const targets = r.type === "MX" ? [r.data.exchange] : r.type === "NS" ? [r.data] : [];
    for (const t of targets) {
      const g = recordsAt(apex, t.replace(/\.$/, ""));
      for (const gr of g || []) if (gr.type === "A") additional.push(gr);
    }
  }
  return { rcode: 0, answers, authority: [], additional };
}

// ---------- wire codec ----------
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
    if (len === 0) {
      if (!jumped) end = off + 1;
      break;
    }
    labels.push(buf.slice(off + 1, off + 1 + len).toString("utf8"));
    off += 1 + len;
  }
  return { name: labels.join("."), end };
}

function parseQuery(buf) {
  if (buf.length < 12) return null;
  const qdcount = buf.readUInt16BE(4);
  if (qdcount < 1) return null;
  const { name, end } = readName(buf, 12);
  if (end + 4 > buf.length) return null;
  return {
    id: buf.readUInt16BE(0),
    rd: (buf[2] & 0x01) === 0x01,
    qname: name,
    qtype: buf.readUInt16BE(end),
    qclass: buf.readUInt16BE(end + 2),
    questionEnd: end + 4,
  };
}

class Writer {
  constructor() { this.parts = []; this.length = 0; this.offsets = new Map(); }
  get offset() { return this.length; }
  bytes(b) { this.parts.push(b); this.length += b.length; }
  u16(v) { const b = Buffer.alloc(2); b.writeUInt16BE(v); this.bytes(b); }
  u32(v) { const b = Buffer.alloc(4); b.writeUInt32BE(v); this.bytes(b); }
  name(n) {
    const lower = n.toLowerCase().replace(/\.+$/, "");
    const labels = lower === "" ? [] : lower.split(".");
    for (let i = 0; i < labels.length; i++) {
      const suffix = labels.slice(i).join(".");
      if (this.offsets.has(suffix)) {
        const ptr = this.offsets.get(suffix);
        const b = Buffer.alloc(2); b.writeUInt16BE(0xc000 | ptr); this.bytes(b);
        return;
      }
      if (ptrFits(this.offset)) this.offsets.set(suffix, this.offset);
      const lb = Buffer.from(labels[i], "utf8");
      this.bytes(Buffer.from([lb.length]));
      this.bytes(lb);
    }
    this.bytes(Buffer.from([0]));
  }
}

function ptrFits(off) { return off < 0x4000; }

// RDATA domain names are written WITHOUT compression (full labels),
// which is always valid on the wire; only owner names use pointers.
function encodeRdataFlat(w, rec) {
  const data = rec.data;
  const flat = (n) => {
    const out = [];
    for (const lb of n.toLowerCase().replace(/\.+$/, "").split(".")) {
      const lb2 = Buffer.from(lb, "utf8");
      out.push(Buffer.from([lb2.length]), lb2);
    }
    out.push(Buffer.from([0]));
    return Buffer.concat(out);
  };
  switch (rec.type) {
    case "A": w.u16(4); w.bytes(Buffer.from(data.split(".").map((x) => parseInt(x, 10)))); break;
    case "AAAA": w.u16(16); w.bytes(Buffer.alloc(16)); break;
    case "NS":
    case "CNAME": { const rb = flat(data); w.u16(rb.length); w.bytes(rb); break; }
    case "MX": {
      const ex = flat(data.exchange);
      const rb = Buffer.alloc(2 + ex.length); rb.writeUInt16BE(data.preference, 0); ex.copy(rb, 2);
      w.u16(rb.length); w.bytes(rb); break;
    }
    case "SOA": {
      const rb = Buffer.concat([flat(data.mname), flat(data.rname), (() => {
        const n = Buffer.alloc(20);
        n.writeUInt32BE(data.serial, 0); n.writeUInt32BE(data.refresh, 4);
        n.writeUInt32BE(data.retry, 8); n.writeUInt32BE(data.expire, 12);
        n.writeUInt32BE(data.minimum, 16); return n;
      })()]);
      w.u16(rb.length); w.bytes(rb); break;
    }
    case "TXT": {
      const chunks = [];
      for (const s of data) {
        const sb = Buffer.from(s, "utf8");
        for (let i = 0; i < sb.length; i += 255) chunks.push(sb.slice(i, i + 255));
      }
      const rb = Buffer.concat(chunks.map((c) => Buffer.concat([Buffer.from([c.length]), c])));
      w.u16(rb.length); w.bytes(rb); break;
    }
    default: w.u16(0);
  }
}

function encodeRR(w, rec) {
  w.name(rec.fqdn);
  w.u16(QTYPE[rec.type] || 1);
  w.u16(1); // IN
  w.u32(rec.ttl);
  encodeRdataFlat(w, rec);
}

export function buildResponse(query, resolution) {
  const w = new Writer();
  const flags = 0x8000 /* QR */ | 0x0400 /* AA */ | (query.rd ? 0x0100 : 0) | (resolution.rcode & 0x000f);
  w.u16(query.id); w.u16(flags);
  const qd = 1;
  w.u16(qd);
  w.u16(resolution.answers.length);
  w.u16(resolution.authority.length);
  w.u16(resolution.additional.length);
  // echo the question section verbatim
  w.name(query.qname === "" ? "." : query.qname);
  w.u16(query.qtype); w.u16(query.qclass);
  for (const r of resolution.answers) encodeRR(w, r);
  for (const r of resolution.authority) encodeRR(w, r);
  for (const r of resolution.additional) encodeRR(w, r);
  return Buffer.concat(w.parts);
}

export function answerPacket(buf) {
  const q = parseQuery(buf);
  if (!q) return null;
  const qtypeName = QNAME[q.qtype] || q.qtype;
  return buildResponse(q, resolveQuestion(q.qname, qtypeName));
}

// ---------- socket layer ----------
export function startDnsServer({ host = "127.0.0.1", port = 0 } = {}) {
  return new Promise((resolve, reject) => {
    const udp = dgram.createSocket("udp4");
    udp.on("message", (msg, rinfo) => {
      try {
        const out = answerPacket(msg);
        if (out) udp.send(out, rinfo.port, rinfo.address, () => {});
      } catch { /* never crash the target on malformed input */ }
    });
    udp.on("error", () => {});
    udp.bind(port, host, () => {
      const bound = udp.address().port;
      const tcp = net.createServer((sock) => {
        let buf = Buffer.alloc(0);
        const kill = setTimeout(() => sock.destroy(), 10000);
        sock.on("data", (d) => {
          buf = Buffer.concat([buf, d]);
          while (buf.length >= 2) {
            const len = buf.readUInt16BE(0);
            if (buf.length < 2 + len) break;
            const msg = buf.slice(2, 2 + len);
            buf = buf.slice(2 + len);
            try {
              const out = answerPacket(msg);
              if (out) {
                const pre = Buffer.alloc(2); pre.writeUInt16BE(out.length);
                sock.write(Buffer.concat([pre, out]));
              }
            } catch { /* malformed input is ignored */ }
          }
        });
        sock.on("close", () => clearTimeout(kill));
        sock.on("error", () => {});
      });
      tcp.on("error", (e) => {
        udp.close();
        if (e?.code === "EADDRINUSE" && port === 0) {
          // Rare race: UDP grabbed an ephemeral port whose TCP twin is
          // taken. Retry with a fresh pairing.
          startDnsServer({ host, port: 0 }).then(resolve, reject);
        } else reject(e);
      });
      tcp.listen(bound, host, () => resolve({
        udp, tcp, port: bound, host,
        close: () => new Promise((r) => { try { udp.close(); } catch {} tcp.close(() => r()); setTimeout(r, 100).unref?.(); }),
      }));
    });
    udp.on("error", reject);
  });
}

// Standalone target entrypoint (used by the Docker image): serve on 0.0.0.0:53.
const invokedAsMain = (() => {
  try { return process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]; } catch { return false; }
})();
if (invokedAsMain) {
  const port = parseInt(process.env.DNS_PORT || "53", 10) || 53;
  startDnsServer({ host: "0.0.0.0", port })
    .then((s) => console.log(`axiom-lab-dns listening on 0.0.0.0:${s.port}/udp+tcp`))
    .catch((e) => { console.error("dns target failed to start", e?.message || e); process.exit(1); });
}
