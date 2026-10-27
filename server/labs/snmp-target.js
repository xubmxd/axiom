// SNMP target for Module 6 / 6.3.6 SNMP Enumeration.
//
// A genuine SNMPv1/v2c agent (not reply theater): real BER decode/encode,
// community validation, and Get/GetNext/GetBulk against a deterministic
// Windows-like HOST-RESOURCES-MIB + IF-MIB view, so onesixtyone, snmpwalk,
// and Nmap SNMP probes observe true agent behavior over real UDP/161.
// The exercise answers (snmp.exe in hrSWRunName; Software Loopback
// Interface 1 as ifDescr.1) come from the MIB data itself.
//
// Canonical data spec (kept HERE, not in lab.json, so the API's target
// listing can never leak the answers):
//   community: public (any other community -> silent drop, per agent practice)
//   UDP open: 161 (only the snmp role; decoys reuse nmap roles, no UDP)
// Display convention: the SNMP host ends in .151 (see orchestrator).
//
// OS fidelity note: the source describes a Windows host. Axiom has no
// Windows-capable target path, so this is a hardened SNMP target whose
// MIB DATA looks like the intended Windows environment (Windows process
// names incl. snmp.exe, Windows interface names). The SNMP behavior is
// reproduced; the Windows OS identity is not.
import dgram from "node:dgram";
import { fileURLToPath } from "node:url";

export const SNMP_SLUG = "m6-6-3-6-snmp";
export const SNMP_ROLES = new Set(["snmp"]);
export const SNMP_PORT = 161;
export const SNMP_OCTETS = { snmp: 151, decoyWhois: 22, decoyDc: 11 };
export const SNMP_COMMUNITY = "public";

// ------------------------------------------------------------ MIB view
// Lexicographically ordered (oid array, type, value). GetNext/GetBulk walk
// this order; the exact sequence below is the deterministic enumeration
// surface the exercise depends on.
const S_PROCESS_NAMES = [
  "System",
  "smss.exe",
  "csrss.exe",
  "wininit.exe",
  "services.exe",
  "lsass.exe",
  "svchost.exe",
  "snmp.exe",
  "spoolsv.exe",
  "explorer.exe",
  "SearchIndexer.exe",
  "wmpnetwk.exe",
];
const S_IF_DESCR = [
  "Software Loopback Interface 1",
  "Intel(R) 82574L Gigabit Network Connection",
  "isatap.local",
];

function buildMibView() {
  const view = [];
  view.push({ oid: [1, 3, 6, 1, 2, 1, 1, 1, 0], type: "octet", value: "Microsoft Windows Server (SNMP)" });
  view.push({ oid: [1, 3, 6, 1, 2, 1, 1, 2, 0], type: "oid", value: [1, 3, 6, 1, 4, 1, 311] });
  view.push({ oid: [1, 3, 6, 1, 2, 1, 2, 1, 0], type: "int", value: S_IF_DESCR.length });
  S_IF_DESCR.forEach((name, i) => {
    view.push({ oid: [1, 3, 6, 1, 2, 1, 2, 2, 1, 2, i + 1], type: "octet", value: name });
  });
  S_PROCESS_NAMES.forEach((name, i) => {
    view.push({ oid: [1, 3, 6, 1, 2, 1, 25, 4, 2, 1, 2, i + 1], type: "octet", value: name });
  });
  return view;
}
export const MIB_VIEW = buildMibView();
export const OID_HR_SW_RUN_NAME = [1, 3, 6, 1, 2, 1, 25, 4, 2, 1, 2];
export const OID_IF_DESCR = [1, 3, 6, 1, 2, 1, 2, 2, 1, 2];

// ------------------------------------------------------------ BER codec
function encLength(n) {
  if (n < 128) return Buffer.from([n]);
  const bytes = [];
  while (n > 0) { bytes.unshift(n & 0xff); n >>= 8; }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
function encTlv(tag, content) {
  return Buffer.concat([Buffer.from([tag]), encLength(content.length), content]);
}
function encInt(n) {
  // Minimal two's-complement encoding (BER). Correctness here matters for
  // strict decoders (onesixtyone only accepts INTEGER lengths 1, 2, 4 and
  // sends negative request-ids): a zero-length body would be malformed.
  const neg = n < 0;
  let a = Math.abs(n);
  const mag = a === 0 ? [0] : [];
  while (a > 0) { mag.unshift(a % 256); a = Math.floor(a / 256); }
  let bytes;
  if (!neg) {
    bytes = (mag[0] & 0x80) ? [0, ...mag] : mag;
  } else {
    let w = mag.length;
    for (;;) {
      const m = [...new Array(w - mag.length).fill(0), ...mag];
      let carry = 1;
      const out = new Array(w);
      for (let i = w - 1; i >= 0; i--) {
        const s = (0xff - m[i]) + carry;
        out[i] = s & 0xff;
        carry = s >> 8;
      }
      if (out[0] & 0x80) { bytes = out; break; }
      w++;
    }
    while (bytes.length > 1 && bytes[0] === 0xff && (bytes[1] & 0x80)) bytes.shift();
  }
  return encTlv(0x02, Buffer.from(bytes));
}
function encOctet(s) {
  return encTlv(0x04, Buffer.from(String(s), "utf8"));
}
function encNull() {
  return Buffer.from([0x05, 0x00]);
}
function encOid(arcs) {
  const out = [40 * arcs[0] + arcs[1]];
  for (let i = 2; i < arcs.length; i++) {
    let v = arcs[i];
    const stack = [v & 0x7f];
    v >>= 7;
    while (v > 0) { stack.unshift((v & 0x7f) | 0x80); v >>= 7; }
    out.push(...stack);
  }
  return encTlv(0x06, Buffer.from(out));
}
function encEndOfMibView() {
  return Buffer.from([0x82, 0x00]);
}

function cmpOid(a, b) {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = i < a.length ? a[i] : -1;
    const y = i < b.length ? b[i] : -1;
    if (x !== y) return x - y;
  }
  return 0;
}

function readTlv(buf, off) {
  if (off + 2 > buf.length) throw new Error("short");
  const tag = buf[off];
  let len = buf[off + 1];
  let pos = off + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || pos + n > buf.length) throw new Error("badlen");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[pos++];
  }
  if (pos + len > buf.length) throw new Error("short");
  return { tag, content: buf.subarray(pos, pos + len), next: pos + len };
}
function decInt(content) {
  let v = 0;
  for (const b of content) v = v * 256 + b;
  if (content.length && (content[0] & 0x80)) v -= 2 ** (8 * content.length);
  return v;
}
function decOid(content) {
  if (!content.length) throw new Error("badoid");
  const arcs = [Math.floor(content[0] / 40), content[0] % 40];
  let v = 0;
  for (let i = 1; i < content.length; i++) {
    v = v * 128 + (content[i] & 0x7f);
    if (!(content[i] & 0x80)) { arcs.push(v); v = 0; }
  }
  return arcs;
}

// ------------------------------------------------------------ messages
// Build an SNMP GetRequest (for readiness probes and tests).
export function buildSnmpGet({ community = SNMP_COMMUNITY, oid = [1, 3, 6, 1, 2, 1, 1, 1, 0], requestId = 1, version = 0 } = {}) {
  const vb = encTlv(0x30, Buffer.concat([encOid(oid), encNull()]));
  const vblist = encTlv(0x30, vb);
  const pdu = encTlv(0xa0, Buffer.concat([encInt(requestId), encInt(0), encInt(0), vblist]));
  return encTlv(0x30, Buffer.concat([encInt(version), encOctet(community), pdu]));
}

// Build an SNMP GetNextRequest (for walks, readiness probes, and tests).
export function buildSnmpGetNext({ community = SNMP_COMMUNITY, oid = [1, 3, 6, 1, 2, 1, 1, 1, 0], requestId = 1, version = 0 } = {}) {
  const vb = encTlv(0x30, Buffer.concat([encOid(oid), encNull()]));
  const vblist = encTlv(0x30, vb);
  const pdu = encTlv(0xa1, Buffer.concat([encInt(requestId), encInt(0), encInt(0), vblist]));
  return encTlv(0x30, Buffer.concat([encInt(version), encOctet(community), pdu]));
}

// Build an SNMPv2c GetBulkRequest (what snmpwalk -v2c actually sends).
export function buildSnmpGetBulk({ community = SNMP_COMMUNITY, oid = [1, 3, 6, 1, 2, 1, 1, 1, 0], requestId = 1, maxRepetitions = 10 } = {}) {
  const vb = encTlv(0x30, Buffer.concat([encOid(oid), encNull()]));
  const vblist = encTlv(0x30, vb);
  const pdu = encTlv(0xa5, Buffer.concat([encInt(0), encInt(maxRepetitions), encInt(0), vblist]));
  return encTlv(0x30, Buffer.concat([encInt(1), encOctet(community), pdu]));
}
export function parseSnmpResponse(buf) {
  try {
    const msg = readTlv(buf, 0);
    if (msg.tag !== 0x30) return null;
    let o = 0;
    const ver = readTlv(msg.content, o); o = ver.next;
    const com = readTlv(msg.content, o); o = com.next;
    const pdu = readTlv(msg.content, o);
    if (pdu.tag !== 0xa2) return null;
    let p = 0;
    const rid = readTlv(pdu.content, p); p = rid.next;
    const es = readTlv(pdu.content, p); p = es.next;
    const ei = readTlv(pdu.content, p); p = ei.next;
    const vl = readTlv(pdu.content, p);
    const pairs = [];
    let q = 0;
    while (q < vl.content.length) {
      const vb = readTlv(vl.content, q); q = vb.next;
      let r = 0;
      const on = readTlv(vb.content, r); r = on.next;
      const vv = readTlv(vb.content, r);
      let type = "raw", value = null;
      if (vv.tag === 0x02) { type = "int"; value = decInt(vv.content); }
      else if (vv.tag === 0x04) { type = "octet"; value = vv.content.toString("utf8"); }
      else if (vv.tag === 0x06) { type = "oid"; value = decOid(vv.content); }
      else if (vv.tag === 0x05) { type = "null"; value = null; }
      else if (vv.tag === 0x82) { type = "endOfMibView"; value = null; }
      else if (vv.tag === 0x80) { type = "noSuchObject"; value = null; }
      else if (vv.tag === 0x81) { type = "noSuchInstance"; value = null; }
      pairs.push({ oid: decOid(on.content), type, value });
    }
    return {
      requestId: decInt(rid.content),
      errorStatus: decInt(es.content),
      errorIndex: decInt(ei.content),
      pairs,
    };
  } catch { return null; }
}

function encodeValue(binding) {
  if (binding.type === "int") return encInt(binding.value);
  if (binding.type === "octet") return encOctet(binding.value);
  if (binding.type === "oid") return encOid(binding.value);
  return encNull();
}

function findExact(oid) {
  return MIB_VIEW.find((b) => cmpOid(b.oid, oid) === 0) || null;
}
function findNext(oid) {
  let best = null;
  for (const b of MIB_VIEW) {
    if (cmpOid(b.oid, oid) > 0 && (!best || cmpOid(b.oid, best.oid) < 0)) best = b;
  }
  return best;
}

// Handle one SNMP message; returns a response Buffer, or null to stay
// silent (bad community, malformed datagram, unsupported PDU).
export function handleSnmpMessage(buf) {
  let msg, o = 0;
  try {
    msg = readTlv(buf, 0);
    if (msg.tag !== 0x30) return null;
    const ver = readTlv(msg.content, o); o = ver.next;
    const version = decInt(ver.content);
    if (version !== 0 && version !== 1) return null;
    const com = readTlv(msg.content, o); o = com.next;
    if (com.tag !== 0x04 || com.content.toString("utf8") !== SNMP_COMMUNITY) return null;
    const pdu = readTlv(msg.content, o);
    const pduType = pdu.tag;
    if (pduType !== 0xa0 && pduType !== 0xa1 && pduType !== 0xa5) return null;
    let p = 0;
    const rid = readTlv(pdu.content, p); p = rid.next;
    const requestId = decInt(rid.content);
    p = readTlv(pdu.content, p).next; // error-status (request: 0)
    p = readTlv(pdu.content, p).next; // error-index (request: 0)
    const vl = readTlv(pdu.content, p);
    const oids = [];
    let q = 0;
    while (q < vl.content.length) {
      const vb = readTlv(vl.content, q); q = vb.next;
      const on = readTlv(vb.content, 0);
      oids.push(decOid(on.content));
    }
    if (!oids.length) return null;
    const isBulk = pduType === 0xa5;
    // GetBulk repetition count comes from max-repetitions; cap for safety.
    let maxRep = 10;
    if (isBulk) {
      // Re-read non-repeaters/max-repetitions from the (misnamed) fields.
      let p2 = rid.next;
      p2 = readTlv(pdu.content, p2).next;
      const ei2 = readTlv(pdu.content, p2);
      maxRep = Math.max(0, Math.min(decInt(ei2.content), 25));
      if (!maxRep) maxRep = 10;
    }
    const outPairs = [];
    let errorStatus = 0, errorIndex = 0;
    if (!isBulk) {
      oids.forEach((oid, i) => {
        if (pduType === 0xa0) {
          const b = findExact(oid);
          if (!b) {
            // v1 Get on missing leaf: noSuchName. v2c: noSuchInstance value.
            if (version === 0) {
              if (!errorStatus) { errorStatus = 2; errorIndex = i + 1; }
              outPairs.push({ oid, enc: encNull() });
            } else {
              const isScalar = oid.length && oid[oid.length - 1] === 0;
              outPairs.push({ oid, enc: Buffer.from([isScalar ? 0x81 : 0x80, 0x00]) });
            }
          } else outPairs.push({ oid, enc: encodeValue(b) });
        } else {
          const b = findNext(oid);
          if (!b) {
            if (version === 0) {
              if (!errorStatus) { errorStatus = 2; errorIndex = i + 1; }
              outPairs.push({ oid, enc: encNull() });
            } else outPairs.push({ oid, enc: encEndOfMibView() });
          } else outPairs.push({ oid: b.oid, enc: encodeValue(b) });
        }
      });
    } else {
      // GetBulk: one successor chain per requested OID.
      for (const oid of oids) {
        let cursor = oid;
        for (let r = 0; r < maxRep; r++) {
          const b = findNext(cursor);
          if (!b) { outPairs.push({ oid: cursor, enc: encEndOfMibView() }); break; }
          outPairs.push({ oid: b.oid, enc: encodeValue(b) });
          cursor = b.oid;
        }
      }
    }
    const vbs = outPairs.map(({ oid, enc }) => encTlv(0x30, Buffer.concat([encOid(oid), enc])));
    const resp = encTlv(0xa2, Buffer.concat([
      encInt(requestId), encInt(errorStatus), encInt(errorIndex), encTlv(0x30, Buffer.concat(vbs)),
    ]));
    return encTlv(0x30, Buffer.concat([encInt(version), encOctet(SNMP_COMMUNITY), resp]));
  } catch { return null; }
}

// role: "snmp"
// opts: { host, ports: { udp161 } } — omitted entries bind ephemeral ports.
export async function startSnmpAgent(role, { host = "127.0.0.1", ports = {} } = {}) {
  if (role !== "snmp") throw new Error(`Unknown SNMP role: ${role}`);
  // Omitted entries bind the fixed service port (the sandbox runs as
  // namespace-root, like the Docker target); loopback-mapped tests pass
  // explicit ephemeral ports.
  const want = ports.udp161 ?? SNMP_PORT;
  const sock = dgram.createSocket("udp4");
  sock.on("message", (msg, rinfo) => {
    try {
      const resp = handleSnmpMessage(msg);
      if (resp) sock.send(resp, rinfo.port, rinfo.address, () => {});
    } catch { /* never crash the target */ }
  });
  sock.on("error", () => {});
  await new Promise((resolve, reject) => {
    sock.on("error", reject);
    sock.bind(want, host, () => resolve());
  });
  return {
    role,
    ports: [sock.address().port],
    close: async () => { try { sock.close(); } catch {} },
  };
}

// Standalone entrypoint (used by the Docker image).
//   TARGET_ROLE=snmp  TARGET_HOST=0.0.0.0
const invokedAsMain = (() => {
  try { return process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]; } catch { return false; }
})();
if (invokedAsMain) {
  const role = process.env.TARGET_ROLE || "";
  if (!SNMP_ROLES.has(role)) {
    console.error("TARGET_ROLE must be snmp");
    process.exit(1);
  }
  startSnmpAgent(role, { host: process.env.TARGET_HOST || "0.0.0.0", ports: { udp161: SNMP_PORT } })
    .then(() => console.log(`axiom-lab-snmp target role=${role} listening`))
    .catch((e) => { console.error("snmp target failed to start", e?.message || e); process.exit(1); });
}
