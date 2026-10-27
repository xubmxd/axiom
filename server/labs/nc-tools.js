// Lab-terminal Netcat for the 6.3.2 port-scanning exercise.
//
// Performs genuine socket-level scans against the learner's own isolated
// target (via the injected checkTcp/checkUdp probes) and formats results
// OpenBSD-nc-style. Closed TCP ports RST, closed UDP ports come back
// refused, open ports complete or reply — the student reads real network
// behavior, never a canned table.
//
// Port-range scans are concurrency-bounded; verbose output is line-capped
// so a 1-10000 sweep cannot flood the terminal UI.
import { SCAN_TCP_PORTS, SCAN_UDP_PORTS } from "./scan-target.js";

const KNOWN_SERVICES = new Map([
  [53, "domain"], [88, "kerberos"], [135, "epmap"], [139, "netbios-ssn"],
  [123, "ntp"], [161, "snmp"], [9389, "adws"],
]);

const MAX_PORTS = 20000;
const MAX_LINES = 15000;
const CONCURRENCY = 256;

function svcName(port) {
  return KNOWN_SERVICES.get(port) || "*";
}

function parseNc(argv) {
  const o = {
    verbose: false, numeric: false, zero: false, udp: false,
    intervalMs: 0, timeoutMs: null, randomize: false,
    host: null, ports: [],
  };
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--") { rest.push(...argv.slice(i + 1)); break; }
    if (/^-[46dnrtvzu]+$/.test(a) && !/^-?[0-9]/.test(a)) {
      for (const c of a.slice(1)) {
        if (c === "v") o.verbose = true;
        else if (c === "n") o.numeric = true;
        else if (c === "z") o.zero = true;
        else if (c === "u") o.udp = true;
        else if (c === "d" || c === "r") { if (c === "r") o.randomize = true; }
        else if (c === "4") { /* IPv4 lab network; default */ }
        else if (c === "6") return { error: "IPv6 is unavailable in the lab network (IPv4 only)." };
        else if (c === "t" || c === "T" || c === "U" || c === "N" || c === "C" || c === "c" || c === "I" || c === "O" || c === "S" || c === "V" || c === "X" || c === "x")          return { error: `Unsupported nc option: -${c}\nUsage: nc [-v] [-n] -z [-u] [-w secs] [-i secs] [-p port] <host> <port[-port]> [port ...]` };
        else return { error: `Unknown nc option: -${c}\nUsage: nc [-v] [-n] -z [-u] [-w secs] [-i secs] [-p port] <host> <port[-port]> [port ...]` };
      }
    } else if ((a === "-w" || a === "-i" || a === "-p" || a === "-s") && i + 1 < argv.length) {
      const v = Number(argv[++i]);
      if (!Number.isFinite(v) || v < 0) return { error: `Invalid value for ${a}: ${argv[i]}` };
      if (a === "-w") o.timeoutMs = Math.min(10000, Math.max(100, Math.round(v * 1000)));
      if (a === "-i") o.intervalMs = Math.min(250, Math.round(v * 1000));
      // -p/-s source ports are accepted and ignored in the scoped terminal.
    } else if (/^-(w|i|p|s).+/.test(a)) {
      // Attached form: -w1, -i0.5, -p2222.
      const m = /^-(w|i|p|s)(.+)$/.exec(a);
      const v = Number(m[2]);
      if (!Number.isFinite(v) || v < 0) return { error: `Invalid value for -${m[1]}: ${m[2]}` };
      if (m[1] === "w") o.timeoutMs = Math.min(10000, Math.max(100, Math.round(v * 1000)));
      if (m[1] === "i") o.intervalMs = Math.min(250, Math.round(v * 1000));
    } else if (a === "-l" || a === "--listen") {
      return { error: "Listen mode is unavailable in the lab terminal (scan mode only)." };
    } else if (a.startsWith("-")) {
      return { error: `Unknown nc option: ${a}\nUsage: nc [-v] [-n] -z [-u] [-w secs] [-i secs] [-p port] <host> <port[-port]> [port ...]` };
    } else rest.push(a);
  }
  if (!rest.length) return { error: "Usage: nc [-v] [-n] -z [-u] [-w secs] [-i secs] [-p port] <host> <port[-port]> [port ...]" };
  o.host = rest[0];
  for (const spec of rest.slice(1)) {
    const m = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(spec);
    if (!m) return { error: `Invalid port specification: ${spec}\nUsage: nc [-v] [-n] -z [-u] [-w secs] [-i secs] [-p port] <host> <port[-port]> [port ...]` };
    let lo = parseInt(m[1], 10), hi = m[2] === undefined ? lo : parseInt(m[2], 10);
    if (lo > 65535 || hi > 65535) return { error: `Port out of range: ${spec}` };
    if (lo > hi) [lo, hi] = [hi, lo];
    for (let p = lo; p <= hi; p++) o.ports.push(p);
  }
  if (!o.ports.length) return { error: "No ports to scan.\nUsage: nc [-v] [-n] -z [-u] [-w secs] [-i secs] [-p port] <host> <port[-port]> [port ...]" };
  if (o.ports.length > MAX_PORTS) return { error: `Port count exceeds the lab limit (${MAX_PORTS}). Narrow the range.` };
  if (o.randomize) {
    for (let i = o.ports.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [o.ports[i], o.ports[j]] = [o.ports[j], o.ports[i]];
    }
  }
  return o;
}

async function pool(items, n, fn) {
  const out = new Array(items.length);
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) {
      const k = i++;
      out[k] = await fn(items[k], k);
    }
  }));
  return out;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function runNc(argv, ctx) {
  const p = parseNc(argv);
  if (p.error) return { output: p.error };
  if (!ctx.serverAllowed(p.host)) {
    return { output: `Scans outside the lab network are not reachable from the lab terminal.\nScan the lab target instead: nc ${p.udp ? "-u " : ""}-z ${ctx.targetIp} <ports>` };
  }
  const t0 = Date.now();
  const check = p.udp
    ? (port) => ctx.checkUdp(port, Math.min(p.timeoutMs || 600, 5000))
    : (port) => ctx.checkTcp(port, Math.min(p.timeoutMs || 3000, 10000));
  const proto = p.udp ? "udp" : "tcp";
  const lines = [];
  let truncated = false;
  const push = (line) => {
    if (lines.length >= MAX_LINES) { truncated = true; return; }
    lines.push(line);
  };
  const results = await pool(p.ports, CONCURRENCY, async (port) => {
    if (p.intervalMs) await sleep(p.intervalMs);
    try {
      return { port, open: await check(port) };
    } catch {
      return { port, open: false, error: true };
    }
  });
  for (const r of results) {
    if (r.open) push(`Connection to ${ctx.displayIp} ${r.port} port [${proto}/${svcName(r.port)}] succeeded!`);
    else if (p.verbose) push(`nc: connect to ${ctx.displayIp} port ${r.port} (${proto}) failed: Connection refused`);
    if (truncated) break;
  }
  if (truncated) push(`... [output truncated at ${MAX_LINES} lines]`);
  if (!p.zero && !p.udp) {
    // Interactive connect without -z: report the single-port result plainly.
    const first = results[0];
    return { output: first?.open ? `Connection to ${ctx.displayIp} ${first.port} port [${proto}/${svcName(first.port)}] succeeded!` : `nc: connect to ${ctx.displayIp} port ${first?.port} (${proto}) failed: Connection refused` };
  }
  return { output: lines.join("\n") };
}

export function ncHelpText(targetIp) {
  return [
    "Lab terminal — scoped to the lab scan target (no host shell).",
    "",
    "  nc [-v] -z <host> <port[-port]>          TCP connect scan",
    "  nc [-v] -z -u <host> <port[-port]>       UDP scan (open ports reply)",
    "  nc -nv -z -w1 <host> 1-10000             fast numeric sweep",
    "  targets                                  show this lab's targets",
    "  echo <text>                              print text",
    "  clear                                    clear the terminal",
    "",
    `Example:  nc -vz ${targetIp} 1-1000`,
  ].join("\n");
}

// Self-check helper used by tests: canonical service-name mapping.
export function knownServiceName(port) {
  return svcName(port);
}

export { SCAN_TCP_PORTS, SCAN_UDP_PORTS };
