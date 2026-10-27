// Lab-terminal DNS tools for the 6.3.1 DNS Enumeration exercise.
//
// These commands speak real wire-format DNS (via the injected `query`
// function, bound to the learner's own isolated target) and only format
// the live responses for the terminal. No canned answers: every value
// shown comes from the target's actual reply.
import { DNS_BRUTE_WORDLIST } from "./dns-zones.js";

const KNOWN_TYPES = new Set(["A", "AAAA", "NS", "CNAME", "SOA", "MX", "TXT", "ANY", "PTR"]);
const KNOWN_DIG_OPTS = new Set(["short", "tcp", "cmd", "noall", "answer", "question", "stats", "time", "tries"]);

function canonQtype(t) {
  const u = String(t || "").toUpperCase();
  if (u === "A" || u === "AAAA" || u === "NS" || u === "CNAME" || u === "SOA" || u === "MX" || u === "TXT" || u === "ANY" || u === "PTR") return u;
  return null;
}

function fqdnLower(n) {
  return String(n || "").toLowerCase().replace(/\.+$/, "");
}

// ---------------- dig ----------------
function parseDig(argv) {
  const out = { server: null, name: null, type: "A", short: false, tcp: false, reverse: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("@")) {
      if (out.server) return { error: "Usage: dig [@server] <name> [type] [+short] [+tcp]" };
      out.server = a.slice(1);
    } else if (a === "-x") {
      out.reverse = argv[++i] || "";
    } else if ((a === "-t" || a === "--type") && i + 1 < argv.length) {
      const t = canonQtype(argv[++i]);
      if (!t) return { error: `Invalid type: ${argv[i]}\nUsage: dig [@server] <name> [type] [+short] [+tcp]` };
      out.type = t;
    } else if (a.startsWith("+")) {
      const key = a.slice(1).split("=")[0].toLowerCase();
      if (!KNOWN_DIG_OPTS.has(key)) return { error: `Invalid option: ${a}\nUsage: dig [@server] <name> [type] [+short] [+tcp]` };
      if (key === "short") out.short = true;
      if (key === "tcp") out.tcp = true;
    } else if (a.startsWith("-")) {
      return { error: `Unsupported dig option: ${a}\nUsage: dig [@server] <name> [type] [+short] [+tcp]` };
    } else if (canonQtype(a) && !out.name) {
      // Bare type token before any name: could be "dig MX name" order.
      out.pendingType = canonQtype(a);
    } else if (!out.name) {
      out.name = a;
      if (out.pendingType) { out.type = out.pendingType; delete out.pendingType; }
    } else if (canonQtype(a) && out.type === "A" && !out.typeSeen) {
      out.type = canonQtype(a); out.typeSeen = true;
    } else {
      return { error: `Couldn't parse query: ${a}\nUsage: dig [@server] <name> [type] [+short] [+tcp]` };
    }
  }
  if (out.pendingType && !out.name) return { error: "Usage: dig [@server] <name> [type] [+short] [+tcp]" };
  if (out.reverse) {
    const octets = out.reverse.split(".");
    if (octets.length !== 4 || octets.some((o) => !/^\d{1,3}$/.test(o))) return { error: `Invalid IP for -x: ${out.reverse}` };
    out.name = `${[...octets].reverse().join(".")}.in-addr.arpa`;
    out.type = "PTR";
  }
  if (!out.name) {
    // Bare "dig": root NS query, like the real tool.
    out.name = ".";
    out.type = "NS";
  }
  return out;
}

function rrText(name, rec) {
  const owner = `${fqdnLower(name) || "@"}.`;
  const ttl = rec.ttl;
  switch (rec.type) {
    case "A": return `${owner}\t${ttl}\tIN\tA\t${rec.data}`;
    case "AAAA": return `${owner}\t${ttl}\tIN\tAAAA\t${rec.data}`;
    case "NS": return `${owner}\t${ttl}\tIN\tNS\t${rec.data}`;
    case "CNAME": return `${owner}\t${ttl}\tIN\tCNAME\t${rec.data}`;
    case "SOA": {
      const d = rec.data;
      return `${owner}\t${ttl}\tIN\tSOA\t${d.mname} ${d.rname} ${d.serial} ${d.refresh} ${d.retry} ${d.expire} ${d.minimum}`;
    }
    case "MX": return `${owner}\t${ttl}\tIN\tMX\t${rec.data.preference} ${rec.data.exchange}`;
    case "TXT": return `${owner}\t${ttl}\tIN\tTXT\t${rec.data.map((s) => `"${s}"`).join(" ")}`;
    default: return `${owner}\t${ttl}\tIN\t${rec.type}\t${JSON.stringify(rec.data)}`;
  }
}

const RCODE_NAMES = { 0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED" };

export async function runDig(argv, ctx) {
  const p = parseDig(argv);
  if (p.error) return { output: p.error };
  if (p.server && !ctx.serverAllowed(p.server)) {
    return { output: `External DNS servers are not reachable from the lab terminal.\nUse the lab target: dig @${ctx.targetIp} ${p.name === "." ? "" : p.name} ${p.type}`.trim() };
  }
  const t0 = Date.now();
  let res;
  try {
    res = await ctx.query(p.name, p.type, { tcp: p.tcp || undefined });
  } catch (e) {
    return { output: `;; communications error: ${String(e?.message || e).slice(0, 120)}` };
  }
  if (p.short) {
    const lines = [];
    for (const a of res.answers) {
      if (a.type === "A" || a.type === "AAAA") lines.push(a.data);
      else if (a.type === "NS" || a.type === "CNAME") lines.push(a.data);
      else if (a.type === "MX") lines.push(`${a.data.preference} ${a.data.exchange}`);
      else if (a.type === "TXT") for (const s of a.data) lines.push(`"${s}"`);
      else if (a.type === "SOA") lines.push(`${a.data.mname} ${a.data.rname} ${a.data.serial} ${a.data.refresh} ${a.data.retry} ${a.data.expire} ${a.data.minimum}`);
    }
    return { output: lines.join("\n") || "" };
  }
  const lines = [
    `; <<>> DiG lab <<>> @${ctx.endpointLabel} ${p.name} ${p.type}`,
    `;; global options: +cmd`,
    `;; Got answer:`,
    `;; ->>HEADER<<- opcode: QUERY, status: ${RCODE_NAMES[res.rcode] || `RCODE${res.rcode}`}, id: ${10000 + Math.floor(Math.random() * 50000)}`,
    `;; flags: qr aa rd; QUERY: 1, ANSWER: ${res.answers.length}, AUTHORITY: ${res.authority.length}, ADDITIONAL: ${res.additional.length}`,
    ``,
    `;; QUESTION SECTION:`,
    `;${fqdnLower(p.name) || "@"}.			IN	${p.type}`,
    ``,
  ];
  if (res.answers.length) {
    lines.push(`;; ANSWER SECTION:`);
    for (const a of res.answers) lines.push(rrText(p.name, a));
    lines.push(``);
  }
  if (res.authority.length) {
    lines.push(`;; AUTHORITY SECTION:`);
    for (const a of res.authority) lines.push(rrText(a.name, a));
    lines.push(``);
  }
  if (res.additional.length) {
    lines.push(`;; ADDITIONAL SECTION:`);
    for (const a of res.additional) lines.push(rrText(a.name, a));
    lines.push(``);
  }
  lines.push(
    `;; Query time: ${Math.max(1, Date.now() - t0)} msec`,
    `;; SERVER: ${ctx.endpointLabel}${p.tcp ? " (TCP)" : ""}`,
    `;; WHEN: ${new Date().toUTCString()}`,
  );
  return { output: lines.join("\n") };
}

// ---------------- nslookup ----------------
function parseNslookup(argv) {
  const out = { type: null, name: null, server: null };
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const m = /^-t(?:ype)?=(.+)$/i.exec(a) || /^-q(?:uery)?=(.+)$/i.exec(a);
    if (m) {
      const t = canonQtype(m[1]);
      if (!t) return { error: `Invalid query type: ${m[1]}\nUsage: nslookup [-type=TYPE] <name> [server]` };
      out.type = t;
    } else if (/^-(t|q)$/i.test(a) && i + 1 < argv.length) {
      const t = canonQtype(argv[++i]);
      if (!t) return { error: `Invalid query type: ${argv[i]}\nUsage: nslookup [-type=TYPE] <name> [server]` };
      out.type = t;
    } else if (a.startsWith("-")) {
      return { error: `Unsupported nslookup option: ${a}\nUsage: nslookup [-type=TYPE] <name> [server]` };
    } else rest.push(a);
  }
  if (!rest.length) return { error: "Usage: nslookup [-type=TYPE] <name> [server]" };
  out.name = rest[0];
  if (rest.length > 1) out.server = rest[1];
  if (rest.length > 2) return { error: "Usage: nslookup [-type=TYPE] <name> [server]" };
  return out;
}

export async function runNslookup(argv, ctx) {
  const p = parseNslookup(argv);
  if (p.error) return { output: p.error };
  if (p.server && !ctx.serverAllowed(p.server)) {
    return { output: `External DNS servers are not reachable from the lab terminal.\nUse the lab target: nslookup ${p.name} ${ctx.targetIp}` };
  }
  const header = `Server:\t\t${ctx.serverHost}\nAddress:\t${ctx.serverHost}#${ctx.serverPort}\n`;
  const types = p.type ? [p.type] : ["A", "AAAA"];
  const blocks = [];
  for (const t of types) {
    let res;
    try {
      res = await ctx.query(p.name, t, {});
    } catch (e) {
      return { output: header + `\n** query failed: ${String(e?.message || e).slice(0, 120)}` };
    }
    if (res.rcode === 3) return { output: header + `\n** server can't find ${p.name}: NXDOMAIN` };
    if (res.rcode !== 0) return { output: header + `\n** server can't find ${p.name}: ${RCODE_NAMES[res.rcode] || `RCODE${res.rcode}`}` };
    for (const a of res.answers) {
      if (a.type === "A" || a.type === "AAAA") blocks.push(`Name:\t${fqdnLower(p.name)}\nAddress: ${a.data}`);
      else if (a.type === "NS") blocks.push(`${fqdnLower(p.name)}\tnameserver = ${a.data}`);
      else if (a.type === "MX") blocks.push(`${fqdnLower(p.name)}\tmail exchanger = ${a.data.preference} ${a.data.exchange}`);
      else if (a.type === "TXT") for (const s of a.data) blocks.push(`${fqdnLower(p.name)}\ttext = "${s}"`);
      else if (a.type === "SOA") blocks.push(`${fqdnLower(p.name)}\n\torigin = ${a.data.mname}\n\tmail addr = ${a.data.rname}\n\tserial = ${a.data.serial}`);
      else if (a.type === "CNAME") blocks.push(`${fqdnLower(p.name)}\tcanonical name = ${a.data}`);
    }
  }
  if (!blocks.length) return { output: header + `\n** No ${p.type || "A/AAAA"} records for ${p.name}` };
  return { output: header + `\n` + blocks.join("\n") };
}

// ---------------- host ----------------
function parseHost(argv) {
  const out = { type: null, name: null, server: null, tcp: false, verbose: false };
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if ((a === "-t" || a === "-T") && i + 1 < argv.length) {
      // -t TYPE selects the query type; -T forces TCP (host uses -T for TCP).
      if (a === "-T" && !canonQtype(argv[i + 1])) { out.tcp = true; continue; }
      const t = canonQtype(argv[++i]);
      if (!t) return { error: `Invalid query type: ${argv[i]}\nUsage: host [-t TYPE] [-T] <name> [server]` };
      out.type = t;
    } else if (a === "-T") { out.tcp = true; }
    else if (a === "-v") { out.verbose = true; }
    else if (a.startsWith("-")) return { error: `Unsupported host option: ${a}\nUsage: host [-t TYPE] [-T] <name> [server]` };
    else rest.push(a);
  }
  if (!rest.length) return { error: "Usage: host [-t TYPE] [-T] <name> [server]" };
  out.type = out.type || "A";
  out.name = rest[0];
  if (rest.length > 1) out.server = rest[1];
  if (rest.length > 2) return { error: "Usage: host [-t TYPE] [-T] <name> [server]" };
  return out;
}

export async function runHost(argv, ctx) {
  const p = parseHost(argv);
  if (p.error) return { output: p.error };
  if (p.server && !ctx.serverAllowed(p.server)) {
    return { output: `External DNS servers are not reachable from the lab terminal.\nUse the lab target: host ${p.name} ${ctx.targetIp}` };
  }
  let res;
  try {
    res = await ctx.query(p.name, p.type, { tcp: p.tcp || undefined });
  } catch (e) {
    return { output: `;; communications error: ${String(e?.message || e).slice(0, 120)}` };
  }
  const lines = [];
  if (ctx.verbose) {
    lines.push(`Trying "${fqdnLower(p.name)}"`, `Using domain server:`, `Name: ${ctx.serverHost}`, `Address: ${ctx.serverHost}#${ctx.serverPort}`, `Aliases:`, ``);
  } else {
    lines.push(`Using domain server:`, `Name: ${ctx.serverHost}`, `Address: ${ctx.serverHost}#${ctx.serverPort}`, `Aliases:`, ``);
  }
  if (res.rcode === 3) {
    lines.push(`Host ${p.name} not found: 3(NXDOMAIN)`);
    return { output: lines.join("\n") };
  }
  if (res.rcode !== 0) {
    lines.push(`Host ${p.name} query failed: ${RCODE_NAMES[res.rcode] || `RCODE${res.rcode}`}`);
    return { output: lines.join("\n") };
  }
  if (!res.answers.length) {
    lines.push(`Host ${fqdnLower(p.name)} has no ${p.type} record`);
    return { output: lines.join("\n") };
  }
  for (const a of res.answers) {
    if (a.type === "A" || a.type === "AAAA") lines.push(`${fqdnLower(p.name)} has ${a.type === "A" ? "address" : "IPv6 address"} ${a.data}`);
    else if (a.type === "NS") lines.push(`${fqdnLower(p.name)} name server ${a.data}`);
    else if (a.type === "MX") lines.push(`${fqdnLower(p.name)} mail is handled by ${a.data.preference} ${a.data.exchange}`);
    else if (a.type === "TXT") for (const s of a.data) lines.push(`${fqdnLower(p.name)} descriptive text "${s}"`);
    else if (a.type === "SOA") lines.push(`${fqdnLower(p.name)} has SOA record ${a.data.mname} ${a.data.rname} ${a.data.serial}`);
    else if (a.type === "CNAME") lines.push(`${fqdnLower(p.name)} is an alias for ${a.data}`);
  }
  return { output: lines.join("\n") };
}

// ---------------- dnsenum ----------------
// Lab dnsenum: performs the real enumeration workflow against the lab
// target — AXFR attempt (refused, like production), record enumeration,
// then A-query bruteforce over the built-in wordlist. Every value shown
// comes from a live response.
function parseDnsenum(argv) {
  const out = { server: null, domain: null, enum: true, verbose: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--dnsserver" && i + 1 < argv.length) out.server = argv[++i];
    else if (a === "--enum" || a === "--bruteforce") out.enum = true;
    else if (a === "-v" || a === "--verbose") out.verbose = true;
    else if (a === "-f" && i + 1 < argv.length) {
      i++;
      return { error: "Wordlist files are unavailable in the lab terminal — the built-in list is used instead." };
    } else if (a.startsWith("-")) {
      return { error: `Unsupported dnsenum option: ${a}\nUsage: dnsenum [--dnsserver <ip>] [--enum] [-v] <domain>` };
    } else if (!out.domain) out.domain = a;
    else return { error: `Unexpected argument: ${a}\nUsage: dnsenum [--dnsserver <ip>] [--enum] [-v] <domain>` };
  }
  if (!out.domain) return { error: "Usage: dnsenum [--dnsserver <ip>] [--enum] [-v] <domain>" };
  return out;
}

export async function runDnsenum(argv, ctx) {
  const p = parseDnsenum(argv);
  if (p.error) return { output: p.error };
  if (p.server && !ctx.serverAllowed(p.server)) {
    return { output: `External DNS servers are not reachable from the lab terminal.\nUse the lab target: dnsenum --dnsserver ${ctx.targetIp} ${p.domain}` };
  }
  const domain = fqdnLower(p.domain);
  const lines = [
    `dnsenum enumeration — ${domain} (lab build; all queries go to ${ctx.targetIp})`,
    ``,
    `-----   ${domain}   -----`,
    ``,
  ];
  const q = async (name, type) => {
    try {
      const r = await ctx.query(name, type, {});
      if (ctx.verbose) lines.push(`; query ${name} ${type} -> ${RCODE_NAMES[r.rcode] || r.rcode}/${r.answers.length}`);
      return r;
    } catch (e) {
      lines.push(`; query ${name} ${type} failed: ${String(e?.message || e).slice(0, 80)}`);
      return { rcode: 2, answers: [], authority: [], additional: [] };
    }
  };
  // 1. Host addresses + name servers + mail servers (real queries).
  const apexA = await q(domain, "A");
  if (apexA.answers.length) {
    lines.push(`Host's addresses:`, `__________________`, ``);
    for (const a of apexA.answers) lines.push(`${a.name}. \t ${a.ttl} \t IN \t A \t ${a.data}`);
    lines.push(``);
  }
  const ns = await q(domain, "NS");
  const nsNames = ns.answers.filter((a) => a.type === "NS").map((a) => a.data.replace(/\.$/, ""));
  if (nsNames.length) {
    lines.push(`Name Servers:`, `______________`, ``);
    for (const n of nsNames) {
      const glue = await q(n, "A");
      const ip = glue.answers.find((a) => a.type === "A")?.data || "(no glue)";
      lines.push(`${n}. \t IN \t A \t ${ip}`);
    }
    lines.push(``);
  }
  const mx = await q(domain, "MX");
  const mxHosts = mx.answers.filter((a) => a.type === "MX");
  if (mxHosts.length) {
    lines.push(`Mail (MX) Servers:`, `___________________`, ``);
    for (const m of mxHosts) {
      const glue = await q(m.data.exchange.replace(/\.$/, ""), "A");
      const ip = glue.answers.find((a) => a.type === "A")?.data || "(no glue)";
      lines.push(`${m.data.exchange} \t pref ${m.data.preference} \t A \t ${ip}`);
    }
    lines.push(``);
  }
  const txt = await q(domain, "TXT");
  if (txt.answers.length) {
    lines.push(`TXT records:`, `_____________`, ``);
    for (const t of txt.answers) for (const s of t.data) lines.push(`${t.name}. \t TXT \t "${s}"`);
    lines.push(``);
  }
  // 2. Zone transfer attempt (the lab server refuses, like production).
  lines.push(`Trying Zone Transfers:`, `_________________________`, ``);
  if (nsNames.length) {
    const axfr = await q(domain, "AXFR");
    lines.push(axfr.rcode === 5
      ? `AXFR record query refused by ${ctx.targetIp} (no zone transfers)`
      : `AXFR unexpected rcode ${axfr.rcode}`);
  } else {
    lines.push(`No name servers discovered — skipping zone transfer.`);
  }
  lines.push(``);
  // 3. Bruteforce subdomains with the built-in wordlist (real A queries).
  let hits = 0;
  if (p.enum) {
    lines.push(`Brute forcing with built-in wordlist:`, `_______________________________________`, ``);
    for (const w of DNS_BRUTE_WORDLIST) {
      const name = `${w}.${domain}`;
      let r;
      try { r = await ctx.query(name, "A", {}); }
      catch { continue; }
      const hit = r.answers.find((a) => a.type === "A");
      if (hit) {
        hits++;
        lines.push(`${name}. \t IN \t A \t ${hit.data}`);
      }
    }
    lines.push(``);
  }
  lines.push(`dnsenum complete: ${hits} bruteforce ${hits === 1 ? "name" : "names"} discovered.`);
  return { output: lines.join("\n").slice(0, 12000) };
}

export function dnsHelpText(targetIp) {
  return [
    "Lab terminal — scoped to the lab DNS target (no host shell).",
    "",
    "  dig [@server] <name> [type] [+short] [+tcp]   query DNS (try MX, TXT, ANY)",
    "  nslookup [-type=TYPE] <name> [server]         query DNS",
    "  host [-t TYPE] [-T] <name> [server]           query DNS",
    "  dnsenum [--dnsserver <ip>] [--enum] <domain>  enumerate (AXFR attempt + bruteforce)",
    "  targets                                      show this lab's targets",
    "  echo <text>                                  print text",
    "  clear                                        clear the terminal",
    "",
    `Example:  dig @${targetIp} megacorpone.com MX`,
  ].join("\n");
}
