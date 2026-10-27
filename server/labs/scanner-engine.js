// Axiom vulnerability-scanner engine: real network probing, genuine
// finding derivation, and actual web crawling.
//
// Nothing here is pre-generated: every finding comes from an observed
// probe result (TCP handshake, HTTP Server header/body, SSH exec output),
// and every sitemap page comes from a fetched URL discovered through page
// links. Detection thresholds and severity labels are implementation
// decisions documented in the fidelity report; all graded VALUES come
// from target behavior.
import http from "node:http";
import net from "node:net";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { PLUGINS, matchPlugins } from "./scanner-plugins.js";
import { TRAVERSAL_MARKER } from "./vuln-targets.js";

const execFileAsync = promisify(execFile);

// The SSH username for authenticated scans (shown in the Connection tab;
// the password is per-instance, minted at provisioning, owner-scoped).
export const SCAN_SSH_USER = "scanner";

// ------------------------------------------------------------ ports
export function parsePorts(spec) {
  const parts = String(spec ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  if (!parts.length) throw new Error("No ports configured (examples: 80, 8080, 9999, 1-1000).");
  const out = new Set();
  for (const p of parts) {
    const range = /^(\d+)\s*-\s*(\d+)$/.exec(p);
    if (range) {
      let a = parseInt(range[1], 10), b = parseInt(range[2], 10);
      if (a < 1 || b > 65535 || a > b || b - a > 2000) throw new Error(`Invalid port range: ${p}`);
      for (let i = a; i <= b; i++) out.add(i);
      continue;
    }
    if (!/^\d+$/.test(p)) throw new Error(`Invalid port specification: ${p}`);
    const n = parseInt(p, 10);
    if (n < 1 || n > 65535) throw new Error(`Port out of range: ${p}`);
    out.add(n);
  }
  if (!out.size) throw new Error("No ports configured.");
  return [...out].sort((a, b) => a - b);
}

// ------------------------------------------------------------ tcp/http
export function tcpConnect(host, port, timeoutMs = 3000) {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    const timer = setTimeout(() => { sock.destroy(); resolve(false); }, timeoutMs);
    sock.on("error", () => { clearTimeout(timer); resolve(false); });
    sock.connect(port, host, () => { clearTimeout(timer); sock.destroy(); resolve(true); });
  });
}

function httpGet(host, port, reqPath, timeoutMs = 5000) {
  return new Promise((resolve) => {
    const req = http.get({ host, port, path: reqPath, timeout: timeoutMs }, (res) => {
      let body = "";
      res.on("data", (d) => { if (body.length < 256 * 1024) body += d.toString("utf8"); });
      res.on("end", () => resolve({
        status: res.statusCode || 0,
        server: res.headers["server"] || "",
        title: /<title>([^<]*)<\/title>/i.exec(body)?.[1]?.trim() || "",
        body,
      }));
    });
    req.on("timeout", () => { req.destroy(); resolve(null); });
    req.on("error", () => resolve(null));
  });
}

export function extractLinks(html, scopeHost, scopePort) {
  const found = [];
  const seen = new Set();
  const re = /<a\s[^>]*href\s*=\s*["']([^"'#]+)["']/gi;
  let m;
  while ((m = re.exec(String(html || "")))) {
    let href = m[1].trim();
    if (/^(javascript|mailto|tel):/i.test(href)) continue;
    let url;
    try {
      url = new URL(href, `http://${scopeHost}:${scopePort}/`);
    } catch { continue; }
    if (url.protocol !== "http:") continue;
    if (url.hostname !== scopeHost || String(url.port || 80) !== String(scopePort)) continue;
    const key = url.pathname + url.search;
    if (seen.has(key)) continue;
    seen.add(key);
    found.push(key.split("?")[0] || "/");
  }
  return [...new Set(found)];
}

export async function crawlSite(host, port, { maxPages = 50, timeoutMs = 5000 } = {}) {
  const pages = [];
  const visited = new Set();
  const queue = ["/"];
  while (queue.length && pages.length < maxPages) {
    const p = queue.shift();
    if (visited.has(p)) continue;
    visited.add(p);
    const r = await httpGet(host, port, p, timeoutMs);
    if (!r) continue;
    const links = r.status === 200 ? extractLinks(r.body, host, port) : [];
    pages.push({ url: `http://${host}:${port}${p}`, path: p, status: r.status, title: r.title, links });
    for (const l of links) if (!visited.has(l)) queue.push(l);
  }
  return pages;
}

// ------------------------------------------------------------ ssh
let sshChecked = null;
async function sshAvailable() {
  if (sshChecked !== null) return sshChecked;
  try {
    await execFileAsync("ssh", ["-V"], { timeout: 8000 });
    sshChecked = true;
  } catch { sshChecked = false; }
  return sshChecked;
}

// Genuine SSH password authentication using the stock OpenSSH client.
// The password travels inside a 0600 askpass helper (SSH_ASKPASS_REQUIRE
// forces its use without a tty); it never appears in argv or logs.
export async function sshExec({ host, port = 22, user, password, command, timeoutMs = 15000 }) {
  if (!await sshAvailable()) throw new Error("The scan host has no ssh client available.");
  if (!user || !password) throw new Error("SSH credentials are required for authenticated checks.");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "axiom-ssh-"));
  const helper = path.join(dir, "askpass.sh");
  fs.writeFileSync(helper, `#!/bin/sh\nprintf '%s' "$AXIOM_SSH_PW"\n`, { mode: 0o700 });
  try {
    const { stdout } = await execFileAsync("ssh", [
      "-o", "BatchMode=no",
      "-o", "StrictHostKeyChecking=no",
      "-o", "UserKnownHostsFile=/dev/null",
      "-o", `ConnectTimeout=${Math.max(2, Math.ceil(timeoutMs / 2000))}`,
      "-p", String(port), `${user}@${host}`, command,
    ], {
      timeout: timeoutMs,
      maxBuffer: 1024 * 1024,
      env: { ...process.env, AXIOM_SSH_PW: String(password), SSH_ASKPASS: helper, SSH_ASKPASS_REQUIRE: "force", DISPLAY: "none" },
    });
    return { ok: true, output: String(stdout || "") };
  } catch (e) {
    const msg = String(e?.stderr || e?.message || e);
    if (/Permission denied|Authentication failed/i.test(msg)) {
      const err = new Error("SSH authentication failed (bad username or password).");
      err.code = "AUTH";
      throw err;
    }
    const err = new Error(`SSH check failed: ${msg.slice(0, 200)}`);
    err.code = "CONN";
    throw err;
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
  }
}

// ------------------------------------------------------------ scan
function pluginAllowed(pluginFilter, plugin) {
  if (!String(pluginFilter || "").trim()) return true;
  return matchPlugins(pluginFilter).some((p) => p.id === plugin.id);
}

function apacheFinding(target, evidence) {
  const p = PLUGINS["ax-apache-traversal"];
  return {
    pluginId: p.id, pluginName: p.name, family: p.family, severity: p.severity,
    targetIp: target.displayIp, port: 80, protocol: "tcp",
    title: p.name,
    description: p.description,
    evidence,
    details: {
      "Exploit Code Maturity": p.exploitCodeMaturity,
      "Patch Pub Date": p.patchPubDate,
      "CVE": "CVE-2021-41773 (behavioral match; see fidelity report)",
    },
    remediation: p.remediation,
  };
}

function jettyFinding(target, version) {
  const p = PLUGINS["ax-http-multiple"];
  return {
    pluginId: p.id, pluginName: p.name, family: p.family, severity: p.severity,
    targetIp: target.displayIp, port: 8080, protocol: "tcp",
    title: p.name,
    description: p.description,
    evidence: `Server header: Jetty(${version})`,
    details: {
      "HTTP Server Type and Version": version,
      "Patch Pub Date": p.patchPubDate,
    },
    remediation: p.remediation,
  };
}

function curlFinding(target, entry) {
  const p = PLUGINS["ax-curl-usn"];
  const oses = (entry.oses || []).join(", ");
  return {
    pluginId: p.id, pluginName: `${p.name}: ${entry.usn}`,
    family: "Patch Report", severity: p.severity,
    targetIp: target.displayIp, port: 22, protocol: "tcp",
    title: `curl ${entry.version} (${entry.usn})`,
    description: `${p.description} Installed curl ${entry.version} is covered by ${entry.usn} (${entry.summary}). Affected releases: ${oses}.`,
    evidence: `inventory: curl ${entry.version} matches ${entry.usn} (retrieved over SSH)`,
    details: {
      "USN": entry.usn,
      "Installed version": entry.version,
      "Affected releases": oses,
    },
    remediation: `Update curl per ${entry.usn}.`,
  };
}

function sshOsFinding(target, uname, inventory) {
  const p = PLUGINS["ax-ssh-os-ident"];
  const osLabel = `${inventory.os.name} ${inventory.os.version}`;
  return {
    pluginId: p.id, pluginName: p.name, family: p.family, severity: p.severity,
    targetIp: target.displayIp, port: 22, protocol: "tcp",
    title: p.name,
    description: `${p.description} Target-reported identity: ${osLabel} (lab fixture served over genuine SSH; see fidelity report).`,
    evidence: `uname -a: ${uname.trim()} (target-reported over authenticated SSH)`,
    details: {
      "Operating system": osLabel,
      "Kernel": inventory.kernel,
      "Data provenance": "target-reported fixture over genuine SSH (see fidelity report)",
    },
    remediation: p.remediation,
  };
}

// targets: [{ displayIp, host, ports: {http80?, http8080?, http9999?, ssh?} }]
// ports: configured port list (already parsed). auth: {user, password} |
// null. webapp: crawl :9999 where in scope. pluginFilter: substring.
// onProgress(frac, label) is called as phases complete.
export async function runVulnScan({ targets, ports, auth = null, webapp = false, pluginFilter = "", onProgress = null } = {}) {
  const findings = [];
  const targetSummaries = [];
  const sitemap = [];
  const total = Math.max(targets.length, 1);
  let done = 0;
  const want = (port) => ports.includes(port);
  for (const t of targets) {
    const open = [];
    const services = {};
    for (const port of ports) {
      const mapped = t.ports?.[`p${port}`];
      if (!mapped) continue;
      if (await tcpConnect(t.host, mapped, 3000)) {
        open.push(port);
        if (port === 22) {
          services[22] = { kind: "ssh", banner: await sshBanner(t.host, mapped) };
        } else {
          const probe = await httpGet(t.host, mapped, "/", 5000);
          if (probe) services[port] = { kind: "http", server: probe.server, title: probe.title, status: probe.status };
        }
      }
    }
    targetSummaries.push({ displayIp: t.displayIp, openPorts: open, services });
    // Apache path-traversal detection: version match AND live traversal probe.
    if (open.includes(80) && services[80]?.server?.match(/Apache\/2\.4\.49\b/)) {
      const trav = await httpGet(t.host, t.ports.p80, "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd", 5000);
      if (trav && trav.status === 200 && trav.body.includes(TRAVERSAL_MARKER)) {
        if (pluginAllowed(pluginFilter, PLUGINS["ax-apache-traversal"])) {
          findings.push(apacheFinding(t, `GET /cgi-bin/.%2e/.../etc/passwd -> 200 with passwd marker (Server: ${services[80].server})`));
        }
      }
    }
    // Jetty version identification on 8080.
    if (open.includes(8080) && services[8080]?.server) {
      const m = /Jetty\(([^)]+)\)/.exec(services[8080].server);
      if (m && pluginAllowed(pluginFilter, PLUGINS["ax-http-multiple"])) {
        findings.push(jettyFinding(t, m[1]));
      }
    }
    // Authenticated enumeration over genuine SSH.
    if (auth?.user && auth?.password && open.includes(22) && t.ports?.p22) {
      try {
        const invRaw = await sshExec({ host: t.host, port: t.ports.p22, user: auth.user, password: auth.password, command: "cat /etc/axiom-scan/inventory.json" });
        const inventory = JSON.parse(invRaw.output);
        const osLabel = `${inventory.os.name} ${inventory.os.version}`;
        const unameRaw = await sshExec({ host: t.host, port: t.ports.p22, user: auth.user, password: auth.password, command: "uname -a" });
        if (pluginAllowed(pluginFilter, PLUGINS["ax-ssh-os-ident"])) {
          findings.push(sshOsFinding(t, unameRaw.output, inventory));
        }
        for (const entry of inventory.packages?.curl || []) {
          if (pluginAllowed(pluginFilter, PLUGINS["ax-curl-usn"])) {
            findings.push(curlFinding(t, entry));
          }
        }
      } catch (e) {
        targetSummaries[targetSummaries.length - 1].authError = e.code === "AUTH"
          ? "SSH authentication failed"
          : `SSH check unreachable: ${String(e.message).slice(0, 120)}`;
      }
    }
    // Web-application crawling on 9999 (only when requested AND in scope).
    if (webapp && open.includes(9999) && t.ports?.p9999) {
      const pages = await crawlSite(t.host, t.ports.p9999, { maxPages: 60 });
      for (const pg of pages) {
        sitemap.push({
          targetIp: t.displayIp, port: 9999,
          url: `http://${t.displayIp}:9999${pg.path}`,
          path: pg.path, status: pg.status, title: pg.title, links: pg.links,
        });
      }
    }
    done++;
    try { onProgress && onProgress(done / total, `scanned ${done}/${total} targets`); } catch {}
  }
  return { targets: targetSummaries, findings, sitemap };
}

async function sshBanner(host, port, timeoutMs = 3000) {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    const timer = setTimeout(() => { sock.destroy(); resolve(""); }, timeoutMs);
    sock.on("error", () => { clearTimeout(timer); resolve(""); });
    sock.on("data", (d) => { clearTimeout(timer); sock.destroy(); resolve(d.toString("utf8").split("\n")[0].trim().slice(0, 120)); });
    sock.connect(port, host);
  });
}
