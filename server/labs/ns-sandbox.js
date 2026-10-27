// Local-provider sandbox for multi-target Nmap labs (6.3.3+).
//
// Runs INSIDE `unshare -Urnm` (user+network+mount namespaces) as
// namespace-root, which grants exactly what the lab needs and nothing
// else: low-port binds, raw sockets for SYN scans, and a private loopback
// network. The host filesystem stays visible (no mount hiding), so this
// provider is for dev/CI — production uses the Docker provider, which is
// fully container-isolated.
//
// usage: unshare -Urnm node ns-sandbox.js <sockdir>
// <sockdir>/config.json: { labSlug, roles: [{role, ip}], flags: {q4, q5, smb},
//                          nameserverIp, hostnames: [{name, ip}],
//                          probes: [{ip, port, proto}] }
// Roles named smb* run impacket smbserver.py shares (real SMB transport +
// share metadata; no SAMR server — see smb-range.js); smtp-vrfy runs the
// Node SMTP dialogue and snmp runs the Node SNMP agent (see smtp-target.js
// and snmp-target.js); every other role runs the Node nmap-targets
// personalities.
// The supervisor bind-mounts <sockdir>/resolv.conf over /etc/resolv.conf
// (a bare netns has no resolver, which crashes some tools), brings lo up,
// starts every target role, then serves shell execution over the unix
// socket <sockdir>/sock as newline-delimited JSON:
//   request:  {"cmd": "...", "timeoutMs": 180000}
//   response: {"stdout": "...", "stderr": "...", "exit": 0, "truncated": false}
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { execFileSync, spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { startRole } from "./nmap-targets.js";
import { launchImpacketShares, NET_VIEW_SHIM, buildHostsFile, SMB_ROLES } from "./smb-range.js";
import { startSmtpRole, SMTP_ROLES } from "./smtp-target.js";
import { startSnmpAgent, SNMP_ROLES, buildSnmpGet, parseSnmpResponse } from "./snmp-target.js";
import { startDnsServer } from "./dns-server.js";
import dgram from "node:dgram";

const OUT_CAP = 256 * 1024;

function sh(cmd) {
  return execFileSync("sh", ["-c", cmd], { encoding: "utf8", timeout: 15000 }).trim();
}

async function main() {
  const sockdir = process.argv[2];
  if (!sockdir) {
    console.error("usage: ns-sandbox.js <sockdir>");
    process.exit(2);
  }
  const config = JSON.parse(fs.readFileSync(path.join(sockdir, "config.json"), "utf8"));
  const workspace = path.join(sockdir, "workspace");
  fs.mkdirSync(workspace, { recursive: true });

  // Private resolver first: without it, tools doing reverse DNS fail badly.
  try {
    sh(`mount --bind ${sockdir}/resolv.conf /etc/resolv.conf`);
  } catch (e) {
    console.error(`sandbox mount failed (needs mount namespace): ${e?.message || e}`);
    process.exit(2);
  }
  try {
    sh("ip link set lo up");
  } catch (e) {
    console.error(`sandbox net setup failed: ${e?.message || e}`);
    process.exit(2);
  }
  // Assign every target address to loopback so the lab subnet is real.
  const addrs = [...new Set([...config.roles.map((t) => t.ip), config.nameserverIp].filter(Boolean))];
  for (const ip of addrs) {
    try { sh(`ip addr add ${ip}/24 dev lo`); }
    catch (e) {
      if (!/exists|busy/i.test(String(e?.message || ""))) {
        console.error(`address setup failed for ${ip}: ${e?.message || e}`);
        process.exit(2);
      }
    }
  }

  const closers = [];
  const dns = await startDnsServer({ host: config.nameserverIp, port: 53 });
  closers.push(() => dns.close());
  // Attacker conveniences inside the namespace: range name resolution
  // (dc01 in particular) and the `net view` workflow. Both are private to
  // this mount namespace — the host's /etc/hosts is never modified, only
  // over-mounted here the way resolv.conf already is.
  try {
    const binDir = path.join(sockdir, "bin");
    fs.mkdirSync(binDir, { recursive: true });
    fs.writeFileSync(path.join(binDir, "net"), NET_VIEW_SHIM, { mode: 0o755 });
    fs.writeFileSync(path.join(sockdir, "hosts"), buildHostsFile(config.hostnames || []));
    // Forward name resolution must consult files first: the host's
    // nsswitch may prefer systemd-resolved, which is unreachable inside
    // the namespace and returns before files is ever tried. This minimal
    // file is private to the mount namespace (host files untouched).
    fs.writeFileSync(path.join(sockdir, "nsswitch.conf"), [
      "passwd: files", "group: files", "shadow: files", "hosts: files dns",
      "networks: files", "protocols: files", "services: files",
      "ethers: files", "rpc: files", "netgroup: files", "",
    ].join("\n"));
    sh(`mount --bind ${sockdir}/hosts /etc/hosts`);
    sh(`mount --bind ${sockdir}/nsswitch.conf /etc/nsswitch.conf`);
  } catch (e) {
    console.error(`sandbox hosts setup failed: ${e?.message || e}`);
  }
  for (const t of config.roles) {
    if (SMB_ROLES.has(t.role)) {
      const h = await launchImpacketShares(t.role, { ip: t.ip, flag: config.flags?.smb || "", workdir: path.join(sockdir, "smb") });
      closers.push(() => h.close());
    } else if (SMTP_ROLES.has(t.role)) {
      const h = await startSmtpRole(t.role, { host: t.ip });
      closers.push(() => h.close());
    } else if (SNMP_ROLES.has(t.role)) {
      const h = await startSnmpAgent(t.role, { host: t.ip });
      closers.push(() => h.close());
    } else {
      const h = await startRole(t.role, { host: t.ip, flags: config.flags || {} });
      closers.push(() => h.close());
    }
  }

  const sockPath = path.join(sockdir, "sock");
  try { fs.unlinkSync(sockPath); } catch {}
  const server = net.createServer((conn) => {
    let buf = "";
    conn.on("data", (d) => {
      buf += d.toString("utf8");
      let idx;
      while ((idx = buf.indexOf("\n")) !== -1) {
        const line = buf.slice(0, idx);
        buf = buf.slice(idx + 1);
        handle(line, conn).catch((e) => {
          try { conn.write(JSON.stringify({ stdout: "", stderr: String(e?.message || e).slice(0, 500), exit: 127, truncated: false }) + "\n"); } catch {}
        });
      }
    });
    conn.on("error", () => {});
  });

  function handle(line, conn) {
    return new Promise((resolve) => {
      let req;
      try { req = JSON.parse(line); }
      catch { conn.write(JSON.stringify({ stdout: "", stderr: "bad request", exit: 127, truncated: false }) + "\n"); return resolve(); }
      const cmd = String(req.cmd || "").slice(0, 4000);
      const timeoutMs = Math.min(Math.max(Number(req.timeoutMs) || 180000, 1000), 300000);
      if (!cmd.trim()) {
        conn.write(JSON.stringify({ stdout: "", stderr: "", exit: 0, truncated: false }) + "\n");
        return resolve();
      }
      // Built-in readiness probe for UDP/SNMP targets: a real GetRequest
      // for sysDescr.0 answered in-namespace (bash cannot speak SNMP).
      const snmpProbe = /^__probe-snmp\s+(\S+)\s+(\d+)\s*$/.exec(cmd.trim());
      if (snmpProbe) {
        const sock = dgram.createSocket("udp4");
        const timer = setTimeout(() => { try { sock.close(); } catch {} reply(""); }, 8000);
        const reply = (text) => {
          clearTimeout(timer);
          conn.write(JSON.stringify({ stdout: text, stderr: "", exit: 0, truncated: false }) + "\n");
          resolve();
        };
        sock.on("error", () => reply(""));
        sock.on("message", (msg) => {
          const r = parseSnmpResponse(msg);
          reply(r && r.errorStatus === 0 && r.pairs.length > 0 ? "SNMP-READY" : "");
        });
        try {
          sock.send(buildSnmpGet({}), parseInt(snmpProbe[2], 10), snmpProbe[1], () => {});
        } catch { reply(""); }
        return;
      }
      const child = spawn("sh", ["-c", cmd], {
        cwd: workspace,
        env: { ...process.env, HOME: workspace, TERM: "dumb", PATH: `${path.join(sockdir, "bin")}:${process.env.PATH || "/usr/bin:/bin"}` },
        stdio: ["ignore", "pipe", "pipe"],
        timeout: timeoutMs,
      });
      let stdout = "", stderr = "", truncated = false;
      child.stdout.on("data", (d) => {
        if (stdout.length + stderr.length > OUT_CAP) { truncated = true; return; }
        stdout += d.toString("utf8").slice(0, Math.max(0, OUT_CAP - stdout.length - stderr.length));
      });
      child.stderr.on("data", (d) => {
        if (stdout.length + stderr.length > OUT_CAP) { truncated = true; return; }
        stderr += d.toString("utf8").slice(0, Math.max(0, OUT_CAP - stdout.length - stderr.length));
      });
      child.on("error", (e) => {
        conn.write(JSON.stringify({ stdout, stderr: stdout ? stderr : String(e?.message || e).slice(0, 500), exit: 127, truncated }) + "\n");
        resolve();
      });
      child.on("close", (code, signal) => {
        conn.write(JSON.stringify({ stdout, stderr, exit: code ?? (signal ? 128 : 0), truncated }) + "\n");
        resolve();
      });
    });
  }

  const cleanup = async () => {
    for (const c of closers) await c().catch(() => {});
    try { server.close(); } catch {}
    try { fs.unlinkSync(sockPath); } catch {}
    process.exit(0);
  };
  process.on("SIGTERM", cleanup);
  process.on("SIGINT", cleanup);

  await new Promise((resolve, reject) => {
    server.on("error", reject);
    server.listen(sockPath, () => resolve());
  });
  fs.writeFileSync(path.join(sockdir, "ready"), "up\n");
}

main().catch((e) => {
  console.error(`sandbox failed: ${e?.message || e}`);
  process.exit(1);
});
