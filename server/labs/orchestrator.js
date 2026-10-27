// Lab orchestrator: provider abstraction between Axiom Express and the
// actual lab infrastructure.
//
//   Browser → Axiom Express → lab service → orchestrator → provider → target
//
// The web layer only knows: provision / destroy / endpoint / terminal.
// It never knows how containers, networks, or processes are created.
//
// Providers:
//   docker — isolated bridge network + hardened container per instance.
//   local  — in-process TCP target on loopback (dev/CI fallback with the
//            identical observable WHOIS behavior).
//
// LAB_PROVIDER=docker|local|auto (default auto: docker when the daemon is
// reachable, otherwise local). The learner experience is the same; the
// provider is recorded on the instance row.
import net from "node:net";
import dgram from "node:dgram";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import { log } from "../log.js";
import { syncInstanceVpn, unsyncInstanceVpn, reconcileVpn } from "./vpn.js";
import { buildWhoisResponse, buildVm2WhoisResponse, buildVm3WhoisResponse, labDomain, labZone, ZONE, LAB_DOMAIN, VM2_SLUG, VM3_SLUG } from "./whois-data.js";
import { dnsQuery, waitForDns } from "./dns-client.js";
import { runDig, runNslookup, runHost, runDnsenum, dnsHelpText } from "./dns-tools.js";
import { startDnsServer } from "./dns-server.js";
import { DNS_SLUG } from "./dns-zones.js";
import { startScanTarget, SCAN_SLUG, SCAN_TCP_PORTS, SCAN_UDP_PORTS, SCAN_PORT_ORDER, SCAN_DISPLAY_OCTET } from "./scan-target.js";
import { runNc, ncHelpText } from "./nc-tools.js";
import { startRole, NMAP_SLUG, NMAP_OCTETS } from "./nmap-targets.js";
import { SMB_SLUG, SMB_ROLES, SMB_PORT } from "./smb-range.js";
import { SMTP_SLUG, SMTP_ROLES, SMTP_PORT, startSmtpRole } from "./smtp-target.js";
import { SNMP_SLUG, SNMP_ROLES, SNMP_PORT, startSnmpAgent, buildSnmpGet, parseSnmpResponse } from "./snmp-target.js";
import { SCAN_ROLES } from "./vuln-targets.js";

const execFileAsync = promisify(execFile);

function providerConfigured() {
  return (process.env.LAB_PROVIDER || "auto").toLowerCase();
}

let dockerChecked = null;
export async function dockerAvailable() {
  if (dockerChecked !== null) return dockerChecked;
  try {
    await execFileAsync("docker", ["info"], { timeout: 8000 });
    dockerChecked = true;
  } catch { dockerChecked = false; }
  return dockerChecked;
}

export async function selectProvider() {
  const want = providerConfigured();
  if (want === "docker") {
    if (await dockerAvailable()) return "docker";
    throw new Error("LAB_PROVIDER=docker but the Docker daemon is unreachable.");
  }
  if (want === "local") return "local";
  return (await dockerAvailable()) ? "docker" : "local";
}

// ---------- shared helpers ----------
export function whoisQuery(host, port, query, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    const q = String(query || "").slice(0, 256);
    const sock = new net.Socket();
    let out = "";
    const timer = setTimeout(() => { sock.destroy(); reject(new Error("WHOIS query timed out.")); }, timeoutMs);
    sock.on("error", (e) => { clearTimeout(timer); reject(e); });
    sock.connect(port, host, () => sock.write(q + "\r\n"));
    sock.on("data", (d) => {
      out += d.toString("utf8");
      if (out.length > 32_768) { clearTimeout(timer); sock.destroy(); resolve(out); }
    });
    sock.on("close", () => { clearTimeout(timer); resolve(out); });
  });
}

export async function waitForWhois(host, port, query = LAB_DOMAIN, { tries = 30, delayMs = 1000 } = {}) {
  let last = null;
  for (let i = 0; i < tries; i++) {
    try {
      const out = await whoisQuery(host, port, query, 4000);
      if (out && out.includes("Name Server")) return out;
      last = new Error("Unexpected WHOIS response.");
    } catch (e) { last = e; }
    await new Promise((r) => setTimeout(r, delayMs));
  }
  throw last || new Error("Target WHOIS service did not become ready.");
}

function safeName(prefix, id) {
  return `${prefix}-${String(id).toLowerCase().replace(/[^a-z0-9-]/g, "").slice(0, 40)}`;
}

// Container hostname derived from the target's declared hostname
// (vm1.megacorpone.lab → vm1). VM #1 keeps its exact historic value.
function containerHostname(target) {
  const first = String(target?.hostname || "").split(".")[0].toLowerCase().replace(/[^a-z0-9-]/g, "");
  return first || "vm1";
}

// Per-instance runtime flag for labs that need one (VM #2). Returns the
// plaintext secret to inject into the target, or null for static labs.
// Lazy service import mirrors getLabTargetsMeta (avoids a module cycle).
function isFlagLab(lab) {
  return String(lab?.slug || "") === VM2_SLUG;
}

async function runtimeFlagFor(lab, instance) {
  if (!isFlagLab(lab)) return null;
  const { ensureRuntimeFlag } = await import("./service.js");
  const row = await ensureRuntimeFlag({
    instanceId: instance.id,
    labId: lab.id || "",
    userId: instance.user_id || "",
    objectiveKey: "flag",
  });
  return row?.flag_value || null;
}

// The app may run on the Docker host (bridge IPs routable) or inside its
// own container (only the published loopback port is routable until the
// app joins the lab network). Prefer the direct target endpoint, fall back
// to the provisioned host endpoint. The domain probe defaults to VM #1's
// domain so existing callers are unchanged; pass the lab's domain for more.
export async function resolveEndpoint(instance, domain = LAB_DOMAIN) {
  const direct = { host: instance.target_ip, port: instance.target_port || 43 };
  if (direct.host) {
    try {
      await whoisQuery(direct.host, direct.port, domain, 1500);
      return direct;
    } catch { /* fall through to host endpoint */ }
  }
  const [host, port] = String(instance.host_endpoint || "").split(":");
  return { host: host || "127.0.0.1", port: parseInt(port, 10) || 0 };
}

// ---------------------------------------------------------------- docker
const DOCKER_SUBNET_BASE = process.env.LAB_DOCKER_SUBNET_BASE || "10.210";
const LOCAL_SUBNET_BASE = process.env.LAB_LOCAL_SUBNET_BASE || "10.200";

async function docker(args, timeout = 60_000) {
  return execFileAsync("docker", args, { timeout });
}

// Build contexts for images that predate the `build` target field.
// (Kept so existing definitions keep working unchanged.)
const LEGACY_BUILD_CONTEXTS = {
  "axiom-lab-whois-vm1:latest": "lab-images/m6/whois-vm1",
  "axiom-lab-whois-vm2:latest": "lab-images/m6/whois-vm2",
  "axiom-lab-whois-vm3:latest": "lab-images/m6/whois-vm3",
  "axiom-lab-dns-631:latest": "lab-images/m6/dns-631",
  "axiom-lab-scan-632:latest": "lab-images/m6/scan-632",
  "axiom-lab-nmap-633:latest": "lab-images/m6/nmap-633",
  "axiom-lab-smb-634:latest": "lab-images/m6/smb-634",
  "axiom-lab-smtp-635:latest": "lab-images/m6/smtp-635",
  "axiom-lab-snmp-636:latest": "lab-images/m6/snmp-636",
  "axiom-lab-scan-723:latest": "lab-images/m7/scan-723",
  "axiom-lab-attacker:latest": "lab-images/m6/attacker",
};

// Resolve where `docker build` should run for an image. Pure + exported for tests.
export function resolveBuildContext(image, metadataJson) {
  try {
    const meta = JSON.parse(metadataJson || "{}");
    if (meta && typeof meta.build === "string" && meta.build) {
      const rel = meta.build.replace(/^\//, "");
      return path.resolve("lab-images", rel);
    }
  } catch { /* fall through to legacy map */ }
  const legacy = LEGACY_BUILD_CONTEXTS[image];
  return legacy ? path.resolve(legacy) : null;
}

async function imageExists(image) {
  try { await docker(["image", "inspect", image], 15000); return true; }
  catch { return false; }
}

async function ensureImage(image, metadataJson) {
  if (await imageExists(image)) return { built: false };
  const ctx = resolveBuildContext(image, metadataJson);
  if (!ctx) throw new Error(`Image ${image} is missing and no build context is known. Pre-build it into the daemon.`);
  log("lab.image.build", { image });
  await docker(["build", "-t", image, ctx], 180_000);
  return { built: true };
}

// Boot-time warmup: pre-build every missing lab image in the background so
// the first lab start never waits on a build. Never throws, never blocks
// boot; a no-daemon host simply skips (local provider needs no images).
export async function warmupLabImages() {
  const summary = { checked: 0, built: 0, skipped: 0 };
  try {
    if (!await dockerAvailable()) return { ...summary, daemon: false };
    const { all } = await import("../db.js");
    const rows = await all(`SELECT DISTINCT image_reference, metadata_json FROM lab_targets WHERE image_reference<>''`);
    for (const row of rows) {
      summary.checked++;
      try {
        if (await imageExists(row.image_reference)) continue;
        const ctx = resolveBuildContext(row.image_reference, row.metadata_json);
        if (!ctx) { summary.skipped++; continue; }
        try { await import("node:fs").then((m) => m.default.statSync(ctx)); }
        catch { summary.skipped++; continue; }
        log("lab.image.build", { image: row.image_reference, warmup: true });
        await docker(["build", "-t", row.image_reference, ctx], 180_000);
        summary.built++;
      } catch (e) {
        summary.skipped++;
        log("lab.warmup.fail", { image: row.image_reference, error: String(e?.message || e).slice(0, 200) });
      }
    }
    return { ...summary, daemon: true };
  } catch (e) {
    log("lab.warmup.error", { error: String(e?.message || e).slice(0, 200) });
    return { ...summary, daemon: false };
  }
}

async function pickDockerSubnet(suffix = 10) {
  const hostOctet = Number.isInteger(suffix) && suffix >= 2 && suffix <= 254 ? suffix : 10;
  const used = new Set();
  try {
    const { stdout } = await docker(["network", "ls", "--format", "{{.Name}}"], 15000);
    for (const n of stdout.split("\n")) used.add(n.trim());
  } catch {}
  for (let attempt = 0; attempt < 20; attempt++) {
    const third = 1 + Math.floor(Math.random() * 254);
    const name = `axiom-lab-${DOCKER_SUBNET_BASE.replace(/\./g, "-")}-${third}`;
    if (!used.has(name)) return { name, cidr: `${DOCKER_SUBNET_BASE}.${third}.0/24`, targetIp: `${DOCKER_SUBNET_BASE}.${third}.${hostOctet}` };
  }
  throw new Error("Could not allocate an isolated lab subnet.");
}

// Display-octet convention: scan targets always end in .151 (the exercise
// identifies the machine by its final octet); other labs keep .10.
function displayOctet(target) {
  return target?.target_type === "scan-target" ? SCAN_DISPLAY_OCTET : 10;
}

// Scan-target loopback port map encoding for host_endpoint:
//   "127.0.0.1:tcp/32001,32002;tudp..." — canonical order follows
// SCAN_PORT_ORDER (TCP 53,88,135,139,9389 then UDP 123,161), so the map
// carries no port identities beyond position.
export function encodeScanEndpoint(host, tcpPorts, udpPorts) {
  return `${host}:tcp/${tcpPorts.join(",")};udp/${udpPorts.join(",")}`;
}

export function resolveScanPorts(instance) {
  const m = /^([^:]+):tcp\/([\d,]+);udp\/([\d,]+)$/.exec(String(instance.host_endpoint || ""));
  if (!m) return null;
  const tcp = m[2].split(",").map((x) => parseInt(x, 10));
  const udp = m[3].split(",").map((x) => parseInt(x, 10));
  if (tcp.length !== SCAN_TCP_PORTS.length || udp.length !== SCAN_UDP_PORTS.length) return null;
  if ([...tcp, ...udp].some((p) => !p)) return null;
  return {
    host: m[1] || "127.0.0.1",
    tcp: new Map(SCAN_TCP_PORTS.map((p, i) => [p, tcp[i]])),
    udp: new Map(SCAN_UDP_PORTS.map((p, i) => [p, udp[i]])),
  };
}

export async function waitForScanTarget(host, tcpPort, udpPort, { tries = 30, delayMs = 1000 } = {}) {
  let last = null;
  for (let i = 0; i < tries; i++) {
    try {
      const open = await tcpConnect(host, tcpPort, 4000);
      if (open && await udpProbe(host, udpPort, 4000)) return true;
      last = new Error("Scan target not ready.");
    } catch (e) { last = e; }
    await new Promise((r) => setTimeout(r, delayMs));
  }
  throw last || new Error("Scan target did not become ready.");
}

function tcpConnect(host, port, timeoutMs = 3000) {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    const timer = setTimeout(() => { sock.destroy(); resolve(false); }, timeoutMs);
    sock.on("error", () => { clearTimeout(timer); resolve(false); });
    sock.connect(port, host, () => { clearTimeout(timer); sock.destroy(); resolve(true); });
  });
}

function udpProbe(host, port, waitMs = 600) {
  // Connected UDP socket: a reply means open, ICMP refused means closed,
  // silence means open|filtered (reported open, matching nc -z semantics).
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; clearTimeout(timer); try { sock.close(); } catch {} resolve(v); } };
    const sock = dgram.createSocket("udp4");
    const timer = setTimeout(() => finish(true), waitMs);
    sock.on("error", () => finish(false));
    sock.on("message", () => finish(true));
    try {
      sock.connect(port, host, () => sock.send(Buffer.alloc(0), (e) => { if (e) finish(false); }));
    } catch { finish(false); }
  });
}

// DNS endpoint for dns-server instances. host_endpoint forms:
//   "127.0.0.1:PORT"      same port for UDP+TCP (local provider)
//   "127.0.0.1:UDP:TCP"    distinct loopback mappings (docker provider)
export function resolveDnsEndpoint(instance) {
  const parts = String(instance.host_endpoint || "").split(":");
  const host = parts[0] || "127.0.0.1";
  const udpPort = parseInt(parts[1], 10) || 0;
  const tcpPort = parts.length > 2 ? (parseInt(parts[2], 10) || 0) : udpPort;
  return { host, udpPort, tcpPort };
}

function dockerPortMapped(stdout, proto) {
  // Parses lines like "53/udp -> 127.0.0.1:32770".
  for (const line of String(stdout || "").split("\n")) {
    const m = new RegExp(`^${proto} -> 127\\.0\\.0\\.1:(\\d+)\\s*$`).exec(line.trim());
    if (m) return parseInt(m[1], 10);
  }
  return 0;
}

const dockerProvider = {
  name: "docker",
  async provision(lab, instance) {
    const metas = await getLabTargetsMeta(lab.id);
    const target = metas.find((t) => t.target_type === "scan-target")
      || metas.find((t) => t.target_type === "dns-server")
      || metas.find((t) => t.target_type === "whois-server") || metas[0] || {};
    const isDns = target.target_type === "dns-server";
    const isScan = target.target_type === "scan-target";
    const image = target.image_reference || (isScan ? "axiom-lab-scan-632:latest" : isDns ? "axiom-lab-dns-631:latest" : "axiom-lab-whois-vm1:latest");
    await ensureImage(image, target.metadata_json);
    const domain = labDomain(lab?.slug);
    // Labs with a runtime flag (VM #2) get a per-instance secret minted at
    // provisioning time and injected into the target as an environment
    // variable. Static labs (VM #1) provision exactly as before.
    const flag = await runtimeFlagFor(lab, instance);
    const hostname = containerHostname(target);
    const { name: networkName, cidr, targetIp } = await pickDockerSubnet(displayOctet(target));
    await docker(["network", "create", "--driver", "bridge", `--subnet=${cidr}`, "--internal=false", networkName], 30000);
    const cname = safeName("axiom", instance.id);
    try {
      const runArgs = [
        "run", "-d", "--name", cname,
        "--network", networkName, "--ip", targetIp,
        "--memory", "128m", "--cpus", "0.25", "--pids-limit", "64",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--read-only", "--tmpfs", "/tmp",
        ...(isScan
          ? ["--publish", "127.0.0.1::53/tcp", "--publish", "127.0.0.1::88/tcp", "--publish", "127.0.0.1::135/tcp", "--publish", "127.0.0.1::139/tcp", "--publish", "127.0.0.1::9389/tcp", "--publish", "127.0.0.1::123/udp", "--publish", "127.0.0.1::161/udp"]
          : isDns
          ? ["--publish", "127.0.0.1::53/udp", "--publish", "127.0.0.1::53/tcp"]
          : ["--publish", "127.0.0.1::43"]),
        "--hostname", hostname,
      ];
      if (flag) runArgs.push("--env", `AXIOM_WHOIS_FLAG=${flag}`);
      runArgs.push(image);
      await docker(runArgs, 60000);
    } catch (e) {
      await docker(["network", "rm", networkName], 15000).catch(() => {});
      throw e;
    }
    // Host-routable endpoint for the app (terminal gateway, health checks).
    const { stdout } = await docker(["port", cname], 15000);
    const hostPort = isDns ? 0 : isScan ? 0 : dockerPortMapped(stdout, "43/tcp");
    const dnsUdp = isDns ? dockerPortMapped(stdout, "53/udp") : 0;
    const dnsTcp = isDns ? dockerPortMapped(stdout, "53/tcp") : 0;
    // Scan targets map every service port; canonical order follows SCAN_PORT_ORDER.
    const scanTcp = isScan ? SCAN_TCP_PORTS.map((p) => dockerPortMapped(stdout, `${p}/tcp`)) : [];
    const scanUdp = isScan ? SCAN_UDP_PORTS.map((p) => dockerPortMapped(stdout, `${p}/udp`)) : [];
    if ((!isDns && !isScan && !hostPort) || (isDns && (!dnsUdp || !dnsTcp)) || (isScan && ([...scanTcp, ...scanUdp].some((p) => !p)))) {
      await this.destroy({ ...instance, provider_reference: cname, network_name: networkName }).catch(() => {});
      throw new Error("Target started but its service port was not mapped.");
    }
    // Readiness depends on where Axiom itself runs:
    // - inside a container (AXIOM_SELF_CONTAINER set): join the lab network
    //   and poll the target's DIRECT address. The published 127.0.0.1 port
    //   is bound on the Docker host, not inside this container, so polling
    //   it from here would fail forever.
    // - on the Docker host: the loopback mapping is reachable; poll it.
    // The lab target itself stays on its isolated network either way.
    const selfContainer = process.env.AXIOM_SELF_CONTAINER || "";
    try {
      if (selfContainer) {
        try {
          await docker(["network", "connect", networkName, selfContainer], 15000);
        } catch (e) {
          throw new Error(`Axiom could not join lab network as ${selfContainer} — check AXIOM_SELF_CONTAINER. ${String(e?.message || e).slice(0, 160)}`);
        }
        if (isScan) await waitForScanTarget(targetIp, 53, 161);
        else if (isDns) await waitForDns(targetIp, 53, "megacorpone.com");
        else await waitForWhois(targetIp, 43, domain);
      } else {
        if (isScan) await waitForScanTarget("127.0.0.1", scanTcp[0], scanUdp[1]);
        else if (isDns) await waitForDns("127.0.0.1", dnsUdp, "megacorpone.com");
        else await waitForWhois("127.0.0.1", hostPort, domain);
      }
    } catch (e) {
      // Never leave orphans behind a failed start.
      if (selfContainer) await docker(["network", "disconnect", "-f", networkName, selfContainer], 15000).catch(() => {});
      await docker(["rm", "-f", cname], 30000).catch(() => {});
      await docker(["network", "rm", networkName], 30000).catch(() => {});
      throw e;
    }
    // Student VPN (best-effort, never fails provisioning): attach the
    // gateway to this lab net and open the owner's target to their client.
    // No-op unless VPN is enabled and the owner holds a VPN pack.
    await syncInstanceVpn({
      id: instance.id, user_id: instance.user_id || "",
      provider: "docker", network_name: networkName, target_ip: targetIp,
    });
    return {
      networkName, networkCidr: cidr, targetIp, targetPort: isScan || isDns ? 53 : 43,
      hostEndpoint: isScan
        ? encodeScanEndpoint("127.0.0.1", scanTcp, scanUdp)
        : isDns ? `127.0.0.1:${dnsUdp}:${dnsTcp}` : `127.0.0.1:${hostPort}`, providerReference: cname,
    };
  },
  async destroy(instance) {
    const t0 = Date.now();
    const cname = instance.provider_reference;
    const selfContainer = process.env.AXIOM_SELF_CONTAINER || "";
    if (selfContainer && instance.network_name) {
      await docker(["network", "disconnect", "-f", instance.network_name, selfContainer], 15000).catch(() => {});
    }
    // Student VPN first: drop the owner's firewall rules and detach the
    // gateway before the network itself is removed (rm fails with live
    // endpoints). No-op unless VPN is enabled.
    await unsyncInstanceVpn(instance);
    if (cname) await docker(["rm", "-f", cname], 30000).catch((e) => log("lab.docker.rm", { ref: cname, error: String(e?.message || e).slice(0, 200) }));
    if (instance.network_name) await docker(["network", "rm", instance.network_name], 30000).catch(() => {});
    const ms = Date.now() - t0;
    if (ms > 10000) log("lab.docker.destroy.slow", { ref: cname || "?", ms });
  },
  endpointOf(instance) {
    const [host, port] = String(instance.host_endpoint || "").split(":");
    return { host: host || "127.0.0.1", port: parseInt(port, 10) || 43 };
  },
};

// ---------------------------------------------------------------- local
// Same observable behavior without a Docker daemon: a loopback TCP/43-style
// server per instance. Virtual 10.x IPs are display identifiers; the
// terminal gateway and smoke tests route through the real loopback endpoint.
const localServers = new Map(); // instanceId -> { server, port }
let localSubnetCounter = 2;

function virtualSubnet(suffix = 10) {
  const hostOctet = Number.isInteger(suffix) && suffix >= 2 && suffix <= 254 ? suffix : 10;
  const third = (localSubnetCounter++ % 250) + 1;
  return { cidr: `${LOCAL_SUBNET_BASE}.${third}.0/24`, targetIp: `${LOCAL_SUBNET_BASE}.${third}.${hostOctet}` };
}

function startLocalWhoisServer(responder = buildWhoisResponse) {
  return new Promise((resolve, reject) => {
    const server = net.createServer((sock) => {
      let buf = "";
      const kill = setTimeout(() => sock.destroy(), 8000);
      sock.on("data", (d) => {
        buf += d.toString("utf8");
        if (buf.includes("\n") || buf.length > 1024) {
          clearTimeout(kill);
          const query = buf.split(/\r?\n/)[0].trim();
          sock.end(responder(query));
        }
      });
      sock.on("error", () => {});
    });
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => resolve(server));
  });
}

const localProvider = {
  name: "local",
  async provision(lab, instance) {
    const metas = await getLabTargetsMeta(lab.id).catch(() => []);
    // Scan labs serve the port-scan target (real listeners, both transports).
    if (metas.some((t) => t.target_type === "scan-target")) {
      const srv = await startScanTarget({ host: "127.0.0.1" });
      const tcpPorts = SCAN_TCP_PORTS.map((p) => srv.tcp[p]);
      const udpPorts = SCAN_UDP_PORTS.map((p) => srv.udp[p]);
      localServers.set(instance.id, { scan: srv, portMap: { tcp: srv.tcp, udp: srv.udp } });
      const { cidr, targetIp } = virtualSubnet(SCAN_DISPLAY_OCTET);
      await waitForScanTarget("127.0.0.1", tcpPorts[0], udpPorts[1]);
      return {
        networkName: `local-${instance.id.slice(0, 12)}`, networkCidr: cidr,
        targetIp, targetPort: 53,
        hostEndpoint: encodeScanEndpoint("127.0.0.1", tcpPorts, udpPorts),
        providerReference: `local-scan:${tcpPorts[0]}`,
      };
    }
    // DNS labs serve the authoritative zones over real UDP+TCP/53.
    if (metas.some((t) => t.target_type === "dns-server")) {
      const srv = await startDnsServer({ host: "127.0.0.1", port: 0 });
      localServers.set(instance.id, { dns: srv, port: srv.port });
      const { cidr, targetIp } = virtualSubnet();
      await waitForDns("127.0.0.1", srv.port, "megacorpone.com");
      return {
        networkName: `local-${instance.id.slice(0, 12)}`, networkCidr: cidr,
        targetIp, targetPort: 53,
        hostEndpoint: `127.0.0.1:${srv.port}`, providerReference: `local-dns:${srv.port}`,
      };
    }
    // Flag labs serve their own dataset with the instance's runtime flag;
    // VM #3 serves its static Tech Email dataset; other static labs keep
    // the exact historic responder.
    let responder = buildWhoisResponse;
    const flag = await runtimeFlagFor(lab, instance);
    if (flag) {
      const captured = flag;
      responder = (q) => buildVm2WhoisResponse(q, captured);
    } else if (String(lab?.slug || "") === VM3_SLUG) {
      responder = buildVm3WhoisResponse;
    }
    const server = await startLocalWhoisServer(responder);
    const port = server.address().port;
    localServers.set(instance.id, { server, port });
    const { cidr, targetIp } = virtualSubnet();
    await waitForWhois("127.0.0.1", port, labDomain(lab?.slug));
    return {
      networkName: `local-${instance.id.slice(0, 12)}`, networkCidr: cidr,
      targetIp, targetPort: 43,
      hostEndpoint: `127.0.0.1:${port}`, providerReference: `local:${port}`,
    };
  },
  async destroy(instance) {
    const entry = localServers.get(instance.id);
    if (entry) {
      localServers.delete(instance.id);
      if (entry.scan) await entry.scan.close().catch(() => {});
      else if (entry.dns) await entry.dns.close().catch(() => {});
      else await new Promise((r) => entry.server.close(r));
    }
  },
  endpointOf(instance) {
    const [host, port] = String(instance.host_endpoint || "").split(":");
    return { host: host || "127.0.0.1", port: parseInt(port, 10) || 0 };
  },
};

// ---------------------------------------------------------------- external research
// Browser-based OSINT exercises (e.g. 6.2.2 Google Hacking) have no target
// infrastructure: the learner works on the live public web. Provisioning
// only records a logical session (progress, submissions, notes, hints) and
// destroy is a no-op. Never a container, never a fake IP.
export function isOsintLab(lab) {
  return lab?.environment_type === "osint";
}

const externalResearchProvider = {
  name: "external-research",
  async provision(lab, instance) {
    return {
      networkName: "", networkCidr: "",
      targetIp: "", targetPort: 0,
      hostEndpoint: "", providerReference: `external-research:${instance.id || "none"}`,
    };
  },
  async destroy(instance) { /* nothing to tear down */ },
  endpointOf(instance) {
    return { host: "", port: 0 };
  },
};

// ---------------------------------------------------------------- nmap multi-target
// Port Scanning with Nmap (6.3.3): an isolated range with several targets
// plus an attacker shell box. The learner runs REAL nmap/NSE/nc/grep in the
// attacker context (docker exec, or an unshared-namespace shell locally).
// Target roles come from each target's metadata_json ({role, ipSuffix});
// NOTHING service-identifying is derived from names or ports.
export const NMAP_ATTACKER_OCTET = 2;

export async function isShellLab(lab) {
  try {
    if (!lab) return false;
    if (lab?.id) {
      const targets = await getLabTargetsMeta(lab.id);
      if (targets.some((t) => t.target_type === "attacker")) return true;
    }
    return String(lab?.slug || "") === NMAP_SLUG;
  } catch { return false; }
}

function nmapRoleOf(target) {
  try { return JSON.parse(target.metadata_json || "{}").role || ""; }
  catch { return ""; }
}

function nmapSuffixOf(target) {
  try {
    const s = parseInt(JSON.parse(target.metadata_json || "{}").ipSuffix, 10);
    if (Number.isInteger(s) && s >= 2 && s <= 254) return s;
  } catch {}
  return 0;
}

// Display topology for routes/tests: attacker + lab boxes with display IPs
// derived from the instance CIDR. Services are NEVER included.
export async function nmapTopology(labId, cidr) {
  const targets = await getLabTargetsMeta(labId);
  const base = String(cidr || "").split(".").slice(0, 3).join(".");
  const boxes = [];
  let attacker = null;
  for (const t of targets) {
    const suffix = t.target_type === "attacker" ? NMAP_ATTACKER_OCTET : nmapSuffixOf(t);
    const ip = suffix ? `${base}.${suffix}` : "";
    if (t.target_type === "attacker") attacker = { name: t.name, ip };
    else boxes.push({ name: t.name, ip });
  }
  boxes.sort((a, b) => a.name.localeCompare(b.name));
  return { subnet: cidr, attacker, boxes };
}

function readManifest(instance) {
  try {
    // Accept both DB rows (snake_case) and provision detail objects.
    const raw = instance.provider_reference ?? instance.providerReference ?? "";
    const m = JSON.parse(raw || "");
    if (m && m.kind === "nmap-multi") return m;
  } catch {}
  return null;
}

// Per-instance runtime flags for range labs with flag objectives. Minted at
// provisioning, rotated on reset, cleared on stop (VM #2 pattern).
// 6.3.3: two flags (high-port + web). 6.3.4: one flag (alfred share comment).
async function nmapFlagsFor(lab, instance) {
  const { ensureRuntimeFlag } = await import("./service.js");
  const q4 = await ensureRuntimeFlag({
    instanceId: instance.id, labId: lab.id || "",
    userId: instance.user_id || "", objectiveKey: "high-port-flag",
  });
  const q5 = await ensureRuntimeFlag({
    instanceId: instance.id, labId: lab.id || "",
    userId: instance.user_id || "", objectiveKey: "web-flag",
  });
  return { q4: q4?.flag_value || "", q5: q5?.flag_value || "" };
}

async function smbFlagsFor(lab, instance) {
  const { ensureRuntimeFlag } = await import("./service.js");
  const smb = await ensureRuntimeFlag({
    instanceId: instance.id, labId: lab.id || "",
    userId: instance.user_id || "", objectiveKey: "alfred-flag",
  });
  return { smb: smb?.flag_value || "" };
}

async function rangeFlagsFor(lab, instance, metas = []) {
  if (String(lab?.slug || "") === SMB_SLUG) return smbFlagsFor(lab, instance);
  if (String(lab?.slug || "") === NMAP_SLUG) return nmapFlagsFor(lab, instance);
  if (rangeTargetsOf(metas).some((t) => SCAN_ROLES.has(nmapRoleOf(t)))) return scanFlagsFor(lab, instance, metas);
  // SMTP/SNMP labs grade static answers (hash-validated); no per-instance
  // secrets are minted, so provisioning mints nothing.
  return {};
}

// Scanner-range secrets: the sitemap page flag (only labs whose objectives
// include it) and the VM#1 SSH password (only ranges with an SSH role).
// Both are per-instance, cleared with the instance, and never baked in.
async function scanFlagsFor(lab, instance, metas) {
  const { ensureRuntimeFlag, ensureSshPassword, labObjectives } = await import("./service.js");
  const out = {};
  try {
    const objectives = await labObjectives(lab.id);
    if (objectives.some((o) => o.objective_key === "sitemap-flag")) {
      const row = await ensureRuntimeFlag({
        instanceId: instance.id, labId: lab.id || "",
        userId: instance.user_id || "", objectiveKey: "sitemap-flag",
      });
      out.sitemapFlag = row?.flag_value || "";
    }
  } catch { /* static labs provision exactly as before */ }
  if (metas.some((t) => nmapRoleOf(t) === "scan-apache")) {
    out.sshPassword = await ensureSshPassword({ instanceId: instance.id, labId: lab.id || "", userId: instance.user_id || "" });
  }
  return out;
}

// Expected service ports per target role (readiness probes + sandbox
// checks), each as {port, proto}. nmap roles keep their exact historic
// ports; smb* roles expose TCP/445 only; smtp-vrfy exposes TCP/25; the
// snmp role exposes UDP/161 only (decoys reuse nmap roles verbatim).
function rangeProbePorts(role) {
  const tcp = (...ports) => ports.map((port) => ({ port, proto: "tcp" }));
  if (role === "smtp") return tcp(25);
  if (role === "whois") return tcp(43);
  if (role === "dc") return tcp(53, 88, 135, 139);
  if (role === "vm1") return tcp(59811, 80);
  if (SMB_ROLES.has(role)) return tcp(SMB_PORT);
  if (SMTP_ROLES.has(role)) return tcp(SMTP_PORT);
  if (SNMP_ROLES.has(role)) return [{ port: SNMP_PORT, proto: "udp" }];
  if (role === "scan-apache") return tcp(80, 9999, 22);
  if (role === "scan-jetty") return tcp(8080, 9999);
  if (role === "scan-web-a" || role === "scan-web-b") return tcp(80, 9999);
  return [];
}

// Range targets share one metadata shape ({role, ipSuffix}) across the
// nmap-target, smb-target, smtp-target, snmp-target, and scanner-target
// types; decoys are nmap-target rows inside the newer labs. Attacker and
// console rows carry no role.
function rangeTargetsOf(metas) {
  return metas.filter((t) => ["nmap-target", "smb-target", "smtp-target", "snmp-target", "scanner-target"].includes(t.target_type));
}

// Per-target container capabilities. Baseline stays dropped-ALL (the 6.3.3
// posture, unchanged); the attacker keeps NET_RAW for SYN scans; smbd
// targets add exactly the file-server minimum (bind 445 + token
// management) because smbd cannot run unprivileged.
function rangeTargetCaps(t) {
  const role = nmapRoleOf(t);
  if (SMB_ROLES.has(role)) return ["NET_BIND_SERVICE", "SETUID", "SETGID"];
  return [];
}

// Per-target container environment. nmap-image rows keep their exact
// historic variables; smb-image rows take TARGET_HOST + (alfred only)
// the runtime flag; scan-image rows take TARGET_HOST + (web-b only) the
// sitemap flag + (apache only) the SSH credentials. Nothing answer-bearing
// reaches any other container.
function rangeTargetEnv(t, role, flags) {
  const env = ["--env", `TARGET_ROLE=${role}`, "--env", "TARGET_HOST=0.0.0.0"];
  if (role === "vm1") env.push("--env", "TARGET_FIXED_PORTS=1", "--env", `FLAG_Q4=${flags.q4 || ""}`, "--env", `FLAG_Q5=${flags.q5 || ""}`);
  else if (role === "smb-alfred") env.push("--env", `FLAG_SMB=${flags.smb || ""}`);
  else if (SCAN_ROLES.has(role)) {
    env.push("--env", "TARGET_FIXED_PORTS=1");
    if (role === "scan-web-b" && flags.sitemapFlag) env.push("--env", `FLAG_723=${flags.sitemapFlag}`);
    if (role === "scan-apache" && flags.sshPassword) env.push("--env", "SCAN_SSH_USER=scanner", "--env", `SCAN_SSH_PASSWORD=${flags.sshPassword}`);
  }
  else if (!SMB_ROLES.has(role)) env.push("--env", "TARGET_FIXED_PORTS=1");
  return env;
}

async function dockerMultiProvision(lab, instance, metas) {
  const labTargets = rangeTargetsOf(metas);
  const attacker = metas.find((t) => t.target_type === "attacker");
  if (!labTargets.length || !attacker) throw new Error("Range lab needs target and attacker definitions.");
  for (const t of [...labTargets, attacker]) await ensureImage(t.image_reference, t.metadata_json);
  const flags = await rangeFlagsFor(lab, instance, metas);
  const { name: networkName, cidr } = await pickDockerSubnet(10);
  const base = cidr.split(".").slice(0, 3).join(".");
  await docker(["network", "create", "--driver", "bridge", `--subnet=${cidr}`, "--internal=false", networkName], 30000);
  const prefix = safeName("axiom", instance.id);
  const cnames = [];
  const cleanup = async () => {
    for (const c of cnames) await docker(["rm", "-f", c], 30000).catch(() => {});
    await docker(["network", "rm", networkName], 30000).catch(() => {});
  };
  try {
    for (const t of labTargets) {
      const role = nmapRoleOf(t);
      const cname = `${prefix}-${t.name.toLowerCase().replace(/[^a-z0-9-]/g, "")}`;
      const ip = `${base}.${nmapSuffixOf(t)}`;
      const extraCaps = rangeTargetCaps(t).flatMap((c) => ["--cap-add", c]);
      const runArgs = [
        "run", "-d", "--name", cname,
        "--network", networkName, "--ip", ip,
        "--network-alias", containerHostname(t),
        "--memory", "128m", "--cpus", "0.5", "--pids-limit", "128",
        "--cap-drop", "ALL", ...extraCaps, "--security-opt", "no-new-privileges",
        "--read-only", "--tmpfs", "/tmp",
        "--hostname", containerHostname(t),
        ...rangeTargetEnv(t, role, flags),
        t.image_reference,
      ];
      await docker(runArgs, 60000);
      cnames.push(cname);
    }
    // Attacker: unprivileged shell box with raw-socket capability for SYN scans.
    const kaliName = `${prefix}-kali`;
    await docker([
      "run", "-d", "--name", kaliName,
      "--network", networkName, "--ip", `${base}.${NMAP_ATTACKER_OCTET}`,
      "--network-alias", "kali",
      "--memory", "512m", "--cpus", "1.0", "--pids-limit", "256",
      "--cap-drop", "ALL", "--cap-add", "NET_RAW", "--security-opt", "no-new-privileges",
      "--read-only", "--tmpfs", "/tmp", "--tmpfs", "/workspace",
      "--hostname", "kali",
      "--workdir", "/workspace",
      attacker.image_reference,
    ], 60000);
    cnames.push(kaliName);
    // Readiness: every service port answers directly on the isolated net.
    const selfContainer = process.env.AXIOM_SELF_CONTAINER || "";
    if (selfContainer) {
      try {
        await docker(["network", "connect", networkName, selfContainer], 15000);
      } catch (e) {
        throw new Error(`Axiom could not join lab network as ${selfContainer} — check AXIOM_SELF_CONTAINER. ${String(e?.message || e).slice(0, 160)}`);
      }
    }
    const waitTcp = (ip, port) => tcpConnect(ip, port, 5000);
    // Genuine SNMP readiness: a real GetRequest for sysDescr.0 with the
    // lab community must come back as a valid GetResponse (an empty
    // datagram would prove nothing — a proper agent stays silent then).
    const waitSnmp = (ip, port) => new Promise((resolve) => {
      let done = false;
      const finish = (v) => { if (!done) { done = true; clearTimeout(timer); try { sock.close(); } catch {} resolve(v); } };
      const sock = dgram.createSocket("udp4");
      const timer = setTimeout(() => finish(false), 5000);
      sock.on("error", () => finish(false));
      sock.on("message", (msg) => {
        const r = parseSnmpResponse(msg);
        finish(!!r && r.errorStatus === 0 && r.pairs.length > 0);
      });
      try {
        sock.send(buildSnmpGet({}), port, ip, (e) => { if (e) finish(false); });
      } catch { finish(false); }
    });
    // Fresh closures per attempt (a new handshake every round, not one
    // cached promise): every expected service port on every range target.
    const probeFns = [];
    for (const t of labTargets) {
      for (const { port, proto } of rangeProbePorts(nmapRoleOf(t))) {
        const ip = `${base}.${nmapSuffixOf(t)}`;
        probeFns.push(proto === "udp" ? () => waitSnmp(ip, port) : () => waitTcp(ip, port));
      }
    }
    const deadline = Date.now() + 90000;
    let ready = false;
    let lastErr = null;
    while (!ready && Date.now() < deadline) {
      try {
        const rs = await Promise.all(probeFns.map((fn) => fn()));
        ready = rs.every(Boolean);
        if (!ready) lastErr = new Error("Targets not ready yet.");
      } catch (e) { lastErr = e; }
      if (!ready) await new Promise((r) => setTimeout(r, 2000));
    }
    if (!ready) throw lastErr || new Error("Lab range did not become ready.");
    for (const t of labTargets) {
      await syncInstanceVpn({
        id: instance.id, user_id: instance.user_id || "",
        provider: "docker", network_name: networkName, target_ip: `${base}.${nmapSuffixOf(t)}`,
      });
    }
    return {
      networkName, networkCidr: cidr, targetIp: `${base}.${NMAP_ATTACKER_OCTET}`, targetPort: 0,
      hostEndpoint: "",
      providerReference: JSON.stringify({ kind: "nmap-multi", labSlug: lab?.slug || "", kali: kaliName, containers: cnames }),
    };
  } catch (e) {
    await cleanup();
    throw e;
  }
}

async function dockerMultiDestroy(instance) {
  const m = readManifest(instance);
  if (!m) return;
  const selfContainer = process.env.AXIOM_SELF_CONTAINER || "";
  if (selfContainer && instance.network_name) {
    await docker(["network", "disconnect", "-f", instance.network_name, selfContainer], 15000).catch(() => {});
  }
  await unsyncInstanceVpn(instance);
  for (const c of m.containers || []) await docker(["rm", "-f", c], 30000).catch(() => {});
  if (instance.network_name) await docker(["network", "rm", instance.network_name], 30000).catch(() => {});
}

async function dockerMultiAlive(instance) {
  const m = readManifest(instance);
  if (!m?.containers?.length) return false;
  for (const c of m.containers) {
    try {
      const { stdout } = await docker(["inspect", "-f", "{{.State.Running}}", c], 15000);
      if (stdout.trim() !== "true") return false;
    } catch { return false; }
  }
  return true;
}

// ---------- scanner ranges (Module 7.2) ----------
// Vulnerability-scanning labs run the Axiom scanner (server-side engine)
// against an isolated target range. Students configure scans in the web
// Scanner tab — there is no attacker shell and no terminal. Targets are
// real listeners; the server reaches them through loopback-mapped ports
// (published container ports on docker, ephemeral loopback binds locally),
// recorded in the manifest loopMap {suffix: {p80, p8080, p9999, p22}}.
// The manifest keeps kind "nmap-multi" (orchestrator-managed range) so
// destroy/reconcile dispatch is reused unchanged.
export async function isScannerLab(lab) {
  try {
    if (!lab) return false;
    if (lab?.id) {
      const targets = await getLabTargetsMeta(lab.id);
      if (targets.some((t) => t.target_type === "scanner-target")) return true;
    }
    return ["m7-7-2-3-vuln-scan", "m7-7-2-4-analyzing-results", "m7-7-2-5-auth-scan", "m7-7-2-6-nessus-plugins"].includes(String(lab?.slug || ""));
  } catch { return false; }
}

// Console-only scanner labs (7.2.2: templates + settings, no range).
// Their instances are logical sessions (external-research provider), so
// boot reconciliation skips them exactly like osint/theory sessions.
export async function isScannerConsoleLab(lab) {
  try {
    if (!lab) return false;
    if (lab?.id) {
      const targets = await getLabTargetsMeta(lab.id);
      if (targets.some((t) => t.target_type === "scanner-target")) return false;
      if (targets.some((t) => t.target_type === "scanner-console")) return true;
      return false;
    }
    return String(lab?.slug || "") === "m7-7-2-2-nessus-components";
  } catch { return false; }
}

function scanRoleFixedPorts(role) {
  if (role === "scan-apache") return [80, 9999, 22];
  if (role === "scan-jetty") return [8080, 9999];
  if (role === "scan-web-a" || role === "scan-web-b") return [80, 9999];
  return [];
}

async function dockerScannerProvision(lab, instance, metas) {
  const labTargets = metas.filter((t) => t.target_type === "scanner-target");
  if (!labTargets.length) throw new Error("Scanner lab needs scanner-target definitions.");
  for (const t of labTargets) await ensureImage(t.image_reference, t.metadata_json);
  const flags = await rangeFlagsFor(lab, instance, metas);
  const { name: networkName, cidr } = await pickDockerSubnet(10);
  const base = cidr.split(".").slice(0, 3).join(".");
  await docker(["network", "create", "--driver", "bridge", `--subnet=${cidr}`, "--internal=false", networkName], 30000);
  const prefix = safeName("axiom", instance.id);
  const cnames = [];
  const loopMap = {};
  const cleanup = async () => {
    for (const c of cnames) await docker(["rm", "-f", c], 30000).catch(() => {});
    await docker(["network", "rm", networkName], 30000).catch(() => {});
  };
  try {
    for (const t of labTargets) {
      const role = nmapRoleOf(t);
      const cname = `${prefix}-${t.name.toLowerCase().replace(/[^a-z0-9-]/g, "")}`;
      const ip = `${base}.${nmapSuffixOf(t)}`;
      const pubs = scanRoleFixedPorts(role).flatMap((p) => ["--publish", `127.0.0.1::${p}`]);
      const runArgs = [
        "run", "-d", "--name", cname,
        "--network", networkName, "--ip", ip,
        "--network-alias", containerHostname(t),
        "--memory", "256m", "--cpus", "0.5", "--pids-limit", "128",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--read-only", "--tmpfs", "/tmp", "--tmpfs", "/run",
        "--hostname", containerHostname(t),
        ...rangeTargetEnv(t, role, flags),
        t.image_reference,
      ];
      pubs.forEach((a) => runArgs.splice(runArgs.length - 1, 0, a));
      await docker(runArgs, 60000);
      cnames.push(cname);
    }
    // Loopback map: what the scanner engine dials (never served to clients
    // beyond owner-scoped connection info; ports stay server-side).
    for (const t of labTargets) {
      const cname = `${prefix}-${t.name.toLowerCase().replace(/[^a-z0-9-]/g, "")}`;
      const { stdout } = await docker(["port", cname], 15000);
      const entry = {};
      for (const p of scanRoleFixedPorts(nmapRoleOf(t))) {
        entry[`p${p}`] = dockerPortMapped(stdout, `${p}/tcp`);
      }
      loopMap[nmapSuffixOf(t)] = entry;
    }
    if (Object.values(loopMap).some((e) => Object.values(e).some((p) => !p))) {
      throw new Error("Scanner target started but its service ports were not mapped.");
    }
    // Readiness: every mapped service port answers on loopback.
    const deadline = Date.now() + 90000;
    let ready = false;
    while (!ready && Date.now() < deadline) {
      const checks = [];
      for (const entry of Object.values(loopMap)) {
        for (const port of Object.values(entry)) checks.push(tcpConnect("127.0.0.1", port, 5000));
      }
      ready = (await Promise.all(checks)).every(Boolean);
      if (!ready) await new Promise((r) => setTimeout(r, 2000));
    }
    if (!ready) throw new Error("Scanner range did not become ready.");
    const firstSuffix = nmapSuffixOf(labTargets[0]);
    return {
      networkName, networkCidr: cidr, targetIp: `${base}.${firstSuffix}`, targetPort: 0,
      hostEndpoint: "",
      providerReference: JSON.stringify({ kind: "nmap-multi", labSlug: lab?.slug || "", containers: cnames, loopMap }),
    };
  } catch (e) {
    await cleanup();
    throw e;
  }
}

const scannerServers = new Map(); // instanceId -> [target handles]

async function localScannerProvision(lab, instance, metas) {
  const { startScanRole } = await import("./vuln-targets.js");
  const labTargets = metas.filter((t) => t.target_type === "scanner-target");
  if (!labTargets.length) throw new Error("Scanner lab needs scanner-target definitions.");
  const flags = await rangeFlagsFor(lab, instance, metas);
  const { cidr } = await pickLocalSubnet();
  const base = cidr.split(".").slice(0, 3).join(".");
  const handles = [];
  const loopMap = {};
  const cleanup = async () => {
    scannerServers.delete(instance.id);
    for (const h of handles) await h.close().catch(() => {});
  };
  try {
    for (const t of labTargets) {
      const role = nmapRoleOf(t);
      const suffix = nmapSuffixOf(t);
      const h = await startScanRole(role, {
        host: "127.0.0.1",
        flag: role === "scan-web-b" ? (flags.sitemapFlag || "") : "",
        ssh: role === "scan-apache" && flags.sshPassword
          ? { user: "scanner", password: flags.sshPassword, port: 0 }
          : null,
      });
      handles.push(h);
      const entry = {};
      if (h.ports.http80) entry.p80 = h.ports.http80;
      if (h.ports.http8080) entry.p8080 = h.ports.http8080;
      if (h.ports.http9999) entry.p9999 = h.ports.http9999;
      if (h.sshPort) entry.p22 = h.sshPort;
      loopMap[suffix] = entry;
    }
    scannerServers.set(instance.id, handles);
    // Readiness: every mapped service port answers on loopback.
    for (const entry of Object.values(loopMap)) {
      for (const port of Object.values(entry)) {
        if (!await tcpConnect("127.0.0.1", port, 5000)) throw new Error("Scanner target did not become ready.");
      }
    }
  } catch (e) {
    await cleanup();
    throw e;
  }
  const firstSuffix = nmapSuffixOf(labTargets[0]);
  return {
    networkName: `local-${instance.id.slice(0, 12)}`, networkCidr: cidr,
    targetIp: `${base}.${firstSuffix}`, targetPort: 0,
    hostEndpoint: "",
    providerReference: JSON.stringify({ kind: "nmap-multi", labSlug: lab?.slug || "", loopMap }),
  };
}

async function scannerLocalDestroy(instance) {
  const handles = scannerServers.get(instance.id);
  scannerServers.delete(instance.id);
  if (handles) {
    for (const h of handles) await h.close().catch(() => {});
  }
}

// ---------- local unshare sandbox ----------
// One supervisor process per instance holds a private net+mount namespace,
// runs every target role on lab-subnet addresses, and executes attacker
// shell commands over a unix socket. Requires unshare/ip/node on the host
// (dev/CI provider; production uses docker).
let unshareChecked = null;
export async function unshareAvailable() {
  if (unshareChecked !== null) return unshareChecked;
  try {
    await execFileAsync("unshare", ["-Urnm", "true"], { timeout: 8000 });
    unshareChecked = true;
  } catch { unshareChecked = false; }
  return unshareChecked;
}

const nsSandboxes = new Map(); // instanceId -> { proc, sockdir, sockPath }

function nsSocketCall(sockPath, payload, timeoutMs = 185000) {
  return new Promise((resolve, reject) => {
    const sock = net.createConnection(sockPath);
    let buf = "";
    const timer = setTimeout(() => { sock.destroy(); reject(new Error("Sandbox command timed out.")); }, timeoutMs);
    sock.on("error", (e) => { clearTimeout(timer); reject(e); });
    sock.on("data", (d) => {
      buf += d.toString("utf8");
      const idx = buf.indexOf("\n");
      if (idx !== -1) {
        clearTimeout(timer);
        sock.destroy();
        try { resolve(JSON.parse(buf.slice(0, idx))); }
        catch (e) { reject(new Error("Bad sandbox response.")); }
      }
    });
    sock.on("connect", () => sock.write(JSON.stringify(payload) + "\n"));
  });
}

async function localMultiProvision(lab, instance, metas) {
  if (!await unshareAvailable()) {
    throw new Error("This lab needs the local unshare sandbox (unshare/ip/node) or LAB_PROVIDER=docker.");
  }
  const labTargets = rangeTargetsOf(metas);
  const attacker = metas.find((t) => t.target_type === "attacker");
  if (!labTargets.length || !attacker) throw new Error("Range lab needs target and attacker definitions.");
  const flags = await rangeFlagsFor(lab, instance, metas);
  const { cidr } = await pickLocalSubnet();
  const base = cidr.split(".").slice(0, 3).join(".");
  const sockdir = fs.mkdtempSync(path.join(os.tmpdir(), "axiom-ns-"));
  const roles = labTargets.map((t) => ({ role: nmapRoleOf(t), ip: `${base}.${nmapSuffixOf(t)}` }));
  const hostnames = labTargets.map((t) => ({ name: containerHostname(t), ip: `${base}.${nmapSuffixOf(t)}` }));
  const probes = [];
  for (const r of roles) {
    for (const { port, proto } of rangeProbePorts(r.role)) probes.push({ ip: r.ip, port, proto });
  }
  fs.writeFileSync(path.join(sockdir, "config.json"), JSON.stringify({
    labSlug: lab?.slug || "", roles, flags, nameserverIp: `${base}.53`, hostnames, probes,
  }));
  fs.writeFileSync(path.join(sockdir, "resolv.conf"), `nameserver ${base}.53\n`);
  const script = path.resolve("server/labs/ns-sandbox.js");
  const proc = spawn("unshare", ["-Urnm", "node", script, sockdir], { stdio: "ignore" });
  nsSandboxes.set(instance.id, { proc, sockdir, sockPath: path.join(sockdir, "sock") });
  const cleanup = async () => {
    nsSandboxes.delete(instance.id);
    await terminateSandboxProc(proc);
    try { fs.rmSync(sockdir, { recursive: true, force: true }); } catch {}
  };
  try {
    const deadline = Date.now() + 90000;
    for (;;) {
      try {
        const r = await nsSocketCall(path.join(sockdir, "sock"), { cmd: "echo sandbox-ready" }, 5000);
        if (r.exit === 0 && r.stdout.includes("sandbox-ready")) break;
      } catch {}
      if (Date.now() > deadline) throw new Error("Local sandbox did not become ready.");
      await new Promise((r) => setTimeout(r, 500));
    }
    // Readiness inside the namespace: every expected service port answers.
    // Built from the provisioned roles (never hardcoded per lab), so each
    // range proves its own topology. TCP pairs go through a bash /dev/tcp
    // loop; UDP/SNMP pairs go through a real in-namespace SNMP query
    // (__probe-snmp), because only a valid GetResponse proves the agent.
    const tcpPairs = probes.filter((p) => p.proto !== "udp").map((p) => `${p.ip}:${p.port}`).join(" ");
    const udpPairs = probes.filter((p) => p.proto === "udp");
    if (tcpPairs) {
      const probe = `for t in ${tcpPairs}; do h=\${t%%:*}; p=\${t##*:}; (exec 3<>/dev/tcp/$h/$p) 2>/dev/null || exit 1; exec 3>&-; done; echo RANGE-READY`;
      const r = await nsSocketCall(path.join(sockdir, "sock"), { cmd: probe }, 60000);
      if (!r.stdout.includes("RANGE-READY")) throw new Error("Sandbox targets did not become ready.");
    }
    for (const p of udpPairs) {
      const r = await nsSocketCall(path.join(sockdir, "sock"), { cmd: `__probe-snmp ${p.ip} ${p.port}` }, 30000);
      if (!r.stdout.includes("SNMP-READY")) throw new Error("Sandbox SNMP target did not become ready.");
    }
  } catch (e) {
    await cleanup();
    throw e;
  }
  return {
    networkName: `local-${instance.id.slice(0, 12)}`, networkCidr: cidr,
    targetIp: `${base}.${NMAP_ATTACKER_OCTET}`, targetPort: 0,
    hostEndpoint: "",
    providerReference: JSON.stringify({ kind: "nmap-multi", labSlug: lab?.slug || "", sandbox: sockdir }),
  };
}

// Destroy prefers SIGTERM (the sandbox runs its closers: Node listeners and
// impacket SMB children shut down) and escalates to SIGKILL only when the
// supervisor does not exit. Plain SIGKILL would orphan impacket children,
// which keep their namespace alive and hold lab ports.
async function terminateSandboxProc(proc, timeoutMs = 5000) {
  try { proc.kill("SIGTERM"); } catch { return; }
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      const exited = proc.exitCode !== null || proc.signalCode !== null;
      if (exited) return;
    } catch { return; }
    if (Date.now() > deadline) break;
    await new Promise((r) => setTimeout(r, 200));
  }
  try { proc.kill("SIGKILL"); } catch {}
}

async function localMultiDestroy(instance) {
  const entry = nsSandboxes.get(instance.id);
  if (entry) {
    nsSandboxes.delete(instance.id);
    await terminateSandboxProc(entry.proc);
    try { fs.rmSync(entry.sockdir, { recursive: true, force: true }); } catch {}
    return;
  }
  // Crash-recovery path: manifest carries the sandbox dir.
  const m = readManifest(instance);
  if (m?.sandbox) {
    try { fs.rmSync(m.sandbox, { recursive: true, force: true }); } catch {}
  }
}

// Local display subnet for multi-target labs (counter-based, like virtualSubnet).
let localMultiCounter = 20;
async function pickLocalSubnet() {
  const third = (localMultiCounter++ % 200) + 10;
  return { cidr: `${LOCAL_SUBNET_BASE}.${third}.0/24` };
}

function providers() { return { docker: dockerProvider, local: localProvider, osint: externalResearchProvider, "external-research": externalResearchProvider }; }
export function providerFor(name) {
  const p = providers()[name];
  if (!p) throw new Error(`Unknown lab provider: ${name}`);
  return p;
}

// Lazy import to avoid a cycle (service.js never imports orchestrator).
async function getLabTargetsMeta(labId) {
  const { labTargets } = await import("./service.js");
  return labTargets(labId);
}

// ---------- high-level lifecycle used by routes ----------
export async function provisionInstance({ lab, instance }) {
  // Multi-target labs (attacker + target group) take the range flow on
  // every provider; everything else keeps its exact historic path.
  if (await isShellLab(lab)) {
    const metas = await getLabTargetsMeta(lab.id);
    if (instance.provider === "docker") return dockerMultiProvision(lab, instance, metas);
    if (instance.provider === "local") return localMultiProvision(lab, instance, metas);
  }
  // Scanner labs (range without attacker shell) provision their target
  // group; a console-only lab (7.2.2) records a logical session instead.
  if (await isScannerLab(lab)) {
    const metas = await getLabTargetsMeta(lab.id);
    const range = metas.filter((t) => t.target_type === "scanner-target");
    if (!range.length) {
      return {
        networkName: "", networkCidr: "",
        targetIp: "", targetPort: 0,
        hostEndpoint: "",
        providerReference: JSON.stringify({ kind: "nmap-multi", labSlug: lab?.slug || "", console: true }),
      };
    }
    if (instance.provider === "docker") return dockerScannerProvision(lab, instance, metas);
    if (instance.provider === "local") return localScannerProvision(lab, instance, metas);
  }
  const provider = providerFor(instance.provider);
  return provider.provision(lab, instance);
}

export async function destroyInstance(instance) {
  try {
    const m = readManifest(instance);
    if (m) {
      if (instance.provider === "docker") await dockerMultiDestroy(instance);
      else if (m.loopMap && !m.sandbox) await scannerLocalDestroy(instance);
      else await localMultiDestroy(instance);
      return;
    }
    await providerFor(instance.provider || "local").destroy(instance);
  } catch (e) {
    log("lab.destroy", { instance: instance.id, error: String(e?.message || e).slice(0, 300) });
  }
}

// ---------- integrated terminal ----------
// Scoped command runner. NEVER a host shell: no shell is spawned, only an
// allowlist of lab-network commands is interpreted, and `whois` performs a
// real TCP/43 query against the instance's own target endpoint.
// The optional lab scopes help text and DNS helpers to the lab's domain;
// without it the terminal behaves exactly as VM #1 always has.
export async function runTerminalCommand(instance, raw, lab = null) {
  const input = String(raw || "").slice(0, 512).trim();
  if (!input) return { output: "" };
  const argv = input.match(/"[^"]*"|'[^']*'|\S+/g)?.map((t) => t.replace(/^["']|["']$/g, "")) || [];
  const cmd = (argv[0] || "").toLowerCase();
  const args = argv.slice(1);
  // OSINT exercises have no network target: the terminal is a convenience
  // wrapper over the same deterministic corpus behind the Search tab.
  if (lab?.environment_type === "osint") return terminalOsint(cmd, args);
  // Theory/knowledge exercises have no network target and no tool output:
  // the terminal offers session helpers only (never fake scan results).
  if (lab?.environment_type === "theory") return terminalTheory(cmd, args);
  // DNS labs query a real authoritative target over UDP+TCP/53.
  if (await isDnsLab(lab)) return terminalDnsLab(instance, cmd, args, lab);
  // Scan labs run genuine socket scans against the isolated target.
  if (await isScanLab(lab)) return terminalScanLab(instance, cmd, args, lab);
  // Attacker-shell labs execute raw commands in the isolated attacker
  // context (real shell: pipes, redirection, files, nmap, grep).
  if (await isShellLab(lab)) return terminalShell(instance, input, lab);
  // Scanner labs have no shell: scanning happens in the Scanner tab.
  if (await isScannerLab(lab)) return terminalScanner(cmd, args);
  const domain = lab ? labDomain(lab.slug ?? lab) : LAB_DOMAIN;
  const zone = lab ? labZone(lab.slug ?? lab) : ZONE;
  switch (cmd) {
    case "help": return { output: helpText(domain) };
    case "clear": return { output: "", clear: true };
    case "echo": return { output: args.join(" ").slice(0, 2000) };
    case "targets": return { output: await targetSummary(instance, lab) };
    case "whois": return terminalWhois(instance, args, domain);
    case "dig":
    case "nslookup":
    case "host": return { output: terminalDns(args, domain, zone) };
    default:
      return { output: `Command not available in the lab terminal: ${cmd}\nAvailable: help, whois, dig, nslookup, host, targets, echo, clear` };
  }
}

function helpText(domain) {
  return [
    "Lab terminal — scoped to this lab environment.",
    "",
    "  whois <domain> [-h <whois-server>]  query the lab WHOIS service (TCP/43)",
    "  dig <domain> [NS]                   minimal lab DNS helper",
    "  nslookup <domain>                   minimal lab DNS helper",
    "  host <domain>                       minimal lab DNS helper",
    "  targets                             show this lab's targets",
    "  echo <text>                         print text",
    "  clear                               clear the terminal",
    "",
    `Example:  whois ${domain} -h <target-ip>`,
  ].join("\n");
}

const HELP_TEXT = helpText(LAB_DOMAIN);

// Attacker-shell labs (6.3.3): the terminal is a real shell inside the
// isolated attacker environment — never the host. Only help/clear are
// interpreted locally; everything else runs verbatim (pipes, redirection,
// output files, nmap, and NSE all work).
const SHELL_MAX_INPUT = 2000;
const SHELL_TIMEOUT_MS = 180000;
const SHELL_OUT_CAP = 256 * 1024;

function shellHelpText(lab = null) {
  const base = [
    "Attacker shell — runs inside your isolated lab network (never the host).",
    "Files you create live in the session workspace and vanish on stop/reset.",
    "",
  ];
  const smb = String(lab?.slug || "") === SMB_SLUG;
  const smtp = String(lab?.slug || "") === SMTP_SLUG;
  const snmp = String(lab?.slug || "") === SNMP_SLUG;
  const examples = smb ? [
    "  nmap -p 445 --open -T4 <subnet>/24 -oN smb.txt",
    "  grep -i open smb.txt",
    "  smbclient -L //<host> -N",
    "  net view \\\\dc01",
    "  enum4linux <host>",
  ] : smtp ? [
    "  nmap -sV -p 25 -T4 --open <subnet>/24 -oN smtp.txt",
    "  grep -i open smtp.txt",
    "  nc -nv <host> 25",
    "  VRFY root",
  ] : snmp ? [
    "  printf 'public\\nprivate\\nmanager\\n' > communities.txt",
    "  onesixtyone -c communities.txt <subnet>/24",
    "  snmpwalk -c public -v1 <host> 1.3.6.1.2.1.25.4.2.1.2",
    "  snmpwalk -c public -v1 -Oa <host> 1.3.6.1.2.1.2.2.1.2",
  ] : [
    "  nmap -sS -p 25 --open -T4 <subnet>/24 -oN scan.txt",
    "  grep -i open scan.txt",
    "  nmap -T4 --script http-title <subnet>/24",
    "  nc -nv <host> <port>",
  ];
  return [...base, ...examples, "",
    "Find your assigned subnet in the Connection tab. Long scans may take",
    "a few minutes; output is capped per command.",
  ].join("\n");
}

function sliceShellOutput(text) {
  if (text.length <= SHELL_OUT_CAP) return text;
  return text.slice(0, SHELL_OUT_CAP) + `\n... [output truncated at ${SHELL_OUT_CAP / 1024}KB]`;
}

async function terminalShell(instance, input, lab = null) {
  const raw = String(input || "").trim();
  if (!raw) return { output: "" };
  const first = (raw.match(/"[^"]*"|'[^']*'|\S+/) || [""])[0].replace(/^["']|["']$/g, "").toLowerCase();
  if (first === "help") return { output: shellHelpText(lab) };
  if (first === "clear" && raw.trim().toLowerCase() === "clear") return { output: "", clear: true };
  if (raw.length > SHELL_MAX_INPUT) return { output: `Command too long (max ${SHELL_MAX_INPUT} characters).` };
  const m = readManifest(instance);
  if (!m) return { output: "Lab session not found. Start the lab first." };
  try {
    if (instance.provider === "docker") {
      if (!m.kali) return { output: "Lab session not found. Start the lab first." };
      const { stdout, stderr } = await execFileAsync(
        "docker", ["exec", "-w", "/workspace", m.kali, "sh", "-c", raw],
        { timeout: SHELL_TIMEOUT_MS, maxBuffer: 4 * 1024 * 1024 });
      return { output: sliceShellOutput(String(stdout || "") + (stderr ? `\n${stderr}` : "")) };
    }
    const sockPath = path.join(m.sandbox || "", "sock");
    const r = await nsSocketCall(sockPath, { cmd: raw, timeoutMs: SHELL_TIMEOUT_MS });
    return { output: sliceShellOutput(String(r.stdout || "") + (r.stderr ? `\n${r.stderr}` : "")) };
  } catch (e) {
    const msg = String(e?.message || e);
    if (/timed out|ETIMEDOUT/i.test(msg)) return { output: "Command timed out. Narrow the scan (fewer ports/hosts) and retry." };
    return { output: "Attacker shell unavailable — the lab may still be starting. Wait a few seconds or reset the lab." };
  }
}

// Scan labs (6.3.2) route to the isolated target for genuine port scans.
async function isScanLab(lab) {
  try {
    if (!lab) return false;
    if (lab?.id) {
      const targets = await getLabTargetsMeta(lab.id);
      if (targets.some((t) => t.target_type === "scan-target")) return true;
    }
    return String(lab?.slug || "") === SCAN_SLUG;
  } catch { return false; }
}

function scanServerAllowed(instance, targetIp, server) {
  if (!server) return true; // default path always uses the lab target
  const s = String(server).toLowerCase().replace(/\.$/, "");
  const known = new Set([
    (targetIp || "").toLowerCase(), (instance.target_ip || "").toLowerCase(),
    "target", "scan", "localhost", "127.0.0.1",
  ]);
  return known.has(s);
}

async function terminalScanLab(instance, cmd, args, lab) {
  const targetIp = instance.target_ip || "<target-ip>";
  const mapped = resolveScanPorts(instance);
  // Fast path probe: if the display target IP is directly routable (docker
  // on a Linux host, or app joined to the lab net), every port is probed
  // genuinely. Otherwise the mapped loopback ports serve the open ports
  // and closed ports short-circuit to refused — identical observable
  // behavior to a real closed port (immediate RST/refusal).
  let direct = null;
  const ensureDirect = async () => {
    if (direct === null) direct = await tcpConnect(targetIp, 53, 700);
    return direct;
  };
  const checkTcp = async (port) => {
    if (await ensureDirect()) return tcpConnect(targetIp, port, 3000);
    const mp = mapped?.tcp?.get(port);
    if (mp) return tcpConnect(mapped.host, mp, 3000);
    return false;
  };
  const checkUdp = async (port, waitMs) => {
    if (await ensureDirect()) return udpProbe(targetIp, port, waitMs);
    const mp = mapped?.udp?.get(port);
    if (mp) return udpProbe(mapped.host, mp, waitMs);
    return false;
  };
  const ctx = {
    targetIp,
    displayIp: targetIp,
    serverAllowed: (s) => scanServerAllowed(instance, targetIp, s),
    checkTcp,
    checkUdp,
  };
  switch (cmd) {
    case "help": return { output: ncHelpText(targetIp) };
    case "clear": return { output: "", clear: true };
    case "echo": return { output: args.join(" ").slice(0, 2000) };
    case "targets": return { output: await targetSummary(instance, lab) };
    case "nc":
    case "ncat":
    case "netcat": return runNc(args, ctx);
    case "whois":
    case "dig":
    case "nslookup":
    case "host":
    case "dnsenum":
      return { output: `No ${cmd} service in this lab. Enumerate open ports instead:\n  nc -vz ${targetIp} 1-1000` };
    default:
      return { output: `Command not available in the lab terminal: ${cmd}\nAvailable: help, nc, targets, echo, clear` };
  }
}

// DNS labs (6.3.1) route to the real authoritative target. Detection is by
// target type so future DNS labs work without slug checks.
async function isDnsLab(lab) {
  try {
    if (!lab) return false;
    if (lab?.id) {
      const targets = await getLabTargetsMeta(lab.id);
      if (targets.some((t) => t.target_type === "dns-server")) return true;
    }
    return String(lab?.slug || "") === DNS_SLUG;
  } catch { return false; }
}

function dnsServerAllowed(instance, targetIp, server) {
  if (!server) return true; // default path always uses the lab target
  const s = String(server).toLowerCase().replace(/\.$/, "");
  const known = new Set([
    (targetIp || "").toLowerCase(), (instance.target_ip || "").toLowerCase(),
    "target", "dns", "localhost", "127.0.0.1",
  ]);
  return known.has(s);
}

async function terminalDnsLab(instance, cmd, args, lab) {
  const targetIp = instance.target_ip || "<target-ip>";
  const ep = resolveDnsEndpoint(instance);
  if (!ep.udpPort) return { output: "Target is not running. Start the lab first." };
  const ctx = {
    targetIp,
    serverHost: ep.host,
    serverPort: ep.udpPort,
    endpointLabel: `${ep.host}#${ep.udpPort}(${ep.host})`,
    serverAllowed: (s) => dnsServerAllowed(instance, targetIp, s),
    query: (name, type, opts = {}) => {
      const tcp = opts.tcp ? true : undefined;
      const port = opts.tcp ? ep.tcpPort : ep.udpPort;
      return dnsQuery(ep.host, port, name, type, { tcp, timeoutMs: 8000 });
    },
  };
  switch (cmd) {
    case "help": return { output: dnsHelpText(targetIp) };
    case "clear": return { output: "", clear: true };
    case "echo": return { output: args.join(" ").slice(0, 2000) };
    case "targets": return { output: await targetSummary(instance, lab) };
    case "dig": return runDig(args, ctx);
    case "nslookup": return runNslookup(args, ctx);
    case "host": return runHost(args, ctx);
    case "dnsenum": return runDnsenum(args, ctx);
    case "whois":
      return { output: `No WHOIS service in this lab. Enumerate DNS instead:\n  dig @${targetIp} megacorpone.com MX` };
    default:
      return { output: `Command not available in the lab terminal: ${cmd}\nAvailable: help, dig, nslookup, host, dnsenum, targets, echo, clear` };
  }
}

// OSINT terminal: this is a browser-based research exercise, so the
// terminal offers no network tooling — only session helpers. Research
// happens on the live web via the Research tab links.
async function terminalOsint(cmd, args) {
  switch (cmd) {
    case "help":
      return {
        output: [
          "Lab terminal — this is a browser-based OSINT exercise (no target network).",
          "",
          "  Research happens in your browser: Google, the MegaCorp One",
          "  public site, and social-media search (see the Research tab).",
          "",
          "  targets          show this lab's environment",
          "  echo <text>      print text",
          "  clear            clear the terminal",
        ].join("\n"),
      };
    case "clear": return { output: "", clear: true };
    case "echo": return { output: args.join(" ").slice(0, 2000) };
    case "targets":
      return { output: ["NAME     External Research", "ACCESS   Live public web (browser-based)", "NETWORK  none — no target VM for this exercise"].join("\n") };
    default:
      return { output: `Command not available in this OSINT exercise: ${cmd}\nResearch is browser-based — see the Research tab. Available: help, targets, echo, clear` };
  }
}

// Theory/knowledge exercises (e.g. 7.1.x vulnerability-scanning concepts)
// have no target, no network, and no tool output: the terminal offers
// session helpers only. It never fabricates scanner results.
async function terminalTheory(cmd, args) {
  switch (cmd) {
    case "help":
      return {
        output: [
          "Lab terminal — this is a knowledge exercise (no target network).",
          "",
          "  Read the scenarios in the Instructions tab, reason from the",
          "  course material, and submit your answers in the Submit panel.",
          "",
          "  targets          show this lab's environment",
          "  echo <text>      print text",
          "  clear            clear the terminal",
        ].join("\n"),
      };
    case "clear": return { output: "", clear: true };
    case "echo": return { output: args.join(" ").slice(0, 2000) };
    case "targets":
      return { output: ["NAME     Knowledge Check", "ACCESS   Instructions tab (reasoning exercise)", "NETWORK  none — no target for this exercise"].join("\n") };
    default:
      return { output: `Command not available in this knowledge exercise: ${cmd}\nThere is no network to scan here — work the scenarios in the Instructions tab. Available: help, targets, echo, clear` };
  }
}

// Scanner labs (Module 7.2) expose no shell: the student configures and
// launches scans in the Scanner tab. The terminal API answers safely
// instead of falling through to unrelated helpers.
async function terminalScanner(cmd, args) {
  switch (cmd) {
    case "help":
      return {
        output: [
          "Lab terminal — scanner labs have no shell.",
          "",
          "  Configure and launch scans in the Scanner tab, then inspect",
          "  findings, sitemap pages, and plugin details there.",
          "",
          "  targets          show this lab's environment",
          "  echo <text>      print text",
          "  clear            clear the terminal",
        ].join("\n"),
      };
    case "clear": return { output: "", clear: true };
    case "echo": return { output: args.join(" ").slice(0, 2000) };
    case "targets":
      return { output: ["RANGE    Scanner targets (see Connection tab)", "ACCESS   Scanner tab (web console)", "NETWORK  isolated lab network"].join("\n") };
    default:
      return { output: `Command not available in scanner labs: ${cmd}\nScanning happens in the Scanner tab. Available: help, targets, echo, clear` };
  }
}

async function targetSummary(instance, lab = null) {
  let name = "VM #1";
  let ports = `${instance.target_port || 43}/tcp (whois)`;
  if (lab?.id) {
    try {
      const targets = await getLabTargetsMeta(lab.id);
      if (targets[0]?.name) name = targets[0].name;
      if (targets.some((t) => t.target_type === "scan-target")) ports = "TCP/UDP (scan to discover)";
      else if (targets.some((t) => t.target_type === "dns-server")) ports = "53/udp+tcp (dns)";
    } catch { /* fall back to the historic default */ }
  }
  return [
    `NAME     ${name}`,
    `IP       ${instance.target_ip || "(provisioning…)"}`,
    `PORT     ${ports}`,
    `NETWORK  ${instance.network_cidr || "(provisioning…)"} (isolated)`,
  ].join("\n");
}

function resolveTargetHost(instance, flag) {
  if (!flag) return null; // null = use the instance endpoint
  const f = String(flag).toLowerCase();
  const known = new Set([(instance.target_ip || "").toLowerCase(), "target", "vm1", "vm1.megacorpone.lab", "vm2", "vm2.offensive-security.lab", "vm3", "vm3.offensive-security.lab", "localhost", "127.0.0.1"]);
  return known.has(f) ? null : flag; // non-target hosts are rejected below
}

async function terminalWhois(instance, args, domain = LAB_DOMAIN) {
  let serverFlag = null;
  const rest = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "-h" && i + 1 < args.length) { serverFlag = args[++i]; }
    else if (args[i].startsWith("-")) return { output: `Unsupported whois option: ${args[i]}\nUsage: whois <domain> [-h <whois-server>]` };
    else rest.push(args[i]);
  }
  if (!rest.length) return { output: "Usage: whois <domain> [-h <whois-server>]" };
  const foreign = resolveTargetHost(instance, serverFlag);
  if (foreign) return { output: `External WHOIS servers are not reachable from the lab terminal.\nUse the lab target: whois ${rest[0]} -h ${instance.target_ip || "<target-ip>"}` };
  const { host, port } = await resolveEndpoint(instance, domain);
  if (!port) return { output: "Target is not running. Start the lab first." };
  try {
    const out = await whoisQuery(host, port, rest[0], 10000);
    return { output: out.slice(0, 8000) || "(empty response)" };
  } catch (e) {
    return { output: `WHOIS query failed: ${targetSafeError(e)}` };
  }
}

function targetSafeError(e) {
  const m = String(e?.message || e);
  if (/timed out/i.test(m)) return "connection timed out — is the target running?";
  return "could not reach the target — is the lab running?";
}

function terminalDns(args, domain = LAB_DOMAIN, zone = ZONE) {
  const lookup = (args.find((a) => !a.startsWith("-")) || "").toLowerCase().replace(/\.$/, "");
  if (!lookup) return "Usage: dig <domain>";
  if (lookup === domain) {
    return [
      `; Lab DNS helper (scoped to ${domain})`,
      ``,
      ...zone.ns.map((ns) => `${domain}.        3600  IN  NS  ${ns}.`),
      ``,
      `;; Use whois against the lab target for authoritative registration data:`,
      `;;   whois ${domain} -h <target-ip>`,
    ].join("\n");
  }
  if (zone.ns.includes(lookup) || zone.ns.includes(lookup + ".")) {
    return `${lookup}.  3600  IN  A  93.184.216.32\n;; Registrar WHOIS: ${zone.registrarWhois}`;
  }
  return `No lab records for ${lookup} (helper is scoped to ${domain}).`;
}

// ---------- boot reconciliation ----------
// Local-process targets die with the app; docker targets may outlive it.
// Local actives are marked failed (never silently "running"); docker
// actives are inspected and reaped when their container is gone.
export async function reconcileOnBoot() {
  const { allActiveInstances, forceInstanceState } = await import("./service.js");
  const { clearRuntimeFlags } = await import("./service.js");
  const actives = await allActiveInstances().catch(() => []);
  for (const inst of actives) {
    try {
      if (inst.provider === "osint" || inst.provider === "external-research") {
        continue; // research-backed exercise: no runtime to die with the app
      }
      if (readManifest(inst)) {
        // Multi-target range: every container must survive, and local
        // sandboxes never survive a restart.
        let alive = inst.provider === "docker" && await dockerAvailable() && await dockerMultiAlive(inst);
        if (!alive) {
          await destroyInstance(inst).catch(() => {});
          await localMultiDestroy(inst).catch(() => {});
          await clearRuntimeFlags(inst.id).catch(() => {});
          await forceInstanceState(inst.id, { status: "failed", error: "Target did not survive restart." });
        } else if (process.env.AXIOM_SELF_CONTAINER && inst.network_name) {
          await docker(["network", "connect", inst.network_name, process.env.AXIOM_SELF_CONTAINER], 15000).catch((e) =>
            log("lab.reconcile.connect", { instance: inst.id, error: String(e?.message || e).slice(0, 200) }));
        }
        continue;
      }
      if (inst.provider === "docker" && await dockerAvailable()) {
        const cname = inst.provider_reference;
        let alive = false;
        if (cname) {
          try {
            const { stdout } = await docker(["inspect", "-f", "{{.State.Running}}", cname], 15000);
            alive = stdout.trim() === "true";
          } catch { alive = false; }
        }
        if (!alive) {
          await destroyInstance(inst).catch(() => {});
          await clearRuntimeFlags(inst.id).catch(() => {});
          await forceInstanceState(inst.id, { status: "failed", error: "Target did not survive restart." });
        } else if (process.env.AXIOM_SELF_CONTAINER && inst.network_name) {
          // A recreated app container loses its lab-network attachments;
          // re-join so the terminal gateway keeps reaching the target.
          await docker(["network", "connect", inst.network_name, process.env.AXIOM_SELF_CONTAINER], 15000).catch((e) =>
            log("lab.reconcile.connect", { instance: inst.id, error: String(e?.message || e).slice(0, 200) }));
        }
      } else if (inst.provider !== "docker") {
        await clearRuntimeFlags(inst.id).catch(() => {});
        await forceInstanceState(inst.id, { status: "failed", error: "Host restarted; start the lab again." });
      }
    } catch (e) {
      log("lab.reconcile", { instance: inst.id, error: String(e?.message || e).slice(0, 200) });
    }
  }
  // Student VPN: re-attach surviving nets, restore peers from the DB,
  // rebuild per-student firewall rules. No-op unless VPN is enabled.
  await reconcileVpn().catch(() => {});
}
