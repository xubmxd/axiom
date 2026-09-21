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
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import { log } from "../log.js";
import { buildWhoisResponse, ZONE, LAB_DOMAIN } from "./whois-data.js";

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

// The app may run on the Docker host (bridge IPs routable) or inside its
// own container (only the published loopback port is routable until the
// app joins the lab network). Prefer the direct target endpoint, fall back
// to the provisioned host endpoint.
export async function resolveEndpoint(instance) {
  const direct = { host: instance.target_ip, port: instance.target_port || 43 };
  if (direct.host) {
    try {
      await whoisQuery(direct.host, direct.port, LAB_DOMAIN, 1500);
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

async function pickDockerSubnet() {
  const used = new Set();
  try {
    const { stdout } = await docker(["network", "ls", "--format", "{{.Name}}"], 15000);
    for (const n of stdout.split("\n")) used.add(n.trim());
  } catch {}
  for (let attempt = 0; attempt < 20; attempt++) {
    const third = 1 + Math.floor(Math.random() * 254);
    const name = `axiom-lab-${DOCKER_SUBNET_BASE.replace(/\./g, "-")}-${third}`;
    if (!used.has(name)) return { name, cidr: `${DOCKER_SUBNET_BASE}.${third}.0/24`, targetIp: `${DOCKER_SUBNET_BASE}.${third}.10` };
  }
  throw new Error("Could not allocate an isolated lab subnet.");
}

const dockerProvider = {
  name: "docker",
  async provision(lab, instance) {
    const metas = await getLabTargetsMeta(lab.id);
    const target = metas.find((t) => t.target_type === "whois-server") || metas[0] || {};
    const image = target.image_reference || "axiom-lab-whois-vm1:latest";
    await ensureImage(image, target.metadata_json);
    const { name: networkName, cidr, targetIp } = await pickDockerSubnet();
    await docker(["network", "create", "--driver", "bridge", `--subnet=${cidr}`, "--internal=false", networkName], 30000);
    const cname = safeName("axiom", instance.id);
    try {
      await docker([
        "run", "-d", "--name", cname,
        "--network", networkName, "--ip", targetIp,
        "--memory", "128m", "--cpus", "0.25", "--pids-limit", "64",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--read-only", "--tmpfs", "/tmp",
        "--publish", "127.0.0.1::43",
        "--hostname", "vm1",
        image,
      ], 60000);
    } catch (e) {
      await docker(["network", "rm", networkName], 15000).catch(() => {});
      throw e;
    }
    // Host-routable endpoint for the app (terminal gateway, health checks).
    const { stdout } = await docker(["port", cname, "43/tcp"], 15000);
    const m = /127\.0\.0\.1:(\d+)/.exec(stdout);
    if (!m) {
      await this.destroy({ ...instance, provider_reference: cname, network_name: networkName }).catch(() => {});
      throw new Error("Target started but its service port was not mapped.");
    }
    const hostPort = parseInt(m[1], 10);
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
        await waitForWhois(targetIp, 43);
      } else {
        await waitForWhois("127.0.0.1", hostPort);
      }
    } catch (e) {
      // Never leave orphans behind a failed start.
      if (selfContainer) await docker(["network", "disconnect", "-f", networkName, selfContainer], 15000).catch(() => {});
      await docker(["rm", "-f", cname], 30000).catch(() => {});
      await docker(["network", "rm", networkName], 30000).catch(() => {});
      throw e;
    }
    return {
      networkName, networkCidr: cidr, targetIp, targetPort: 43,
      hostEndpoint: `127.0.0.1:${hostPort}`, providerReference: cname,
    };
  },
  async destroy(instance) {
    const t0 = Date.now();
    const cname = instance.provider_reference;
    const selfContainer = process.env.AXIOM_SELF_CONTAINER || "";
    if (selfContainer && instance.network_name) {
      await docker(["network", "disconnect", "-f", instance.network_name, selfContainer], 15000).catch(() => {});
    }
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

function virtualSubnet() {
  const third = (localSubnetCounter++ % 250) + 1;
  return { cidr: `${LOCAL_SUBNET_BASE}.${third}.0/24`, targetIp: `${LOCAL_SUBNET_BASE}.${third}.10` };
}

function startLocalWhoisServer() {
  return new Promise((resolve, reject) => {
    const server = net.createServer((sock) => {
      let buf = "";
      const kill = setTimeout(() => sock.destroy(), 8000);
      sock.on("data", (d) => {
        buf += d.toString("utf8");
        if (buf.includes("\n") || buf.length > 1024) {
          clearTimeout(kill);
          const query = buf.split(/\r?\n/)[0].trim();
          sock.end(buildWhoisResponse(query));
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
    const server = await startLocalWhoisServer();
    const port = server.address().port;
    localServers.set(instance.id, { server, port });
    const { cidr, targetIp } = virtualSubnet();
    await waitForWhois("127.0.0.1", port);
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
      await new Promise((r) => entry.server.close(r));
    }
  },
  endpointOf(instance) {
    const [host, port] = String(instance.host_endpoint || "").split(":");
    return { host: host || "127.0.0.1", port: parseInt(port, 10) || 0 };
  },
};

function providers() { return { docker: dockerProvider, local: localProvider }; }
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
  const provider = providerFor(instance.provider);
  return provider.provision(lab, instance);
}

export async function destroyInstance(instance) {
  try {
    await providerFor(instance.provider || "local").destroy(instance);
  } catch (e) {
    log("lab.destroy", { instance: instance.id, error: String(e?.message || e).slice(0, 300) });
  }
}

// ---------- integrated terminal ----------
// Scoped command runner. NEVER a host shell: no shell is spawned, only an
// allowlist of lab-network commands is interpreted, and `whois` performs a
// real TCP/43 query against the instance's own target endpoint.
export async function runTerminalCommand(instance, raw) {
  const input = String(raw || "").slice(0, 512).trim();
  if (!input) return { output: "" };
  const argv = input.match(/"[^"]*"|'[^']*'|\S+/g)?.map((t) => t.replace(/^["']|["']$/g, "")) || [];
  const cmd = (argv[0] || "").toLowerCase();
  const args = argv.slice(1);
  switch (cmd) {
    case "help": return { output: HELP_TEXT };
    case "clear": return { output: "", clear: true };
    case "echo": return { output: args.join(" ").slice(0, 2000) };
    case "targets": return { output: targetSummary(instance) };
    case "whois": return terminalWhois(instance, args);
    case "dig":
    case "nslookup":
    case "host": return { output: terminalDns(args) };
    default:
      return { output: `Command not available in the lab terminal: ${cmd}\nAvailable: help, whois, dig, nslookup, host, targets, echo, clear` };
  }
}

const HELP_TEXT = [
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
  "Example:  whois megacorpone.com -h <target-ip>",
].join("\n");

function targetSummary(instance) {
  return [
    `NAME     ${"VM #1"}`,
    `IP       ${instance.target_ip || "(provisioning…)"}`,
    `PORT     ${instance.target_port || 43}/tcp (whois)`,
    `NETWORK  ${instance.network_cidr || "(provisioning…)"} (isolated)`,
  ].join("\n");
}

function resolveTargetHost(instance, flag) {
  if (!flag) return null; // null = use the instance endpoint
  const f = String(flag).toLowerCase();
  const known = new Set([(instance.target_ip || "").toLowerCase(), "target", "vm1", "vm1.megacorpone.lab", "localhost", "127.0.0.1"]);
  return known.has(f) ? null : flag; // non-target hosts are rejected below
}

async function terminalWhois(instance, args) {
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
  const { host, port } = await resolveEndpoint(instance);
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

function terminalDns(args) {
  const domain = (args.find((a) => !a.startsWith("-")) || "").toLowerCase().replace(/\.$/, "");
  if (!domain) return "Usage: dig <domain>";
  if (domain === LAB_DOMAIN || domain === "megacorpone.com") {
    return [
      `; Lab DNS helper (scoped to ${LAB_DOMAIN})`,
      ``,
      `${LAB_DOMAIN}.        3600  IN  NS  ${ZONE.ns[0]}.`,
      `${LAB_DOMAIN}.        3600  IN  NS  ${ZONE.ns[1]}.`,
      `${LAB_DOMAIN}.        3600  IN  NS  ${ZONE.ns[2]}.`,
      ``,
      `;; Use whois against the lab target for authoritative registration data:`,
      `;;   whois ${LAB_DOMAIN} -h <target-ip>`,
    ].join("\n");
  }
  if (ZONE.ns.includes(domain) || ZONE.ns.includes(domain + ".")) {
    return `${domain}.  3600  IN  A  93.184.216.32\n;; Registrar WHOIS: ${ZONE.registrarWhois}`;
  }
  return `No lab records for ${domain} (helper is scoped to ${LAB_DOMAIN}).`;
}

// ---------- boot reconciliation ----------
// Local-process targets die with the app; docker targets may outlive it.
// Local actives are marked failed (never silently "running"); docker
// actives are inspected and reaped when their container is gone.
export async function reconcileOnBoot() {
  const { allActiveInstances, forceInstanceState } = await import("./service.js");
  const actives = await allActiveInstances().catch(() => []);
  for (const inst of actives) {
    try {
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
          await forceInstanceState(inst.id, { status: "failed", error: "Target did not survive restart." });
        } else if (process.env.AXIOM_SELF_CONTAINER && inst.network_name) {
          // A recreated app container loses its lab-network attachments;
          // re-join so the terminal gateway keeps reaching the target.
          await docker(["network", "connect", inst.network_name, process.env.AXIOM_SELF_CONTAINER], 15000).catch((e) =>
            log("lab.reconcile.connect", { instance: inst.id, error: String(e?.message || e).slice(0, 200) }));
        }
      } else if (inst.provider !== "docker") {
        await forceInstanceState(inst.id, { status: "failed", error: "Host restarted; start the lab again." });
      }
    } catch (e) {
      log("lab.reconcile", { instance: inst.id, error: String(e?.message || e).slice(0, 200) });
    }
  }
}
