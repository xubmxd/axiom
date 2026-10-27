// Axiom scanner job runner: validates a student scan configuration,
// resolves display IPs to the instance's loopback-mapped targets, runs
// the engine, and persists findings + sitemap metadata.
//
// Security boundaries (all enforced here, not in the client):
// - targets must belong to the owning instance's range (suffixes from the
//   provisioned manifest; stale/foreign subnets are rejected)
// - ports are parsed strictly (parsePorts rejects ranges > 2000, non-numeric)
// - the SSH password is memory-only for the run and is NEVER persisted
// - page content is never stored; page views re-fetch live from the target
//   and only for URLs the job actually discovered
import { runVulnScan, parsePorts, SCAN_SSH_USER } from "./scanner-engine.js";
import { SCAN_TEMPLATES, matchPlugins } from "./scanner-plugins.js";

function readManifest(instance) {
  try {
    const raw = instance.provider_reference ?? instance.providerReference ?? "";
    const m = JSON.parse(raw || "");
    if (m && m.kind === "nmap-multi" && m.loopMap) return m;
  } catch {}
  return null;
}

function displayBase(instance) {
  const cidr = instance.network_cidr || instance.networkCidr || "";
  const base = String(cidr).split(".").slice(0, 3).join(".");
  if (!/^\d+\.\d+\.\d+$/.test(base)) throw new Error("Lab network is not ready. Start or reset the lab.");
  return base;
}

function suffixOfIp(base, ip) {
  const m = new RegExp(`^${base.replace(/\./g, "\\.")}\\.(\\d{1,3})$`).exec(String(ip || "").trim());
  if (!m) return 0;
  const s = parseInt(m[1], 10);
  return s >= 2 && s <= 254 ? s : 0;
}

export function scannerTargetsFor(instance) {
  const m = readManifest(instance);
  if (!m) throw new Error("Scanner range is not running. Start the lab first.");
  const base = displayBase(instance);
  return Object.entries(m.loopMap).map(([suffix, ports]) => ({
    displayIp: `${base}.${suffix}`,
    host: "127.0.0.1",
    ports,
  }));
}

export async function launchScan({ lab, instance, userId, config }) {
  const svc = await import("./service.js");
  const name = String(config?.name || "Untitled scan").slice(0, 80) || "Untitled scan";
  const template = SCAN_TEMPLATES.some((t) => t.id === config?.template) ? config.template : "basic";
  const ports = parsePorts(config?.ports ?? "80");
  const rawTargets = Array.isArray(config?.targets) && config.targets.length ? config.targets : null;
  const assessment = config?.assessment && typeof config.assessment === "object" ? config.assessment : {};
  const webapp = assessment.mode === "custom" && assessment.webapp === true;
  const pluginFilter = String(config?.pluginFilter || "").slice(0, 120);
  const auth = config?.auth?.user ? { user: String(config.auth.user).slice(0, 80), password: String(config.auth.password || "") } : null;

  const available = scannerTargetsFor(instance);
  const targets = (rawTargets || available.map((t) => t.displayIp))
    .map((ip) => {
      const base = displayBase(instance);
      const suffix = suffixOfIp(base, ip);
      const found = available.find((t) => t.displayIp === `${base}.${suffix}`);
      if (!suffix || !found) throw new Error(`Target ${ip} is not part of this lab range.`);
      return found;
    });
  if (!targets.length) throw new Error("Select at least one target.");

  const job = await svc.createScanJob({
    instanceId: instance.id, labId: lab.id, userId,
    name, template, targets: targets.map((t) => t.displayIp), ports,
    authUser: auth?.user || "",
    assessment: { mode: assessment.mode === "custom" ? "custom" : "default", webapp },
    pluginFilter,
  });
  // Run in the background; progress is polled. The SSH password stays in
  // this closure and is never written to the database.
  runJob(job.id, { lab, instance, targets, ports, auth, webapp, pluginFilter }).catch(() => {});
  return job;
}

async function runJob(jobId, ctx) {
  const svc = await import("./service.js");
  await svc.updateScanJob(jobId, { status: "running", progress: 0 });
  try {
    const result = await runVulnScan({
      targets: ctx.targets, ports: ctx.ports, auth: ctx.auth,
      webapp: ctx.webapp, pluginFilter: ctx.pluginFilter,
      onProgress: (frac) => svc.updateScanJob(jobId, { progress: Math.round(frac * 100) }).catch(() => {}),
    });
    for (const f of result.findings) await svc.addScanFinding(jobId, ctx.instance.id, f);
    for (const p of result.sitemap) await svc.addSitemapPage(jobId, ctx.instance.id, p);
    await svc.updateScanJob(jobId, { status: "complete", progress: 100 });
  } catch (e) {
    await svc.updateScanJob(jobId, {
      status: "failed",
      error: String(e?.message || e).slice(0, 300),
    }).catch(() => {});
  }
}

// Fetch a discovered sitemap page live (never from stored content —
// content is never persisted). The URL must belong to the job's own
// sitemap, so this endpoint cannot be abused as an open fetch proxy.
export async function fetchSitemapPage({ instance, jobId, url }) {
  const svc = await import("./service.js");
  const job = await svc.getScanJob(jobId);
  if (!job || job.instance_id !== instance.id) throw new Error("Scan not found.");
  const pages = await svc.listSitemapPages(jobId);
  const row = pages.find((p) => p.url === String(url || ""));
  if (!row) throw new Error("URL was not discovered by this scan.");
  const available = scannerTargetsFor(instance);
  const target = available.find((t) => t.displayIp === row.target_ip);
  if (!target) throw new Error("Target is no longer part of this lab range.");
  const mapped = target.ports?.[`p${row.port}`];
  if (!mapped) throw new Error("Port is no longer mapped for this target.");
  const { default: http } = await import("node:http");
  const body = await new Promise((resolve, reject) => {
    const req = http.get({ host: "127.0.0.1", port: mapped, path: row.path || "/", timeout: 8000 }, (res) => {
      let data = "";
      res.on("data", (d) => { if (data.length < 256 * 1024) data += d.toString("utf8"); });
      res.on("end", () => resolve({ status: res.statusCode || 0, html: data }));
    });
    req.on("timeout", () => { req.destroy(); reject(new Error("Page fetch timed out.")); });
    req.on("error", (e) => reject(new Error(`Page fetch failed: ${String(e.message).slice(0, 120)}`)));
  });
  return { url: row.url, status: body.status, title: /<title>([^<]*)<\/title>/i.exec(body.html)?.[1]?.trim() || "", html: body.html };
}

export { SCAN_SSH_USER };
export async function pluginCatalog(filter) {
  return matchPlugins(filter).map((p) => ({
    id: p.id, name: p.name, family: p.family, severity: p.severity,
    description: p.description, remediation: p.remediation,
  }));
}
