import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "axiom-qa723-"));
process.env.DATA_DIR = TMP;
process.env.LAB_PROVIDER = "local";
const REPO = process.cwd();

const db = await import("./server/db.js");
await db.initDb();
const svc = await import("./server/labs/service.js");
const orch = await import("./server/labs/orchestrator.js");
const { createUser } = await import("./server/auth.js");
const u = await createUser({ username: "qa", email: "q@t.local", displayName: "Q", password: "password12345" });
await svc.seedFromDefinitions(path.join(REPO, "labs"));
const lab = await svc.getLab("slug", "m7-7-2-3-vuln-scan");
const tmp = await svc.createInstance({ userId: u.id, labId: lab.id, provider: "local" });
const details = await orch.provisionInstance({ lab, instance: { ...tmp, user_id: u.id } });
await svc.setInstanceStatus(tmp, "running", {
  providerReference: details.providerReference, networkName: details.networkName,
  networkCidr: details.networkCidr, targetIp: details.targetIp, targetPort: details.targetPort,
  hostEndpoint: details.hostEndpoint, startedAt: new Date().toISOString(),
});
const inst = await db.get(`SELECT * FROM lab_instances WHERE id=?`, [tmp.id]);
console.log("CIDR", details.networkCidr);
const { launchScan } = await import("./server/labs/scanner-jobs.js");
const job = await launchScan({ lab, instance: inst, userId: u.id, config: { name: "full", template: "basic" } });
console.log("JOB", job.id, "targets?", JSON.parse(job.targets_json));
for (let i = 0; i < 40; i++) {
  await new Promise((r) => setTimeout(r, 2000));
  const j = await svc.getScanJob(job.id);
  console.log("status", j.status, j.progress);
  if (j.status === "complete" || j.status === "failed") break;
}
const findings = await svc.listScanFindings(job.id);
for (const f of findings) console.log("FINDING:", f.severity, "|", f.plugin_name, "|", f.target_ip + ":" + f.port);
const pages = await svc.listSitemapPages(job.id);
console.log("SITEMAP PAGES:", pages.length);
await orch.destroyInstance({ ...details, id: tmp.id, provider: "local", provider_reference: details.providerReference, network_name: details.networkName, network_cidr: details.networkCidr, target_ip: details.targetIp });
console.log("QA DONE");
process.exit(0);
