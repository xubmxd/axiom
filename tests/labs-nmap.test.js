import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { spawn } from "node:child_process";

// Isolate: temp sqlite file + local provider before any server module loads.
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "axiom-labs-nmap-"));
process.env.DATA_DIR = TMP;
process.env.LAB_PROVIDER = "local";

const REPO = path.resolve(import.meta.dirname, "..");
const SLUG = "m6-6-3-3-nmap";
const DEF = path.join(REPO, "labs/module-06/6.3.3-nmap/lab.json");
const run = promisify(execFile);

function readDef() {
  return JSON.parse(fs.readFileSync(DEF, "utf8"));
}

// Mirror the route lifecycle: provision, then mark running with the
// provisioned details, and return the live DB row for terminal calls.
async function activate(svc, db, lab, tmp, details) {
  await svc.setInstanceStatus(tmp, "running", {
    providerReference: details.providerReference, networkName: details.networkName,
    networkCidr: details.networkCidr, targetIp: details.targetIp, targetPort: details.targetPort,
    hostEndpoint: details.hostEndpoint, startedAt: new Date().toISOString(),
  });
  return { ...(await db.get(`SELECT * FROM lab_instances WHERE id=?`, [tmp.id])), lab_id: lab.id };
}

// DB-shaped instance row for destroy paths (mirrors service rows).
function instRow(details, iid, labId) {
  return {
    ...details, id: iid, provider: "local", lab_id: labId,
    provider_reference: details.providerReference,
    network_name: details.networkName, network_cidr: details.networkCidr,
    target_ip: details.targetIp,
  };
}

async function hostHas(cmd) {
  try {
    await run("sh", ["-c", `command -v ${cmd}`], { timeout: 8000 });
    return true;
  } catch { return false; }
}

describe("nmap definition", () => {
  it("loads as its own exercise under Module 6 (new 6.3.3 section)", async () => {
    const { loadAllDefinitions, validateDefinition, normalizePlacement } = await import("../server/labs/definitions.js");
    const all = loadAllDefinitions(path.join(REPO, "labs"));
    const lab = all.find((l) => l.def.slug === SLUG);
    assert.ok(lab, "6.3.3 lab.json must be discovered");
    assert.deepEqual(validateDefinition(lab.def), []);
    const p = normalizePlacement(lab.def);
    assert.equal(p.courseSlug, "oscp");
    assert.equal(p.moduleNumber, 6);
    assert.equal(p.moduleTitle, "Information Gathering");
    assert.equal(p.section, "6.3.3");
    assert.equal(p.sectionTitle, "Port Scanning with Nmap");
    assert.equal(lab.def.labNumber, 1);
    assert.equal(lab.def.title, "6.3.3 Port Scanning with Nmap");
    const sections = new Set(all.filter((l) => normalizePlacement(l.def).moduleNumber === 6).map((l) => normalizePlacement(l.def).section));
    assert.deepEqual([...sections].sort(), ["6.2.1", "6.2.2", "6.2.3", "6.2.4", "6.3.1", "6.3.2", "6.3.3", "6.3.4", "6.3.5", "6.3.6"]);
  });

  it("declares an attacker plus four neutral multi-targets", async () => {
    const def = readDef();
    assert.equal(def.environment.type, "multi-target");
    assert.equal(def.targets.length, 5);
    const byType = {};
    for (const t of def.targets) byType[t.type] = (byType[t.type] || 0) + 1;
    assert.equal(byType.attacker, 1, "attacker shell box present");
    assert.equal(byType["nmap-target"], 4);
    for (const t of def.targets) {
      assert.ok(t.name && t.image && t.build, "each target needs name/image/build");
      assert.deepEqual(t.ports, [], "no service ports in the definition");
    }
    const roles = def.targets.filter((t) => t.type === "nmap-target").map((t) => t.metadata?.role).sort();
    assert.deepEqual(roles, ["dc", "smtp", "vm1", "whois"]);
    const suffixes = def.targets.filter((t) => t.type === "nmap-target").map((t) => t.metadata?.ipSuffix).sort((a, b) => a - b);
    assert.deepEqual(suffixes, [8, 100, 151, 251]);
    assert.ok(!def.targets.some((t) => /smtp|whois|dc|vm1|mail/i.test(t.name)), "names stay service-neutral");
  });

  it("has five objectives: three canonical plus two runtime flags", async () => {
    const def = readDef();
    assert.equal(def.objectives.length, 5);
    assert.deepEqual(def.objectives.map((o) => o.key),
      ["subnet-smtp", "subnet-whois", "dc-ports", "high-port-flag", "web-flag"]);
    const byKey = Object.fromEntries(def.objectives.map((o) => [o.key, o]));
    assert.equal(byKey["dc-ports"].validation, "comma-list");
    assert.equal(byKey["high-port-flag"].validation, "flag");
    assert.equal(byKey["web-flag"].validation, "flag");
    for (const o of def.objectives) assert.match(o.expectedHash, /^[0-9a-f]{64}$/);
  });

  it("stored hashes match the canonical answers; flag placeholders match nothing guessable", async () => {
    const { verifyAnswer } = await import("../server/labs/answers.js");
    const def = readDef();
    const byKey = Object.fromEntries(def.objectives.map((o) => [o.key, o]));
    assert.ok(verifyAnswer("192.168.50.8", byKey["subnet-smtp"].expectedHash, "case-insensitive-exact"));
    assert.ok(verifyAnswer("192.168.50.251", byKey["subnet-whois"].expectedHash, "case-insensitive-exact"));
    assert.ok(verifyAnswer("53,88,135,139", byKey["dc-ports"].expectedHash, "comma-list"));
    assert.ok(!verifyAnswer("AXIOM{anything}", byKey["high-port-flag"].expectedHash, "flag"));
    assert.ok(!verifyAnswer("flag", byKey["web-flag"].expectedHash, "flag"));
  });

  it("leaks no answers, ports, flags, or evidence paths", async () => {
    const raw = fs.readFileSync(DEF, "utf8");
    assert.ok(!raw.includes("192.168.50"), "canonical IPs must not appear");
    assert.ok(!raw.includes("59811"), "high port must not appear");
    assert.ok(!raw.includes("AXIOM{"), "no flag material");
    assert.ok(!/xampp|\.users/i.test(raw), "no evidence filenames");
    const joined = JSON.stringify(readDef().hints);
    assert.ok(!joined.includes("192.168.50") && !joined.includes("59811"));
    assert.ok(!/\b53\b/.test(joined.replace(/6\.3\.3/g, "")), "hints must not name ports");
  });
});

describe("comma-list validation", () => {
  it("normalizes comma-separated answers independent of spacing/case", async () => {
    const { normalizeAnswer, hashAnswer, verifyAnswer } = await import("../server/labs/answers.js");
    assert.equal(normalizeAnswer("53, 88, 135, 139", "comma-list"), "53,88,135,139");
    assert.equal(normalizeAnswer("  53,88,135,139, ", "comma-list"), "53,88,135,139");
    const h = hashAnswer("53,88,135,139", "comma-list");
    assert.ok(verifyAnswer("53, 88, 135, 139", h, "comma-list"));
    assert.ok(!verifyAnswer("53,88,135", h, "comma-list"));
    assert.ok(!verifyAnswer("53,88,135,140", h, "comma-list"));
    assert.ok(!verifyAnswer("", h, "comma-list"));
  });
});

describe("nmap target roles", () => {
  it("smtp/whois/dc/vm1 serve their ports with correct behavior", async () => {
    const { startRole } = await import("../server/labs/nmap-targets.js");
    // Ephemeral loopback ports (unprivileged test process cannot bind 25/43).
    const smtp = await startRole("smtp", { host: "127.0.0.1", ports: { tcp25: 0 } });
    const whois = await startRole("whois", { host: "127.0.0.1", ports: { tcp43: 0 } });
    const dc = await startRole("dc", { host: "127.0.0.1", ports: { tcp53: 0, tcp88: 0, tcp135: 0, tcp139: 0 } });
    const vm1 = await startRole("vm1", { host: "127.0.0.1", ports: { tcp59811: 0, tcp80: 0 }, flags: { q4: "AXIOM{Q4}", q5: "AXIOM{Q5}" } });
    try {
      const conn = (port, send) => new Promise((resolve) => {
        const s = new net.Socket();
        const t = setTimeout(() => { s.destroy(); resolve(null); }, 3000);
        let out = "";
        s.on("error", () => { clearTimeout(t); resolve(null); });
        s.on("data", (d) => { out += d.toString("utf8"); });
        s.on("close", () => { clearTimeout(t); resolve(out); });
        s.connect(port, "127.0.0.1", () => {
          if (send) s.write(send);
          else setTimeout(() => s.destroy(), 300);
        });
      });
      assert.ok((await conn(smtp.ports[0])) !== null, "smtp accepts");
      const w = await conn(whois.ports[0], "megacorpone.com\r\n");
      assert.ok(w && w.includes("Domain Name"), "whois responds like a WHOIS service");
      const dcPorts = dc.ports;
      assert.equal(dcPorts.length, 4);
      for (const p of dcPorts) assert.ok((await conn(p)) !== null, `dc port ${p} accepts`);
      const f = await conn(vm1.ports[0]);
      assert.ok(f && f.includes("AXIOM{Q4}"), "59811-equivalent returns its flag on connect");
      const http = await new Promise((resolve) => {
        const s = new net.Socket();
        let out = "";
        s.on("error", () => resolve(""));
        s.on("data", (d) => { out += d.toString("utf8"); });
        s.on("close", () => resolve(out));
        s.connect(vm1.ports[1], "127.0.0.1", () => s.write("GET /index.html HTTP/1.0\r\n\r\n"));
        setTimeout(() => { s.destroy(); resolve(out); }, 3000);
      });
      assert.ok(http.includes("<title>Under Construction</title>"), "index carries the exact title");
      assert.ok(http.includes("AXIOM{Q5}"), "index carries its flag");
      assert.ok(!http.includes("AXIOM{Q4}"), "flags stay separated per service");
    } finally {
      await smtp.close(); await whois.close(); await dc.close(); await vm1.close();
    }
  });

  it("ships the exact role modules (no drift between providers)", async () => {
    for (const f of ["nmap-targets.js", "whois-data.js"]) {
      const a = fs.readFileSync(path.join(REPO, "server/labs", f), "utf8");
      const b = fs.readFileSync(path.join(REPO, "lab-images/m6/nmap-633", f), "utf8");
      assert.equal(a, b, `${f} copy must match the canonical module`);
    }
  });
});

describe("nmap images", () => {
  it("target image is hardened and role-driven", async () => {
    const dockerfile = fs.readFileSync(path.join(REPO, "lab-images/m6/nmap-633/Dockerfile"), "utf8");
    assert.ok(dockerfile.includes("USER nmaplab"), "target must not run as root");
    assert.ok(dockerfile.includes("TARGET_ROLE"), "personality comes from env, not the image");
    assert.ok(dockerfile.includes("cap_net_bind_service"));
    assert.ok(!/AXIOM\{|password|secret/i.test(dockerfile), "no secrets in the image definition");
  });

  it("attacker image carries real tooling (nmap+NSE, nc, RDP client)", async () => {
    const dockerfile = fs.readFileSync(path.join(REPO, "lab-images/m6/attacker/Dockerfile"), "utf8");
    for (const pkg of ["nmap", "netcat-openbsd", "dnsutils", "freerdp2-x11", "iproute2", "bash", "grep"]) {
      assert.ok(dockerfile.includes(pkg), `attacker needs ${pkg}`);
    }
    assert.ok(dockerfile.includes("NET_RAW"), "SYN scans need the raw capability, nothing more");
    assert.ok(dockerfile.includes("USER lab"), "attacker shell runs unprivileged");
  });

  it("both images resolve build contexts", async () => {
    const { resolveBuildContext } = await import("../server/labs/orchestrator.js");
    assert.equal(resolveBuildContext("axiom-lab-nmap-633:latest", JSON.stringify({ build: "m6/nmap-633" })), path.resolve(REPO, "lab-images/m6/nmap-633"));
    assert.equal(resolveBuildContext("axiom-lab-attacker:latest", JSON.stringify({ build: "m6/attacker" })), path.resolve(REPO, "lab-images/m6/attacker"));
  });
});

describe("nmap service (sqlite) + local range", () => {
  let svc, db, orch, userId, lab;
  let haveSandbox = true;
  before(async () => {
    db = await import("../server/db.js");
    await db.initDb();
    svc = await import("../server/labs/service.js");
    orch = await import("../server/labs/orchestrator.js");
    haveSandbox = await orch.unshareAvailable();
    if (!haveSandbox) console.log("  (skip range tests: no unshare sandbox on this host)");
    const { createUser } = await import("../server/auth.js");
    const u = await createUser({ username: "nmaptester", email: "nmap@test.local", displayName: "NMAP", password: "password12345" });
    userId = u.id;
    await svc.seedFromDefinitions(path.join(REPO, "labs"));
    lab = await svc.getLab("slug", SLUG);
    assert.ok(lab);
  });

  it("seeds attacker + four neutral targets, five hash-only objectives", async () => {
    const targets = await svc.labTargets(lab.id);
    assert.equal(targets.length, 5);
    assert.equal(targets.filter((t) => t.target_type === "attacker").length, 1);
    assert.equal(targets.filter((t) => t.target_type === "nmap-target").length, 4);
    for (const t of targets) {
      assert.deepEqual(JSON.parse(t.service_ports), []);
      assert.ok(!JSON.stringify(t).match(/59811|192\.168\.50/));
    }
    const objectives = await svc.labObjectives(lab.id);
    assert.equal(objectives.length, 5);
    assert.ok(!("expected_value_hash" in objectives[0]), "hashes must never be served to clients");
    assert.equal((await svc.labHints(lab.id)).length, 5);
  });

  it("provisions an isolated range with canonical octet semantics", async function () {
    if (!haveSandbox) { console.log("  (skip: no sandbox)"); return; }
    const topo = await orch.nmapTopology(lab.id, "10.210.9.0/24");
    assert.equal(topo.subnet, "10.210.9.0/24");
    assert.equal(topo.attacker.ip, "10.210.9.2");
    assert.deepEqual(topo.boxes.map((b) => b.ip).sort(),
      ["10.210.9.100", "10.210.9.151", "10.210.9.251", "10.210.9.8"]);
    const tmp = await svc.createInstance({ userId, labId: lab.id, provider: "local" });
    const details = await orch.provisionInstance({ lab, instance: { ...tmp, user_id: userId } });
    const iid = tmp.id;
    const inst = await activate(svc, db, lab, tmp, details);
    try {
      assert.ok(details.networkCidr.startsWith("10.200."));
      assert.ok(details.targetIp.endsWith(".2"), "instance IP is the attacker");
      assert.match(details.providerReference, /nmap-multi/);
    } finally {
      await orch.destroyInstance(instRow(details, iid, lab.id));
      await svc.clearRuntimeFlags(iid).catch(() => {});
    }
  });

  it("real nmap SYN scan discovers .8, and shell files/grep work (Q1 methodology)", async function () {
    if (!haveSandbox || !await hostHas("nmap")) { console.log("  (skip: needs unshare + host nmap)"); return; }
    const tmp = await svc.createInstance({ userId, labId: lab.id, provider: "local" });
    const details = await orch.provisionInstance({ lab, instance: { ...tmp, user_id: userId } });
    const iid = tmp.id;
    const inst = await activate(svc, db, lab, tmp, details);
    const base = details.networkCidr.split(".").slice(0, 3).join(".");
    const sh = (command) => orch.runTerminalCommand(inst, command, lab).then((r) => r.output);
    try {
      const out = await sh(`nmap -sS -p 25 --open -T4 ${base}.0/24 -oN scan.txt && grep -i open scan.txt`);
      assert.ok(out.includes(`${base}.8`), "subnet SYN scan finds the SMTP host");
      assert.ok(!out.includes(`${base}.151`) && !out.includes(`${base}.251`) && !out.includes(`${base}.100`), "only the SMTP host exposes 25");
      const r = await svc.submitAnswer({ userId, lab, objectiveKey: "subnet-smtp", answer: "192.168.50.8", instanceId: iid });
      assert.ok(r.correct && r.completed);
    } finally {
      await orch.destroyInstance(instRow(details, iid, lab.id));
      await svc.clearRuntimeFlags(iid).catch(() => {});
    }
  }, { timeout: 180000 });

  it("real nmap finds WHOIS on .251 and DC ports on .151 (Q2/Q3 methodology)", async function () {
    if (!haveSandbox || !await hostHas("nmap")) { console.log("  (skip: needs unshare + host nmap)"); return; }
    const tmp = await svc.createInstance({ userId, labId: lab.id, provider: "local" });
    const details = await orch.provisionInstance({ lab, instance: { ...tmp, user_id: userId } });
    const iid = tmp.id;
    const inst = await activate(svc, db, lab, tmp, details);
    const base = details.networkCidr.split(".").slice(0, 3).join(".");
    const sh = (command) => orch.runTerminalCommand(inst, command, lab).then((r) => r.output);
    try {
      const w = await sh(`nmap -sS -p 43 --open -T4 ${base}.0/24`);
      assert.ok(w.includes(`${base}.251`), "WHOIS host discovered");
      assert.ok(!w.includes(`${base}.8`), "SMTP host does not expose 43");
      const dc = await sh(`nmap -sS --open ${base}.151`);
      const ports = [...dc.matchAll(/(\d+)\/tcp\s+open/g)].map((m) => parseInt(m[1], 10));
      assert.deepEqual(ports, [53, 88, 135, 139], "first four DC ports in order");
      for (const [key, ans] of [["subnet-whois", "192.168.50.251"], ["dc-ports", "53,88,135,139"]]) {
        const r = await svc.submitAnswer({ userId, lab, objectiveKey: key, answer: ans, instanceId: iid });
        assert.ok(r.correct, `${key} completes from scanned values`);
      }
      const spaced = await svc.submitAnswer({ userId, lab, objectiveKey: "dc-ports", answer: "53, 88, 135, 139", instanceId: iid });
      assert.ok(spaced.correct, "comma spacing normalizes");
    } finally {
      await orch.destroyInstance(instRow(details, iid, lab.id));
      await svc.clearRuntimeFlags(iid).catch(() => {});
    }
  }, { timeout: 180000 });

  it("high-range discovery + nc flag retrieval and NSE http-title (Q4/Q5 methodology)", async function () {
    if (!haveSandbox || !await hostHas("nmap")) { console.log("  (skip: needs unshare + host nmap)"); return; }
    const tmp = await svc.createInstance({ userId, labId: lab.id, provider: "local" });
    const details = await orch.provisionInstance({ lab, instance: { ...tmp, user_id: userId } });
    const iid = tmp.id;
    const inst = await activate(svc, db, lab, tmp, details);
    const base = details.networkCidr.split(".").slice(0, 3).join(".");
    const sh = (command) => orch.runTerminalCommand(inst, command, lab).then((r) => r.output);
    try {
      const hi = await sh(`nmap -sS -p 50000-60000 -T4 ${base}.100 -Pn`);
      assert.ok(/59811\/tcp\s+open/.test(hi), "high-range service discovered");
      const flag4 = await sh(`nc -nv -w2 ${base}.100 59811`);
      const m4 = /AXIOM\{[0-9a-f]{32}\}/.exec(flag4);
      assert.ok(m4, "flag retrieved over a real connection");
      const r4 = await svc.submitAnswer({ userId, lab, objectiveKey: "high-port-flag", answer: m4[0], instanceId: iid });
      assert.ok(r4.correct && r4.completed, "retrieved flag validates");
      const nse = await sh(`nmap -T4 --script http-title ${base}.0/24`);
      assert.ok(nse.includes("Under Construction"), "NSE http-title identifies the web target");
      assert.equal((nse.match(/Under Construction/g) || []).length, 1, "exactly one matching host");
      const page = await sh(`curl -s http://${base}.100/index.html`);
      const m5 = /AXIOM\{[0-9a-f]{32}\}/.exec(page);
      assert.ok(m5 && m5[0] !== m4[0], "distinct web flag retrieved from the page");
      const r5 = await svc.submitAnswer({ userId, lab, objectiveKey: "web-flag", answer: m5[0], instanceId: iid });
      assert.ok(r5.correct, "web flag validates");
      const p = await svc.labProgress(userId, lab.id);
      assert.ok(p.complete, "all five objectives complete");
    } finally {
      await orch.destroyInstance(instRow(details, iid, lab.id));
      await svc.clearRuntimeFlags(iid).catch(() => {});
    }
  }, { timeout: 240000 });

  it("wrong answers fail: hosts, ports, flags, blanks", async () => {
    const wrong = [
      ["subnet-smtp", "192.168.50.9"], ["subnet-smtp", "10.210.9.8"], ["subnet-smtp", ""],
      ["subnet-whois", "192.168.50.8"], ["subnet-whois", "192.168.50.250"], ["subnet-whois", "   "],
      ["dc-ports", "53,88,135,140"], ["dc-ports", "53,88,135"], ["dc-ports", "53,88,135,139,445"],
      ["dc-ports", "88,53,135,139"], ["dc-ports", ""],
      ["high-port-flag", "AXIOM{00000000000000000000000000000000}"],
      ["high-port-flag", ""],
      ["web-flag", "AXIOM{00000000000000000000000000000000}"],
      ["web-flag", "Under Construction"],
    ];
    for (const [key, ans] of wrong) {
      const r = await svc.submitAnswer({ userId, lab, objectiveKey: key, answer: ans, instanceId: "li_nmapx" });
      assert.ok(r.ok && !r.correct, `${key}=${JSON.stringify(ans)} must fail`);
      assert.ok(!JSON.stringify(r).match(/AXIOM\{[0-9a-f]{32}\}/), "no flag material in responses");
    }
  });

  it("reset rotates flags; stale flags die with the instance", async function () {
    if (!haveSandbox) { console.log("  (skip: no sandbox)"); return; }
    const tmp1 = await svc.createInstance({ userId, labId: lab.id, provider: "local" });
    const d1 = await orch.provisionInstance({ lab, instance: { ...tmp1, user_id: userId } });
    const iid = tmp1.id;
    const inst = await activate(svc, db, lab, tmp1, d1);
    const base = d1.networkCidr.split(".").slice(0, 3).join(".");
    const sh = (command) => orch.runTerminalCommand(inst, command, lab).then((r) => r.output);
    try {
      const f1 = /AXIOM\{[0-9a-f]{32}\}/.exec(await sh(`nc -nv -w2 ${base}.100 59811`))[0];
      assert.ok((await svc.submitAnswer({ userId, lab, objectiveKey: "high-port-flag", answer: f1, instanceId: iid })).correct);
      await orch.destroyInstance(instRow(d1, iid, lab.id));
      await svc.clearRuntimeFlags(iid);
      const tmp2 = await svc.createInstance({ userId, labId: lab.id, provider: "local" });
      const d2 = await orch.provisionInstance({ lab, instance: { ...tmp2, user_id: userId } });
      const inst2 = await activate(svc, db, lab, tmp2, d2);
      const base2 = d2.networkCidr.split(".").slice(0, 3).join(".");
      const sh2 = (command) => orch.runTerminalCommand(inst2, command, lab).then((r) => r.output);
      const f2 = /AXIOM\{[0-9a-f]{32}\}/.exec(await sh2(`nc -nv -w2 ${base2}.100 59811`))[0];
      assert.notEqual(f2, f1, "fresh instance mints a fresh flag");
      const stale = await svc.submitAnswer({ userId, lab, objectiveKey: "high-port-flag", answer: f1, instanceId: tmp2.id });
      assert.ok(!stale.correct, "pre-reset flag no longer validates");
      await orch.destroyInstance(instRow(d2, tmp2.id, lab.id));
      await svc.clearRuntimeFlags(tmp2.id);
    } catch (e) {
      await orch.destroyInstance(instRow({ providerReference: "" }, iid, lab.id)).catch(() => {});
      await svc.clearRuntimeFlags(iid).catch(() => {});
      throw e;
    }
  }, { timeout: 180000 });

  it("never leaks answers or flags through lab reads", async () => {
    for (const row of await svc.labTargets(lab.id)) {
      assert.ok(!JSON.stringify(row).match(/192\.168\.50|59811|AXIOM\{/));
    }
    for (const row of await svc.labObjectives(lab.id)) {
      assert.ok(!JSON.stringify(row).match(/192\.168\.50|AXIOM\{/));
    }
    const labRow = await svc.getLab("slug", SLUG);
    assert.ok(!JSON.stringify(labRow).match(/192\.168\.50|AXIOM\{/));
    assert.ok(!JSON.stringify(await svc.labProgress(userId, lab.id)).match(/AXIOM\{[0-9a-f]{32}\}/));
    assert.ok(!JSON.stringify(await svc.hintsFor(userId, lab.id)).match(/192\.168\.50|59811/));
  });
});

describe("nmap routes (http)", () => {
  const PORT = 3464;
  const BASE = `http://127.0.0.1:${PORT}`;
  let child, cookie, labId;
  before(async () => {
    child = spawn("node", ["server/index.js"], {
      cwd: REPO, env: { ...process.env, PORT: String(PORT), DATA_DIR: TMP, LAB_PROVIDER: "local" },
      stdio: "ignore",
    });
    const deadline = Date.now() + 25000;
    for (;;) {
      try { const r = await fetch(`${BASE}/login`); if (r.ok) break; } catch {}
      if (Date.now() > deadline) throw new Error("test server did not boot");
      await new Promise((r) => setTimeout(r, 200));
    }
    const db = await import("../server/db.js");
    try { await db.initDb(); } catch {}
    const { createUser } = await import("../server/auth.js");
    let user;
    try {
      user = await createUser({ username: "nmaphttp", email: "nmaph@test.local", displayName: "NMAPH", password: "password12345" });
    } catch {
      user = await db.get(`SELECT * FROM users WHERE username=?`, ["nmaphttp"]);
    }
    const r = await fetch(`${BASE}/login`, {
      method: "POST", redirect: "manual",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ identifier: "nmaphttp", password: "password12345" }),
    });
    assert.equal(r.status, 302);
    cookie = (r.headers.get("set-cookie") || "").split(";")[0];
    const labsRes = await fetch(`${BASE}/api/labs`, { headers: { Cookie: cookie } });
    labId = (await labsRes.json()).labs.find((l) => l.slug === SLUG).id;
    assert.ok(labId);
  });
  after(() => { try { child.kill(); } catch {} });

  const get = (p, opts = {}) => fetch(`${BASE}${p}`, { redirect: "manual", headers: { Cookie: cookie }, ...opts });
  const post = (p, body) => fetch(`${BASE}${p}`, {
    method: "POST", headers: { Cookie: cookie, "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });

  it("workspace shows the range without services, ports, or flags", async () => {
    const r = await get(`/labs/oscp/${SLUG}`);
    assert.equal(r.status, 200);
    const html = await r.text();
    for (const crumb of ["6.3.3", "Port Scanning with Nmap", "Lab 1"]) assert.ok(html.includes(crumb), `missing: ${crumb}`);
    assert.ok(html.includes("kali"), "attacker shell framing present");
    assert.ok(!html.includes("59811"), "no high-port answer in HTML");
    assert.ok(!html.includes("192.168.50"), "no canonical IPs in HTML");
    assert.ok(!html.includes("AXIOM{"), "no flag material in HTML");
    assert.ok(!html.includes("Under Construction</title>"), "no web-title answer context in HTML");
    for (const marker of ["Attacker Terminal", "Submit Answer", "Lab Progress", "Connection"]) assert.ok(html.includes(marker));
  });

  it("lab API redacts deployment internals from target listings", async () => {
    const j = await (await get(`/api/labs/${labId}`)).json();
    assert.equal(j.targets.length, 5);
    const blob = JSON.stringify(j.targets);
    assert.ok(!blob.includes("59811") && !blob.includes("192.168.50"));
    assert.ok(!blob.includes("service_ports") && !blob.includes("metadata_json"), "internals redacted");
    assert.ok(blob.includes("Attacker"), "neutral names still served");
  });

  it("full lifecycle over HTTP with real enumeration", async function () {
    const orch = await import("../server/labs/orchestrator.js");
    if (!await orch.unshareAvailable()) { console.log("  (skip: no sandbox)"); return; }
    const svc = await import("../server/labs/service.js");
    const labRow = await svc.getLab("slug", SLUG);
    const postq = (p, body) => fetch(`${BASE}${p}`, {
      method: "POST", headers: { Cookie: cookie, "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    });
    let r = await postq(`/api/labs/${labId}/start`);
    assert.equal(r.status, 200);
    const started = await r.json();
    assert.equal(started.instance.status, "running");
    assert.ok(started.instance.networkCidr.startsWith("10.200."));
    const iid = started.instance.id;
    const base = started.instance.networkCidr.split(".").slice(0, 3).join(".");
    const sh = (command) => postq(`/api/labs/${labId}/terminal`, { command }).then((x) => x.json()).then((j) => j.output);
    const s25 = await sh(`nmap -sS -p 25 --open -T4 ${base}.0/24`);
    assert.ok(s25.includes(`${base}.8`), "terminal subnet scan discovers SMTP");
    const dc = await sh(`nmap -sS --open ${base}.151`);
    assert.deepEqual([...dc.matchAll(/(\d+)\/tcp\s+open/g)].map((m) => +m[1]), [53, 88, 135, 139]);
    r = await postq(`/api/labs/${labId}/submit`, { answers: { "subnet-smtp": "192.168.50.9" } });
    assert.equal((await r.json()).results["subnet-smtp"].correct, false);
    const flag = /AXIOM\{[0-9a-f]{32}\}/.exec(await sh(`nc -nv -w2 ${base}.100 59811`))[0];
    r = await postq(`/api/labs/${labId}/submit`, {
      answers: {
        "subnet-smtp": "192.168.50.8", "subnet-whois": "192.168.50.251",
        "dc-ports": "53,88,135,139", "high-port-flag": flag,
        "web-flag": /AXIOM\{[0-9a-f]{32}\}/.exec(await sh(`curl -s http://${base}.100/`))[0],
      },
    });
    const done = await r.json();
    assert.ok(Object.values(done.results).every((x) => x.correct));
    assert.ok(done.progress.complete);
    assert.equal(done.progress.objectiveDone, 5);
    r = await postq(`/api/labs/${labId}/reset`);
    assert.equal((await r.json()).instance.resetCount, 1);
    r = await postq(`/api/labs/${labId}/stop`);
    assert.equal((await r.json()).instance.status, "stopped");
    const st = await (await get(`/api/labs/${labId}/status`)).json();
    assert.ok(st.progress.complete, "completion survives stop");
  }, { timeout: 240000 });
});
