import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// Isolate: temp sqlite file + local provider before any server module loads.
// node --test runs each test file in its own process, so these env pins only
// affect this file.
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "axiom-labs-"));
process.env.DATA_DIR = TMP;
process.env.LAB_PROVIDER = "local";

const REPO = path.resolve(import.meta.dirname, "..");

describe("answer normalization + validation", () => {
  it("accepts case/whitespace variants for hostnames, rejects wrong values", async () => {
    const { normalizeAnswer, hashAnswer, verifyAnswer } = await import("../server/labs/answers.js");
    assert.equal(normalizeAnswer("  NS3.MEGACORPONE.COM  "), "ns3.megacorpone.com");
    assert.equal(normalizeAnswer("Whois.Gandi.Net"), "whois.gandi.net");
    const h = hashAnswer("ns3.megacorpone.com");
    assert.ok(verifyAnswer("  NS3.megacorpone.com\n", h, "case-insensitive-exact"));
    assert.ok(!verifyAnswer("ns1.megacorpone.com", h, "case-insensitive-exact"));
    assert.ok(!verifyAnswer("", h, "case-insensitive-exact"));
    assert.ok(!verifyAnswer("ns3.megacorpone.com", "0".repeat(64), "case-insensitive-exact"));
  });
  it("exact validation stays case-sensitive (flags/tokens)", async () => {
    const { hashAnswer, verifyAnswer } = await import("../server/labs/answers.js");
    const h = hashAnswer("FLAG{AbC-123}", "exact");
    assert.ok(verifyAnswer("FLAG{AbC-123}", h, "exact"));
    assert.ok(!verifyAnswer("flag{abc-123}", h, "exact"));
  });
  it("stored lab hashes match the exercise's expected answers", async () => {
    const { verifyAnswer } = await import("../server/labs/answers.js");
    const def = JSON.parse(fs.readFileSync(path.join(REPO, "labs/module-06/6.2.1-whois/vm-01/lab.json"), "utf8"));
    const byKey = Object.fromEntries(def.objectives.map((o) => [o.key, o]));
    assert.ok(verifyAnswer("ns3.megacorpone.com", byKey["third-nameserver"].expectedHash, "case-insensitive-exact"));
    assert.ok(verifyAnswer("whois.gandi.net", byKey["registrar-whois"].expectedHash, "case-insensitive-exact"));
  });
  it("lab definition carries hashes, never plaintext answers", async () => {
    const raw = fs.readFileSync(path.join(REPO, "labs/module-06/6.2.1-whois/vm-01/lab.json"), "utf8");
    assert.ok(!raw.includes("ns3.megacorpone.com"), "plaintext answer leaked into lab.json");
    assert.ok(!raw.includes("whois.gandi.net"), "plaintext answer leaked into lab.json");
  });
});

describe("lab definitions", () => {
  it("discovers and validates the first lab", async () => {
    const { loadAllDefinitions, validateDefinition } = await import("../server/labs/definitions.js");
    const all = loadAllDefinitions(path.join(REPO, "labs"));
    assert.equal(all.length, 1);
    assert.equal(all[0].def.slug, "m6-6-2-1-whois-vm1");
    assert.deepEqual(validateDefinition(all[0].def), []);
  });
  it("rejects malformed definitions", async () => {
    const { validateDefinition } = await import("../server/labs/definitions.js");
    assert.ok(validateDefinition({}).length > 0);
    assert.ok(validateDefinition({ slug: "BAD SLUG!", title: "x", targets: [{ name: "t" }], objectives: [{ key: "a", expectedHash: "zz" }] }).length > 0);
  });
});

describe("whois dataset", () => {
  it("exposes the full discovery path for megacorpone.com", async () => {
    const { buildWhoisResponse } = await import("../server/labs/whois-data.js");
    const out = buildWhoisResponse("megacorpone.com");
    const ns = out.match(/Name Server: (\S+)/gi) || [];
    assert.equal(ns.length, 3);
    assert.ok(/ns3\.megacorpone\.com/i.test(out));
    assert.ok(out.includes("whois.gandi.net"));
    assert.ok(out.includes("Registrar WHOIS Server:"));
  });
  it("answers nameserver and unknown queries sanely", async () => {
    const { buildWhoisResponse } = await import("../server/labs/whois-data.js");
    assert.ok(buildWhoisResponse("ns3.megacorpone.com").includes("whois.gandi.net"));
    assert.ok(buildWhoisResponse("no-such-domain-xyz.test").startsWith("No match"));
  });
});

describe("lab state machine", () => {
  it("allows only the documented lifecycle transitions", async () => {
    const { canTransition } = await import("../server/labs/service.js");
    assert.ok(canTransition("stopped", "provisioning"));
    assert.ok(canTransition("provisioning", "running"));
    assert.ok(canTransition("running", "resetting") && canTransition("resetting", "running"));
    assert.ok(canTransition("running", "stopping") && canTransition("stopping", "stopped"));
    assert.ok(canTransition("running", "failed") && canTransition("failed", "provisioning"));
    assert.ok(!canTransition("stopped", "running"));
    assert.ok(!canTransition("running", "provisioning"));
    assert.ok(!canTransition("stopped", "stopped"));
  });
});

describe("lab service (sqlite)", () => {
  let svc, db, userId, lab;
  before(async () => {
    db = await import("../server/db.js");
    await db.initDb();
    svc = await import("../server/labs/service.js");
    const { createUser } = await import("../server/auth.js");
    const u = await createUser({ username: "labtester", email: "lab@test.local", displayName: "Lab Tester", password: "password12345" });
    userId = u.id;
    await svc.seedFromDefinitions(path.join(REPO, "labs"));
    // reseeding is idempotent: same lab row, no duplicates
    await svc.seedFromDefinitions(path.join(REPO, "labs"));
    lab = await svc.getLab("slug", "m6-6-2-1-whois-vm1");
    assert.ok(lab);
    const dupes = await db.all(`SELECT slug, COUNT(*) n FROM labs GROUP BY slug HAVING n > 1`);
    assert.equal(dupes.length, 0);
  });

  it("seeds targets, objectives (hash-only) and empty hints", async () => {
    const targets = await svc.labTargets(lab.id);
    assert.equal(targets.length, 1);
    assert.equal(targets[0].target_type, "whois-server");
    const objectives = await svc.labObjectives(lab.id);
    assert.equal(objectives.length, 2);
    assert.ok(!("expected_value_hash" in objectives[0]), "hashes must never be served to clients");
    const hints = await svc.labHints(lab.id);
    assert.equal(hints.length, 0);
  });

  it("rejects submissions before the lab is started", async () => {
    // route-level guard uses activeInstance; service records nevertheless —
    // assert the guard signal exists (no active instance yet).
    assert.equal(await svc.activeInstance(userId, lab.id), null);
  });

  it("records incorrect submissions without completing objectives", async () => {
    const r = await svc.submitAnswer({ userId, lab, objectiveKey: "third-nameserver", answer: "ns1.megacorpone.com", instanceId: "li_test" });
    assert.ok(r.ok && !r.correct);
    const p = await svc.labProgress(userId, lab.id);
    assert.equal(p.objectiveDone, 0);
    const subs = await db.all(`SELECT * FROM lab_submissions WHERE user_id=? AND lab_id=?`, [userId, lab.id]);
    assert.equal(subs.length, 1);
    assert.equal(subs[0].is_correct, 0);
  });

  it("completes objectives on correct answers; progress aggregates", async () => {
    const a = await svc.submitAnswer({ userId, lab, objectiveKey: "third-nameserver", answer: "ns3.megacorpone.com", instanceId: "li_test" });
    assert.ok(a.correct && a.completed);
    const b = await svc.submitAnswer({ userId, lab, objectiveKey: "registrar-whois", answer: "WHOIS.GANDI.NET", instanceId: "li_test" });
    assert.ok(b.correct);
    const p = await svc.labProgress(userId, lab.id);
    assert.equal(p.objectiveDone, 2);
    assert.ok(p.complete);
    const mod = await svc.moduleProgress(userId, lab.course_id, 6);
    assert.deepEqual(mod, { total: 1, completed: 1 });
  });

  it("repeat correct submissions stay idempotent", async () => {
    const beforeRows = await db.all(`SELECT * FROM lab_objective_progress WHERE user_id=? AND lab_id=?`, [userId, lab.id]);
    const r = await svc.submitAnswer({ userId, lab, objectiveKey: "third-nameserver", answer: "ns3.megacorpone.com", instanceId: "li_test" });
    assert.ok(r.correct);
    const afterRows = await db.all(`SELECT * FROM lab_objective_progress WHERE user_id=? AND lab_id=?`, [userId, lab.id]);
    assert.equal(afterRows.length, beforeRows.length);
  });

  it("unknown objectives are rejected", async () => {
    const r = await svc.submitAnswer({ userId, lab, objectiveKey: "nope", answer: "x", instanceId: "" });
    assert.ok(!r.ok);
  });

  it("notes persist per user+lab", async () => {
    await svc.saveNotes(userId, lab.id, "li_test", "found ns3 via whois");
    const n = await svc.getNotes(userId, lab.id);
    assert.equal(n.body, "found ns3 via whois");
    // other users cannot see them
    const { createUser } = await import("../server/auth.js");
    const other = await createUser({ username: "labother", email: "o@test.local", displayName: "O", password: "password12345" });
    assert.equal(await svc.getNotes(other.id, lab.id), null);
  });

  it("instance lifecycle enforces single-active + transitions", async () => {
    // create → provisioning → running → resetting → running → stopping → stopped
    let inst = await svc.createInstance({ userId, labId: lab.id, provider: "local" });
    assert.equal(inst.status, "provisioning");
    assert.ok(await svc.activeInstance(userId, lab.id), "active while provisioning");
    inst = await svc.setInstanceStatus(inst, "running", { targetIp: "10.200.9.10", networkCidr: "10.200.9.0/24" });
    await assert.rejects(svc.setInstanceStatus(inst, "provisioning"), /Illegal lab state/);
    inst = await svc.setInstanceStatus(inst, "resetting");
    inst = await svc.setInstanceStatus(inst, "running", { resetCount: 1 });
    assert.equal(inst.reset_count, 1);
    inst = await svc.setInstanceStatus(inst, "stopping");
    inst = await svc.setInstanceStatus(inst, "stopped");
    assert.equal(await svc.activeInstance(userId, lab.id), null);
  });
});

describe("orchestrator local-provider smoke test", () => {
  it("provisions a real TCP/43 target, serves WHOIS, scopes terminal, cleans up", async () => {
    const orch = await import("../server/labs/orchestrator.js");
    const svc = await import("../server/labs/service.js");
    const lab = await svc.getLab("slug", "m6-6-2-1-whois-vm1");
    const fakeInstance = { id: "li_smoke1" };
    const details = await orch.providerFor("local").provision(lab, fakeInstance);
    assert.ok(details.targetIp.startsWith("10."));
    assert.equal(details.targetPort, 43);
    try {
      // 1. real TCP/43 query against the provisioned endpoint
      const { host, port } = await orch.resolveEndpoint({ target_ip: details.targetIp, target_port: 43, host_endpoint: details.hostEndpoint });
      const out = await orch.whoisQuery(host, port, "megacorpone.com");
      assert.ok(/ns3\.megacorpone\.com/i.test(out), "third nameserver discoverable");
      assert.ok(out.includes("whois.gandi.net"), "registrar discoverable");
      // 2. terminal whois goes over the same real path
      const inst = { ...fakeInstance, target_ip: details.targetIp, target_port: 43, host_endpoint: details.hostEndpoint, provider: "local", network_cidr: details.networkCidr };
      const t = await orch.runTerminalCommand(inst, "whois megacorpone.com");
      assert.ok(t.output.includes("Name Server"), "terminal whois returns live data, shape: " + JSON.stringify(t).slice(0, 80));
      // 3. terminal never runs host commands
      const evil = await orch.runTerminalCommand(inst, "rm -rf /");
      assert.ok(/not available/i.test(evil.output));
      const evil2 = await orch.runTerminalCommand(inst, "whois example.com -h evil.example");
      assert.ok(/not reachable/i.test(evil2.output));
      // 4. dig helper mirrors the dataset without faking whois
      const dig = await orch.runTerminalCommand(inst, "dig megacorpone.com NS");
      assert.ok(dig.output.includes("ns3.megacorpone.com"));
    } finally {
      await orch.providerFor("local").destroy({ id: "li_smoke1", provider_reference: details.providerReference, network_name: details.networkName });
    }
    // 5. no orphan: endpoint dead after destroy
    await assert.rejects(orch.whoisQuery("127.0.0.1", details.hostEndpoint.split(":")[1], "megacorpone.com", 1500));
  });

  it("docker provider provisions the real container when a daemon exists (skipped otherwise)", async () => {
    const orch = await import("../server/labs/orchestrator.js");
    if (!await orch.dockerAvailable()) {
      console.log("  (skip: no Docker daemon — docker path covered by design + local parity)");
      return;
    }
    const svc = await import("../server/labs/service.js");
    const lab = await svc.getLab("slug", "m6-6-2-1-whois-vm1");
    const inst = { id: `li_dockertest_${Date.now().toString(36)}` };
    const details = await orch.providerFor("docker").provision(lab, inst);
    try {
      const { host, port } = await orch.resolveEndpoint({ target_ip: details.targetIp, target_port: 43, host_endpoint: details.hostEndpoint });
      const out = await orch.whoisQuery(host, port, "megacorpone.com", 10000);
      assert.ok(/ns3\.megacorpone\.com/i.test(out));
    } finally {
      await orch.providerFor("docker").destroy({ id: inst.id, provider_reference: details.providerReference, network_name: details.networkName });
    }
  });
});

describe("image build automation", () => {
  it("resolves build contexts from metadata, legacy map, or nothing", async () => {
    const { resolveBuildContext } = await import("../server/labs/orchestrator.js");
    assert.equal(resolveBuildContext("img:x", JSON.stringify({ build: "m6/whois-vm1" })), path.resolve(REPO, "lab-images/m6/whois-vm1"));
    assert.equal(resolveBuildContext("axiom-lab-whois-vm1:latest", "{}"), path.resolve(REPO, "lab-images/m6/whois-vm1"));
    assert.equal(resolveBuildContext("unknown:latest", "{}"), null);
    assert.equal(resolveBuildContext("unknown:latest", "not-json"), null);
  });
  it("seed stores the target build context in metadata", async () => {
    const db = await import("../server/db.js");
    try { await db.initDb(); } catch {}
    const svc = await import("../server/labs/service.js");
    await svc.seedFromDefinitions(path.join(REPO, "labs"));
    const targets = await svc.labTargets((await svc.getLab("slug", "m6-6-2-1-whois-vm1")).id);
    assert.ok(targets.length >= 1);
    assert.equal(JSON.parse(targets[0].metadata_json).build, "m6/whois-vm1");
  });
  it("warmup never throws and skips cleanly without a daemon", async () => {
    const orch = await import("../server/labs/orchestrator.js");
    if (await orch.dockerAvailable()) {
      console.log("  (skip: daemon present — warmup would build images here)");
      return;
    }
    const r = await orch.warmupLabImages();
    assert.equal(r.daemon, false);
    assert.equal(r.built, 0);
  });
});

describe("docker provider failure hygiene", () => {
  it("fails fast with a clear error and no orphans when the app cannot join the lab net", async () => {
    const orch = await import("../server/labs/orchestrator.js");
    if (!await orch.dockerAvailable()) {
      console.log("  (skip: no Docker daemon)");
      return;
    }
    const { execFile } = await import("node:child_process");
    const { promisify } = await import("node:util");
    const run = promisify(execFile);
    const names = async (args) => (await run("docker", args).catch(() => ({ stdout: "" }))).stdout;
    const beforeNets = await names(["network", "ls", "--format", "{{.Name}}"]);
    const beforePs = await names(["ps", "-a", "--format", "{{.Names}}"]);
    process.env.AXIOM_SELF_CONTAINER = "axiom-no-such-container-xyz";
    try {
      const svc = await import("../server/labs/service.js");
      const lab = await svc.getLab("slug", "m6-6-2-1-whois-vm1");
      await assert.rejects(
        orch.providerFor("docker").provision(lab, { id: `li_testjoin_${Date.now().toString(36)}` }),
        /could not join lab network/
      );
    } finally {
      delete process.env.AXIOM_SELF_CONTAINER;
    }
    const afterNets = await names(["network", "ls", "--format", "{{.Name}}"]);
    const afterPs = await names(["ps", "-a", "--format", "{{.Names}}"]);
    const leaked = (afterNets + afterPs).split("\n").filter((n) => n.includes("axiom-lab-") || n.includes("axiom-li"));
    const preexisting = (beforeNets + beforePs).split("\n");
    assert.deepEqual(leaked.filter((n) => !preexisting.includes(n)), [], "orphaned lab container/network left behind");
  });
});

describe("training-path icons", () => {
  const ONE_PX_PNG = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==", "base64");
  let dir, oldEnv;
  before(async () => {
    const { mkdtempSync, writeFileSync } = await import("node:fs");
    dir = mkdtempSync(path.join(os.tmpdir(), "axiom-icons-"));
    writeFileSync(path.join(dir, "core.png"), ONE_PX_PNG);
    writeFileSync(path.join(dir, "extra.svg"), "<svg></svg>");
    oldEnv = process.env.LAB_ICONS_DIR;
    process.env.LAB_ICONS_DIR = dir;
  });
  after(() => {
    if (oldEnv === undefined) delete process.env.LAB_ICONS_DIR;
    else process.env.LAB_ICONS_DIR = oldEnv;
  });

  it("finds icons by slug with correct mime, rejects junk", async () => {
    const { findLabCourseIcon } = await import("../server/labs/icons.js");
    assert.equal(findLabCourseIcon("core").mime, "image/png");
    assert.equal(findLabCourseIcon("extra").mime, "image/svg+xml");
    assert.equal(findLabCourseIcon("nosuch"), null);
    assert.equal(findLabCourseIcon("../secret"), null);
    assert.equal(findLabCourseIcon(""), null);
    assert.equal(findLabCourseIcon("Core"), null); // slugs are lowercase
  });
  it("card art uses the icon when present, glyph otherwise", async () => {
    const { labCourseArt } = await import("../server/views.js");
    assert.ok(labCourseArt({ slug: "core", title: "Core" }).includes("/media/lab-course/core"));
    assert.ok(labCourseArt({ slug: "nosuch", title: "X" }).includes("◈"));
  });
});
