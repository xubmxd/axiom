import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

// Isolate: temp sqlite file + local provider before any server module loads.
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "axiom-labs-oss-"));
process.env.DATA_DIR = TMP;
process.env.LAB_PROVIDER = "local";

const REPO = path.resolve(import.meta.dirname, "..");
const SLUG = "m6-6-2-4-open-source-code";
const DEF = path.join(REPO, "labs/module-06/6.2.4-open-source-code/lab.json");

const USERNAME = "trivera";
const PLACEHOLDER = "git-test";

const ORG_URL = "https://github.com/megacorpone";
const REPO_URL = "https://github.com/megacorpone/megacorpone.com";

function readDef() {
  return JSON.parse(fs.readFileSync(DEF, "utf8"));
}

describe("open-source-code definition", () => {
  it("loads as its own exercise under Module 6 (sections stay distinct)", async () => {
    const { loadAllDefinitions, validateDefinition, normalizePlacement } = await import("../server/labs/definitions.js");
    const all = loadAllDefinitions(path.join(REPO, "labs"));
    const lab = all.find((l) => l.def.slug === SLUG);
    assert.ok(lab, "6.2.4 lab.json must be discovered");
    assert.deepEqual(validateDefinition(lab.def), []);
    const p = normalizePlacement(lab.def);
    assert.equal(p.courseSlug, "oscp");
    assert.equal(p.moduleNumber, 6);
    assert.equal(p.moduleTitle, "Information Gathering");
    assert.equal(p.section, "6.2.4");
    assert.equal(p.sectionTitle, "Open-Source Code");
    assert.equal(lab.def.labNumber, 1);
    assert.equal(lab.def.title, "6.2.4 Open-Source Code");
    const sections = new Set(all.filter((l) => normalizePlacement(l.def).moduleNumber === 6).map((l) => normalizePlacement(l.def).section));
    assert.deepEqual([...sections].sort(), ["6.2.1", "6.2.2", "6.2.3", "6.2.4", "6.3.1", "6.3.2", "6.3.3", "6.3.4", "6.3.5", "6.3.6"]);
  });

  it("is an external-research OSINT lab with no Docker/VM target", async () => {
    const def = readDef();
    assert.equal(def.environment.type, "osint");
    assert.equal(def.environment.provider, "external-research");
    assert.ok(def.targets.length >= 1, "definitions require at least one target entry");
    assert.ok(def.targets.every((t) => t.type === "external-research"), "no VM-backed target types");
    assert.ok(def.targets.every((t) => !(t.ports || []).length), "no service ports on a research lab");
    assert.ok(!JSON.stringify(def.targets).match(/whois-server|docker|10\.\d+\.\d+\./), "no container or fake-IP wiring");
  });

  it("keeps exactly the two source objectives with hashed answers", async () => {
    const def = readDef();
    assert.equal(def.objectives.length, 2);
    assert.deepEqual(def.objectives.map((o) => o.key), ["credential-username", "placeholder-repository"]);
    for (const o of def.objectives) assert.match(o.expectedHash, /^[0-9a-f]{64}$/);
    const joined = JSON.stringify(def.objectives);
    assert.ok(joined.includes("username associated with") && joined.includes("discovered hash"), "Q1 substance preserved");
    assert.ok(joined.includes("secondary") && joined.includes("placeholder"), "Q2 substance preserved");
  });

  it("leaks no answers through the definition, hints, instructions, or research content", async () => {
    const def = readDef();
    const raw = fs.readFileSync(DEF, "utf8");
    assert.ok(!raw.includes(USERNAME), "username must not appear in plaintext");
    assert.ok(!raw.includes(PLACEHOLDER), "placeholder repo must not appear in plaintext");
    assert.ok(!/xampp/i.test(raw), "credential filename must not appear");
    assert.ok(!/\$apr1\$|\$2[aby]\$|\$6\$/.test(raw), "no hash material in the definition");
    assert.ok(!JSON.stringify(def.instructions).includes(PLACEHOLDER));
  });

  it("carries six progressive technique hints that do not reveal answers", async () => {
    const def = readDef();
    assert.equal(def.hints.length, 6);
    const joined = JSON.stringify(def.hints);
    assert.ok(!joined.includes(USERNAME) && !joined.includes(PLACEHOLDER) && !/xampp/i.test(joined));
    assert.ok(/github/i.test(joined), "hints point at the GitHub workflow");
    assert.ok(/organization/i.test(joined), "hints distinguish the org-level objective");
  });

  it("links org + main repo only (never the answer-bearing file or repo)", async () => {
    const def = readDef();
    assert.ok(def.research && Array.isArray(def.research.links));
    const urls = def.research.links.map((l) => l.url);
    assert.ok(urls.includes(ORG_URL), "organization link present");
    assert.ok(urls.includes(REPO_URL), "main repository link present");
    assert.ok(urls.every((u) => u.startsWith("https://")), "external links are https only");
    assert.ok(!urls.some((u) => /xampp|git-test/i.test(u)), "no direct link to answer-bearing evidence");
    assert.ok(!/xampp|git-test/i.test(JSON.stringify(def.research)), "research copy names no evidence");
  });
});

describe("open-source-code service (sqlite)", () => {
  let svc, db, userId, lab;
  before(async () => {
    db = await import("../server/db.js");
    await db.initDb();
    svc = await import("../server/labs/service.js");
    const { createUser } = await import("../server/auth.js");
    const u = await createUser({ username: "osstester", email: "oss@test.local", displayName: "OSS", password: "password12345" });
    userId = u.id;
    await svc.seedFromDefinitions(path.join(REPO, "labs"));
    lab = await svc.getLab("slug", SLUG);
    assert.ok(lab);
    assert.equal(lab.environment_type, "osint");
  });

  it("seeds the research target + two hash-only objectives + hints", async () => {
    const targets = await svc.labTargets(lab.id);
    assert.equal(targets.length, 1);
    assert.equal(targets[0].target_type, "external-research");
    const objectives = await svc.labObjectives(lab.id);
    assert.equal(objectives.length, 2);
    assert.ok(!("expected_value_hash" in objectives[0]), "hashes must never be served to clients");
    assert.equal((await svc.labHints(lab.id)).length, 6);
  });

  it("rejects hashes, wrong names, emails, blanks, and partial answers", async () => {
    const wrong = [
      ["credential-username", "$apr1$A0vSKwao$GV3sgGAj53j.c3GkS4oUC0"],
      ["credential-username", "trivera:$apr1$A0vSKwao$GV3sgGAj53j.c3GkS4oUC0"],
      ["credential-username", "tanya"], ["credential-username", "joe@megacorpone.com"],
      ["credential-username", "triver"], ["credential-username", ""],
      ["credential-username", "   "],
      ["placeholder-repository", "megacorpone.com"], ["placeholder-repository", "MegaCorp One"],
      ["placeholder-repository", "git"], ["placeholder-repository", "test"],
      ["placeholder-repository", "megacorpone"], ["placeholder-repository", ""],
      ["placeholder-repository", "   "],
    ];
    for (const [key, ans] of wrong) {
      const r = await svc.submitAnswer({ userId, lab, objectiveKey: key, answer: ans, instanceId: "li_oss" });
      assert.ok(r.ok && !r.correct, `${key}=${JSON.stringify(ans).slice(0, 40)} must fail`);
    }
    const p = await svc.labProgress(userId, lab.id);
    assert.equal(p.objectiveDone, 0);
  });

  it("accepts the documented answers with harmless formatting variants", async () => {
    const a = await svc.submitAnswer({ userId, lab, objectiveKey: "credential-username", answer: "TRIVERA", instanceId: "li_oss" });
    assert.ok(a.correct && a.completed);
    const a2 = await svc.submitAnswer({ userId, lab, objectiveKey: "credential-username", answer: " trivera ", instanceId: "li_oss" });
    assert.ok(a2.correct, "case/whitespace variants normalize");
    const b = await svc.submitAnswer({ userId, lab, objectiveKey: "placeholder-repository", answer: "GIT-TEST", instanceId: "li_oss" });
    assert.ok(b.correct);
    const b2 = await svc.submitAnswer({ userId, lab, objectiveKey: "placeholder-repository", answer: " git-test ", instanceId: "li_oss" });
    assert.ok(b2.correct);
    const p = await svc.labProgress(userId, lab.id);
    assert.equal(p.objectiveDone, 2);
    assert.ok(p.complete);
    const again = await svc.labProgress(userId, lab.id);
    assert.ok(again.complete && again.objectiveDone === 2, "progress must persist");
  });

  it("public lab reads never expose expected answers", async () => {
    for (const row of await svc.labTargets(lab.id)) {
      assert.ok(!JSON.stringify(row).includes(USERNAME) && !JSON.stringify(row).includes(PLACEHOLDER));
    }
    for (const row of await svc.labObjectives(lab.id)) {
      assert.ok(!JSON.stringify(row).includes(USERNAME) && !JSON.stringify(row).includes(PLACEHOLDER));
    }
    const labRow = await svc.getLab("slug", SLUG);
    assert.ok(!JSON.stringify(labRow).includes(USERNAME) && !JSON.stringify(labRow).includes(PLACEHOLDER));
    assert.ok(!JSON.stringify(await svc.labProgress(userId, lab.id)).includes(USERNAME));
    assert.ok(!JSON.stringify(await svc.hintsFor(userId, lab.id)).includes(USERNAME));
  });

  it("existing labs keep their sections and answers (regression)", async () => {
    for (const slug of ["m6-6-2-1-whois-vm1", "m6-6-2-1-whois-vm2", "m6-6-2-1-whois-vm3", "m6-6-2-2-google-hacking", "m6-6-2-3-netcraft"]) {
      assert.ok(await svc.getLab("slug", slug), `${slug} still registered`);
    }
    assert.equal(lab.section_number, "6.2.4", "Open-Source Code stays separate");
    const { verifyAnswer } = await import("../server/labs/answers.js");
    const def = JSON.parse(fs.readFileSync(path.join(REPO, "labs/module-06/6.2.1-whois/vm-01/lab.json"), "utf8"));
    const byKey = Object.fromEntries(def.objectives.map((o) => [o.key, o]));
    assert.ok(verifyAnswer("ns3.megacorpone.com", byKey["third-nameserver"].expectedHash, "case-insensitive-exact"));
    const r = await svc.submitAnswer({ userId, lab: await svc.getLab("slug", "m6-6-2-1-whois-vm1"), objectiveKey: "third-nameserver", answer: "ns3.megacorpone.com", instanceId: "li_x" });
    assert.ok(r.correct);
  });
});

describe("open-source-code routes (http)", () => {
  const PORT = 3461;
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
      user = await createUser({ username: "osshttp", email: "ossh@test.local", displayName: "OSSH", password: "password12345" });
    } catch {
      user = await db.get(`SELECT * FROM users WHERE username=?`, ["osshttp"]);
    }
    const r = await fetch(`${BASE}/login`, {
      method: "POST", redirect: "manual",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ identifier: "osshttp", password: "password12345" }),
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

  it("workspace shows org/repo links, no evidence links, no answers, no iframe", async () => {
    const r = await get(`/labs/oscp/${SLUG}`);
    assert.equal(r.status, 200);
    const html = await r.text();
    assert.ok(html.includes("External Research"), "research workspace must render");
    assert.ok(html.includes("6.2.4"), "section breadcrumb must render");
    assert.ok(html.includes(ORG_URL), "organization link present");
    assert.ok(html.includes(REPO_URL), "main repository link present");
    assert.ok(html.includes('target="_blank"'), "research links open in new tabs");
    assert.ok(!html.includes("<iframe"), "third-party sites are never embedded");
    assert.ok(!html.includes("10.210.") && !html.includes("10.200."), "no fake lab-network IPs");
    assert.ok(!html.includes(USERNAME), "workspace HTML must not leak the username");
    assert.ok(!html.includes(PLACEHOLDER), "workspace HTML must not leak the placeholder repo");
    assert.ok(!/xampp/i.test(html), "workspace HTML must not name the evidence file");
  });

  it("6.2.3 workspace is untouched (still Netcraft, no GitHub-org links)", async () => {
    const r = await get(`/labs/oscp/m6-6-2-3-netcraft`);
    assert.equal(r.status, 200);
    const html = await r.text();
    assert.ok(html.includes("sitereport.netcraft.com"), "Netcraft keeps its report link");
    assert.ok(!html.includes("github.com/megacorpone\""), "no org-link leakage into 6.2.3");
  });

  it("hints API loads and reveals without leaking answers", async () => {
    const hints = (await (await get(`/api/labs/${labId}/hints`)).json()).hints;
    assert.equal(hints.length, 6);
    assert.ok(hints.every((h) => !h.revealed));
    const r = await post(`/api/labs/${labId}/hints/${hints[0].id}/reveal`, null);
    const body = await r.json();
    assert.ok(body.ok && body.hint.body);
    assert.ok(!body.hint.body.includes(USERNAME) && !body.hint.body.includes(PLACEHOLDER));
    const after = (await (await get(`/api/labs/${labId}/hints`)).json()).hints;
    assert.equal(after.filter((h) => h.revealed).length, 1, "reveal persists for that hint only");
  });

  it("full flow: activate (no VM) → submit → progress persists", async () => {
    let r = await post(`/api/labs/${labId}/start`);
    assert.equal(r.status, 200);
    const started = await r.json();
    assert.equal(started.instance.status, "running");
    assert.equal(started.instance.provider, "external-research");
    assert.ok(!started.instance.targetIp, "no target IP on a research session");
    r = await post(`/api/labs/${labId}/submit`, { answers: { "credential-username": "joe" } });
    assert.equal((await r.json()).results["credential-username"].correct, false);
    r = await post(`/api/labs/${labId}/submit`, {
      answers: { "credential-username": USERNAME, "placeholder-repository": PLACEHOLDER },
    });
    const done = await r.json();
    assert.ok(done.results["credential-username"].correct);
    assert.ok(done.results["placeholder-repository"].correct);
    assert.ok(done.progress.complete);
    const st = await (await get(`/api/labs/${labId}/status`)).json();
    assert.ok(st.progress.complete);
    r = await post(`/api/labs/${labId}/stop`);
    assert.equal((await r.json()).instance.status, "stopped");
    const st2 = await (await get(`/api/labs/${labId}/status`)).json();
    assert.ok(st2.progress.complete, "completion survives stop");
  }, { timeout: 60000 });
});
