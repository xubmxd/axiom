import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

// Isolate: temp sqlite file + local provider before any server module loads.
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "axiom-labs-osint-"));
process.env.DATA_DIR = TMP;
process.env.LAB_PROVIDER = "local";

const REPO = path.resolve(import.meta.dirname, "..");
const SLUG = "m6-6-2-2-google-hacking";
const DEF = path.join(REPO, "labs/module-06/6.2.2-google-hacking/lab.json");

const VP_NAME = "Mike Carlow";
const VP_EMAIL = "mcarlow@megacorpone.com";
const EXTRA = "William Adler";

const GOOGLE_URL = "https://www.google.com";
const SITE_URL = "https://www.megacorpone.com";
const MIRROR_URL = "https://github.com/megacorpone/megacorpone.com";

function readDef() {
  return JSON.parse(fs.readFileSync(DEF, "utf8"));
}

describe("google-hacking definition", () => {
  it("loads as its own exercise under Module 6 (not inside 6.2.1)", async () => {
    const { loadAllDefinitions, validateDefinition, normalizePlacement } = await import("../server/labs/definitions.js");
    const all = loadAllDefinitions(path.join(REPO, "labs"));
    const lab = all.find((l) => l.def.slug === SLUG);
    assert.ok(lab, "6.2.2 lab.json must be discovered");
    assert.deepEqual(validateDefinition(lab.def), []);
    const p = normalizePlacement(lab.def);
    assert.equal(p.courseSlug, "oscp");
    assert.equal(p.moduleNumber, 6);
    assert.equal(p.moduleTitle, "Information Gathering");
    assert.equal(p.section, "6.2.2");
    assert.equal(p.sectionTitle, "Google Hacking");
    assert.equal(lab.def.labNumber, 1);
    assert.equal(lab.def.title, "6.2.2 Google Hacking");
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

  it("has three hashed objectives and leaks no answers", async () => {
    const def = readDef();
    assert.equal(def.objectives.length, 3);
    assert.deepEqual(def.objectives.map((o) => o.key), ["vp-legal-name", "vp-legal-email", "additional-employee"]);
    for (const o of def.objectives) assert.match(o.expectedHash, /^[0-9a-f]{64}$/);
    const raw = fs.readFileSync(DEF, "utf8");
    assert.ok(!raw.includes(VP_NAME), "VP name must not appear in plaintext");
    assert.ok(!raw.includes(VP_EMAIL), "VP email must not appear in plaintext");
    assert.ok(!raw.includes(EXTRA), "extra employee must not appear in plaintext");
    assert.ok(!JSON.stringify(def.instructions).includes(VP_NAME));
  });

  it("carries progressive technique hints that do not reveal answers", async () => {
    const def = readDef();
    assert.ok(def.hints.length >= 4, "progressive guidance for all three questions");
    const joined = JSON.stringify(def.hints);
    assert.ok(!joined.includes(VP_NAME) && !joined.includes(VP_EMAIL) && !joined.includes(EXTRA));
    assert.ok(/site:/.test(joined), "hints point at domain restriction");
    assert.ok(/social/i.test(joined), "hints point at social-media reconnaissance");
  });

  it("ships no fabricated corpus and no local search implementation", async () => {
    assert.ok(!fs.existsSync(path.join(REPO, "server/labs/osint-corpus.js")), "fake corpus must be gone");
    assert.ok(!fs.existsSync(path.join(REPO, "server/labs/osint-search.js")), "fake search engine must be gone");
    for (const f of ["server/routes-labs.js", "server/labs/orchestrator.js", "public/js/lab.js"]) {
      const src = fs.readFileSync(path.join(REPO, f), "utf8");
      assert.ok(!src.includes("osint-search") && !src.includes("osint-corpus"), `${f} must not reference the removed modules`);
    }
  });
});

describe("osint service (sqlite)", () => {
  let svc, db, userId, lab;
  before(async () => {
    db = await import("../server/db.js");
    await db.initDb();
    svc = await import("../server/labs/service.js");
    const { createUser } = await import("../server/auth.js");
    const u = await createUser({ username: "osinttester", email: "osint@test.local", displayName: "OSINT", password: "password12345" });
    userId = u.id;
    await svc.seedFromDefinitions(path.join(REPO, "labs"));
    lab = await svc.getLab("slug", SLUG);
    assert.ok(lab);
    assert.equal(lab.environment_type, "osint");
  });

  it("seeds the research target + three hash-only objectives + hints", async () => {
    const targets = await svc.labTargets(lab.id);
    assert.equal(targets.length, 1);
    assert.equal(targets[0].target_type, "external-research");
    const objectives = await svc.labObjectives(lab.id);
    assert.equal(objectives.length, 3);
    assert.ok(!("expected_value_hash" in objectives[0]), "hashes must never be served to clients");
    const hints = await svc.labHints(lab.id);
    assert.ok(hints.length >= 4);
  });

  it("wrong submissions fail without revealing answers", async () => {
    for (const [key, bad] of [["vp-legal-name", "John Smith"], ["vp-legal-email", "legal@megacorpone.com"], ["additional-employee", "Jane Doe"]]) {
      const r = await svc.submitAnswer({ userId, lab, objectiveKey: key, answer: bad, instanceId: "li_osint" });
      assert.ok(r.ok && !r.correct, `${key} must reject wrong answers`);
      assert.ok(!JSON.stringify(r).includes(VP_NAME) && !JSON.stringify(r).includes(VP_EMAIL) && !JSON.stringify(r).includes(EXTRA));
    }
    const p = await svc.labProgress(userId, lab.id);
    assert.equal(p.objectiveDone, 0);
  });

  it("correct submissions succeed with normalization; progress persists", async () => {
    const a = await svc.submitAnswer({ userId, lab, objectiveKey: "vp-legal-name", answer: "  mike CARLOW ", instanceId: "li_osint" });
    assert.ok(a.correct && a.completed);
    const b = await svc.submitAnswer({ userId, lab, objectiveKey: "vp-legal-email", answer: "MCARLOW@MEGACORPONE.COM", instanceId: "li_osint" });
    assert.ok(b.correct);
    const c = await svc.submitAnswer({ userId, lab, objectiveKey: "additional-employee", answer: "william adler", instanceId: "li_osint" });
    assert.ok(c.correct);
    const p = await svc.labProgress(userId, lab.id);
    assert.equal(p.objectiveDone, 3);
    assert.ok(p.complete);
    // refresh-equivalent: fresh read of the same rows
    const again = await svc.labProgress(userId, lab.id);
    assert.ok(again.complete && again.objectiveDone === 3, "progress must persist");
  });

  it("public lab reads never expose expected answers", async () => {
    for (const row of await svc.labTargets(lab.id)) {
      assert.ok(!JSON.stringify(row).includes(VP_EMAIL));
    }
    for (const row of await svc.labObjectives(lab.id)) {
      assert.ok(!JSON.stringify(row).toLowerCase().includes("mcarlow"));
    }
    const labRow = await svc.getLab("slug", SLUG);
    assert.ok(!JSON.stringify(labRow).includes(VP_EMAIL));
    assert.ok(!JSON.stringify(await svc.labProgress(userId, lab.id)).includes(VP_EMAIL));
    assert.ok(!JSON.stringify(await svc.hintsFor(userId, lab.id)).toLowerCase().includes("mcarlow"));
  });

  it("hints reveal progressively and notes persist", async () => {
    const hints = await svc.hintsFor(userId, lab.id);
    assert.ok(hints.length >= 4);
    assert.ok(hints.every((h) => !h.revealed && h.body === null), "hints stay hidden until revealed");
    const first = await svc.revealHint(userId, lab.id, hints[0].id);
    assert.ok(first?.body, "revealed hint returns its body");
    assert.ok(!(first.body.includes(VP_NAME) || first.body.includes(VP_EMAIL) || first.body.includes(EXTRA)));
    await svc.saveNotes(userId, lab.id, "li_osint", "dork: site:megacorpone.com");
    assert.equal((await svc.getNotes(userId, lab.id)).body, "dork: site:megacorpone.com");
  });

  it("external-research provider provisions a logical session with no network footprint", async () => {
    const orch = await import("../server/labs/orchestrator.js");
    const details = await orch.providerFor("external-research").provision(lab, { id: "li_osint1" });
    assert.equal(details.targetIp, "");
    assert.equal(details.targetPort, 0);
    assert.equal(details.hostEndpoint, "");
    await orch.providerFor("external-research").destroy({ id: "li_osint1" }); // no-op, must not throw
  });

  it("osint terminal stays browser-scoped with no network tooling", async () => {
    const orch = await import("../server/labs/orchestrator.js");
    const osintLab = { slug: SLUG, environment_type: "osint" };
    const help = await orch.runTerminalCommand({}, "help", osintLab);
    assert.ok(/browser/i.test(help.output), "terminal directs research to the browser");
    const evil = await orch.runTerminalCommand({}, "rm -rf /", osintLab);
    assert.ok(/not available/i.test(evil.output));
    const whois = await orch.runTerminalCommand({}, "whois megacorpone.com", osintLab);
    assert.ok(/not available/i.test(whois.output), "no network tooling in the OSINT terminal");
  });

  it("existing WHOIS labs keep their placement and answers (regression)", async () => {
    const vm1 = await svc.getLab("slug", "m6-6-2-1-whois-vm1");
    const vm2 = await svc.getLab("slug", "m6-6-2-1-whois-vm2");
    const vm3 = await svc.getLab("slug", "m6-6-2-1-whois-vm3");
    assert.ok(vm1 && vm2 && vm3);
    assert.equal(vm1.section_number, "6.2.1");
    assert.equal(lab.section_number, "6.2.2", "Google Hacking stays separate from Whois Enumeration");
    const { verifyAnswer } = await import("../server/labs/answers.js");
    const def = JSON.parse(fs.readFileSync(path.join(REPO, "labs/module-06/6.2.1-whois/vm-01/lab.json"), "utf8"));
    const byKey = Object.fromEntries(def.objectives.map((o) => [o.key, o]));
    assert.ok(verifyAnswer("ns3.megacorpone.com", byKey["third-nameserver"].expectedHash, "case-insensitive-exact"));
    assert.ok(verifyAnswer("whois.gandi.net", byKey["registrar-whois"].expectedHash, "case-insensitive-exact"));
    const r = await svc.submitAnswer({ userId, lab: vm1, objectiveKey: "third-nameserver", answer: "ns3.megacorpone.com", instanceId: "li_x" });
    assert.ok(r.correct);
  });
});

describe("osint routes (http)", () => {
  const PORT = 3459;
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
      user = await createUser({ username: "osinthttp", email: "oh@test.local", displayName: "OH", password: "password12345" });
    } catch {
      user = await db.get(`SELECT * FROM users WHERE username=?`, ["osinthttp"]);
    }
    const r = await fetch(`${BASE}/login`, {
      method: "POST", redirect: "manual",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ identifier: "osinthttp", password: "password12345" }),
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

  it("workspace shows Research (not Search) with external links and no answers", async () => {
    const r = await get(`/labs/oscp/${SLUG}`);
    assert.equal(r.status, 200);
    const html = await r.text();
    assert.ok(html.includes("External Research"), "research workspace must render");
    assert.ok(html.includes("6.2.2"), "section breadcrumb must render");
    for (const url of [GOOGLE_URL, SITE_URL, MIRROR_URL]) {
      assert.ok(html.includes(url), `research link missing: ${url}`);
    }
    assert.ok(html.includes('target="_blank"'), "research links open in new tabs");
    assert.ok(!html.includes("osintSearchForm"), "fake in-app search must be gone");
    assert.ok(!html.includes("10.210.") && !html.includes("10.200."), "no fake lab-network IPs");
    assert.ok(!html.includes(VP_EMAIL), "workspace HTML must not leak the email");
    assert.ok(!html.includes(EXTRA), "workspace HTML must not leak the extra employee");
  });

  it("old local-search API is gone", async () => {
    assert.equal((await get(`/api/labs/${labId}/osint/search?q=x`)).status, 404);
    assert.equal((await get(`/api/labs/${labId}/osint/doc/press-counsel`)).status, 404);
  });

  it("hints API loads and reveals without leaking answers", async () => {
    const hints = (await (await get(`/api/labs/${labId}/hints`)).json()).hints;
    assert.ok(hints.length >= 4);
    assert.ok(hints.every((h) => !h.revealed));
    const r = await post(`/api/labs/${labId}/hints/${hints[0].id}/reveal`, null);
    const body = await r.json();
    assert.ok(body.ok && body.hint.body);
    assert.ok(!body.hint.body.includes(VP_NAME) && !body.hint.body.includes(VP_EMAIL));
  });

  it("full flow: activate (no VM) → submit → progress persists", async () => {
    let r = await post(`/api/labs/${labId}/start`);
    assert.equal(r.status, 200);
    const started = await r.json();
    assert.equal(started.instance.status, "running");
    assert.equal(started.instance.provider, "external-research");
    assert.ok(!started.instance.targetIp, "no target IP on a research session");
    // wrong answers fail
    r = await post(`/api/labs/${labId}/submit`, { answers: { "vp-legal-name": "Nobody Here" } });
    assert.equal(r.status, 200);
    assert.equal((await r.json()).results["vp-legal-name"].correct, false);
    // correct answers complete the exercise
    r = await post(`/api/labs/${labId}/submit`, {
      answers: { "vp-legal-name": VP_NAME, "vp-legal-email": VP_EMAIL, "additional-employee": EXTRA },
    });
    const done = await r.json();
    assert.ok(done.results["vp-legal-name"].correct);
    assert.ok(done.results["vp-legal-email"].correct);
    assert.ok(done.results["additional-employee"].correct);
    assert.ok(done.progress.complete);
    // progress persists across reads (refresh-equivalent)
    const st = await (await get(`/api/labs/${labId}/status`)).json();
    assert.ok(st.progress.complete);
    // stop cleans up the logical session
    r = await post(`/api/labs/${labId}/stop`);
    assert.equal((await r.json()).instance.status, "stopped");
    const st2 = await (await get(`/api/labs/${labId}/status`)).json();
    assert.ok(st2.progress.complete, "completion survives stop");
  }, { timeout: 60000 });
});
