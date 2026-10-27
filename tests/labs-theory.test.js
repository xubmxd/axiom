import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

// Isolate: temp sqlite file before any server module loads. Theory labs
// need no provider infrastructure (no containers, no sandbox).
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "axiom-labs-theory-"));
process.env.DATA_DIR = TMP;
process.env.LAB_PROVIDER = "local";

const REPO = path.resolve(import.meta.dirname, "..");

const LABS = [
  {
    section: "7.1.1",
    slug: "m7-7-1-1-scanner-findings",
    title: "7.1.1 How Vulnerability Scanners Work",
    sectionTitle: "How Vulnerability Scanners Work",
    file: "labs/module-07/7.1.1-scanner-findings/lab.json",
    answers: { "question-1": "false positive", "question-2": "false negative" },
    wrong: { "question-1": "false negative", "question-2": "false positive" },
    hintMustLack: ["false positive", "false negative"],
  },
  {
    section: "7.1.2",
    slug: "m7-7-1-2-scan-types",
    title: "7.1.2 Types of Vulnerability Scans",
    sectionTitle: "Types of Vulnerability Scans",
    file: "labs/module-07/7.1.2-scan-types/lab.json",
    answers: { "question-1": "authenticated", "question-2": "unauthenticated" },
    wrong: { "question-1": "unauthenticated", "question-2": "authenticated" },
    hintMustLack: ["authenticated", "unauthenticated"],
  },
  {
    section: "7.1.3",
    slug: "m7-7-1-3-scan-impact",
    title: "7.1.3 Things to Consider in a Vulnerability Scan",
    sectionTitle: "Things to Consider in a Vulnerability Scan",
    file: "labs/module-07/7.1.3-scan-impact/lab.json",
    answers: { "question-1": "false", "question-2": "true" },
    wrong: { "question-1": "true", "question-2": "false" },
    hintMustLack: ["true", "false"],
  },
];

function readDef(entry) {
  return JSON.parse(fs.readFileSync(path.join(REPO, entry.file), "utf8"));
}

describe("theory definitions", () => {
  it("all three labs load as Module 7 theory exercises", async () => {
    const { loadAllDefinitions, validateDefinition, normalizePlacement } = await import("../server/labs/definitions.js");
    const all = loadAllDefinitions(path.join(REPO, "labs"));
    for (const entry of LABS) {
      const lab = all.find((l) => l.def.slug === entry.slug);
      assert.ok(lab, `${entry.slug} must be discovered`);
      assert.deepEqual(validateDefinition(lab.def), [], `${entry.slug} must validate`);
      const p = normalizePlacement(lab.def);
      assert.equal(p.courseSlug, "oscp");
      assert.equal(p.moduleNumber, 7);
      assert.equal(p.section, entry.section);
      assert.equal(p.sectionTitle, entry.sectionTitle);
      assert.equal(lab.def.title, entry.title);
      assert.equal(lab.def.labNumber, 1);
    }
    const sections = new Set(all.filter((l) => normalizePlacement(l.def).moduleNumber === 7).map((l) => normalizePlacement(l.def).section));
    assert.deepEqual([...sections].sort(), ["7.1.1", "7.1.2", "7.1.3", "7.2.1", "7.2.2", "7.2.3", "7.2.4", "7.2.5", "7.2.6"]);
  });

  for (const entry of LABS) {
    it(`${entry.section} declares two objectives and no infrastructure`, () => {
      const def = readDef(entry);
      assert.equal(def.environment.type, "theory");
      assert.equal(def.objectives.length, 2);
      assert.deepEqual(def.objectives.map((o) => o.key), ["question-1", "question-2"]);
      for (const o of def.objectives) {
        assert.equal(o.validation, "case-insensitive-exact");
        assert.match(o.expectedHash, /^[0-9a-f]{64}$/);
      }
      // Exactly one declared target, and it is not a machine.
      assert.equal(def.targets.length, 1);
      assert.ok(!/attacker|nmap|smb|smtp|snmp|scan|dns|whois|vm/i.test(JSON.stringify(def.targets)), "no fake infrastructure target");
      assert.ok(def.hints.length >= 2, "methodology hints present");
      assert.deepEqual(def.instructions.commands || [], [], "no commands for a theory lab");
    });

    it(`${entry.section} hashes match the source answers`, async () => {
      const { verifyAnswer } = await import("../server/labs/answers.js");
      const def = readDef(entry);
      const byKey = Object.fromEntries(def.objectives.map((o) => [o.key, o]));
      for (const [key, ans] of Object.entries(entry.answers)) {
        assert.ok(verifyAnswer(ans, byKey[key].expectedHash, "case-insensitive-exact"), `${key} accepts the source answer`);
        assert.ok(verifyAnswer(`  ${ans.toUpperCase()}  `, byKey[key].expectedHash, "case-insensitive-exact"), `${key} normalizes case/whitespace`);
      }
      for (const [key, ans] of Object.entries(entry.wrong)) {
        assert.ok(!verifyAnswer(ans, byKey[key].expectedHash, "case-insensitive-exact"), `${key} rejects the swapped answer`);
      }
      assert.ok(!verifyAnswer("", byKey["question-1"].expectedHash, "case-insensitive-exact"), "blank rejected");
      assert.ok(!verifyAnswer("nonsense answer here", byKey["question-2"].expectedHash, "case-insensitive-exact"), "unrelated text rejected");
    });

    it(`${entry.section} hints never state the answers (framing lives in the objectives)`, () => {
      const def = readDef(entry);
      const hints = JSON.stringify(def.hints).toLowerCase();
      for (const term of entry.hintMustLack) {
        assert.ok(!hints.includes(term), `hints must not state ${JSON.stringify(term)}`);
      }
      // The objectives themselves carry the source questions (necessary
      // question text); the mapping to the correct choice is hash-only.
      const objectives = JSON.stringify(def.objectives.map((o) => o.description));
      assert.ok(objectives.length > 0);
    });
  }
});

describe("theory service (sqlite)", () => {
  let svc, db, userId;
  const labs = {};
  before(async () => {
    db = await import("../server/db.js");
    await db.initDb();
    svc = await import("../server/labs/service.js");
    const { createUser } = await import("../server/auth.js");
    const u = await createUser({ username: "theorytester", email: "theory@test.local", displayName: "THEORY", password: "password12345" });
    userId = u.id;
    await svc.seedFromDefinitions(path.join(REPO, "labs"));
    for (const entry of LABS) {
      const lab = await svc.getLab("slug", entry.slug);
      assert.ok(lab, entry.slug);
      labs[entry.slug] = lab;
    }
  });

  for (const entry of LABS) {
    it(`${entry.section} validates answers server-side with hash-only objectives`, async () => {
      const lab = labs[entry.slug];
      const objectives = await svc.labObjectives(lab.id);
      assert.equal(objectives.length, 2);
      assert.ok(!("expected_value_hash" in objectives[0]), "hashes must never be served to clients");
      const tmp = await svc.createInstance({ userId, labId: lab.id, provider: "external-research" });
      await svc.setInstanceStatus(tmp, "running", { providerReference: `external-research:${tmp.id}` });
      // Swapped answers are both wrong; each objective completes independently.
      const w1 = await svc.submitAnswer({ userId, lab, objectiveKey: "question-1", answer: entry.wrong["question-1"], instanceId: tmp.id });
      assert.ok(w1.ok && !w1.correct);
      const c1 = await svc.submitAnswer({ userId, lab, objectiveKey: "question-1", answer: entry.answers["question-1"], instanceId: tmp.id });
      assert.ok(c1.correct && c1.completed);
      let p = await svc.labProgress(userId, lab.id);
      assert.equal(p.objectiveDone, 1, "one correct answer must not complete the second objective");
      assert.ok(!p.complete);
      const c2 = await svc.submitAnswer({ userId, lab, objectiveKey: "question-2", answer: entry.answers["question-2"], instanceId: tmp.id });
      assert.ok(c2.correct);
      p = await svc.labProgress(userId, lab.id);
      assert.ok(p.complete, "2/2 completes the lab");
      assert.equal(p.objectiveDone, 2);
      // Repeat submissions stay completed without duplicating completion.
      const again = await svc.submitAnswer({ userId, lab, objectiveKey: "question-1", answer: entry.answers["question-1"], instanceId: tmp.id });
      assert.ok(again.correct && again.completed);
    });

    it(`${entry.section} notes and hint views persist`, async () => {
      const lab = labs[entry.slug];
      await svc.saveNotes(userId, lab.id, "", "my reasoning notes");
      assert.equal((await svc.getNotes(userId, lab.id)).body, "my reasoning notes");
      const before = await svc.hintsFor(userId, lab.id);
      assert.ok(before.length >= 2 && before.every((h) => !h.revealed && h.body === null));
      const hint = await svc.labHints(lab.id).then((rows) => rows[0]);
      const revealed = await svc.revealHint(userId, lab.id, hint.id);
      assert.ok(revealed.body);
      for (const term of entry.hintMustLack) {
        assert.ok(!revealed.body.toLowerCase().includes(term), "revealed hint still must not state answers");
      }
      const after = await svc.hintsFor(userId, lab.id);
      assert.ok(after.find((h) => String(h.id) === String(hint.id)).revealed, "hint-view persists");
    });
  }
});

describe("theory routes (http)", () => {
  const PORT = 3468;
  const BASE = `http://127.0.0.1:${PORT}`;
  let child, cookie;
  const labIds = {};
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
    try {
      await createUser({ username: "theoryhttp", email: "th@test.local", displayName: "TH", password: "password12345" });
    } catch {
      // already exists on re-runs against a shared dir (never the case here)
    }
    const r = await fetch(`${BASE}/login`, {
      method: "POST", redirect: "manual",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ identifier: "theoryhttp", password: "password12345" }),
    });
    assert.equal(r.status, 302);
    cookie = (r.headers.get("set-cookie") || "").split(";")[0];
    const labsRes = await fetch(`${BASE}/api/labs`, { headers: { Cookie: cookie } });
    const found = (await labsRes.json()).labs;
    for (const entry of LABS) {
      labIds[entry.slug] = found.find((l) => l.slug === entry.slug).id;
      assert.ok(labIds[entry.slug], entry.slug);
    }
  });
  after(() => { try { child.kill(); } catch {} });

  const get = (p, opts = {}) => fetch(`${BASE}${p}`, { redirect: "manual", headers: { Cookie: cookie }, ...opts });
  const post = (p, body) => fetch(`${BASE}${p}`, {
    method: "POST", headers: { Cookie: cookie, "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });

  for (const entry of LABS) {
    it(`${entry.section} workspace has no terminal, no fake target, no answer key`, async () => {
      const r = await get(`/labs/oscp/${entry.slug}`);
      assert.equal(r.status, 200);
      const html = await r.text();
      for (const crumb of [entry.section, entry.title.split(" ").slice(1).join(" ") || entry.title, "Lab 1"]) {
        assert.ok(html.includes(crumb), `missing: ${crumb}`);
      }
      assert.ok(!html.includes("termForm"), "no terminal card on a knowledge exercise");
      assert.ok(!html.includes("termOut"), "no terminal output surface");
      assert.ok(!html.includes("10.210.") && !html.includes("10.200."), "no fake lab-network IPs");
      assert.ok(html.includes("Knowledge exercise"), "connection states the exercise kind");
      assert.ok(html.includes("none for this exercise"), "no target is explicit");
      assert.ok(html.includes("<h3>Questions</h3>"), "questions section renders");
      // Every objective's full question text must be visible (titles alone
      // are not enough on knowledge checks).
      const def = JSON.parse(fs.readFileSync(path.join(REPO, entry.file), "utf8"));
      const escHtml = (s) => String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
      for (const o of def.objectives) {
        assert.ok(html.includes(escHtml(o.description)), `question text visible: ${o.key}`);
        assert.ok(html.includes(`name="${o.key}"`), `submit input present: ${o.key}`);
      }
      assert.ok(!html.includes("expectedHash") && !html.includes("expected_value_hash"), "no answer metadata in HTML");
      for (const marker of ["Submit Answer", "Lab Progress", "Connection", "Notes"]) assert.ok(html.includes(marker));
    });

    it(`${entry.section} API redacts internals; direct submission cannot bypass validation`, async () => {
      const labId = labIds[entry.slug];
      const j = await (await get(`/api/labs/${labId}`)).json();
      assert.equal(j.targets.length, 1);
      const blob = JSON.stringify(j);
      assert.ok(!blob.includes("expectedHash") && !blob.includes("expected_value_hash"), "hashes never served");
      assert.ok(!blob.includes("service_ports") && !blob.includes("metadata_json"), "internals redacted");
      // Unknown objective key is rejected, not completed.
      let r = await post(`/api/labs/${labId}/start`);
      assert.equal(r.status, 200);
      r = await post(`/api/labs/${labId}/submit`, { answers: { "nope": entry.answers["question-1"] } });
      assert.ok((await r.json()).results["nope"].correct === false);
    });

    it(`${entry.section} full flow: start → wrong → right → persistence → stop`, async () => {
      const labId = labIds[entry.slug];
      const postq = (p, body) => fetch(`${BASE}${p}`, {
        method: "POST", headers: { Cookie: cookie, "Content-Type": "application/json" },
        body: body ? JSON.stringify(body) : undefined,
      });
      let r = await postq(`/api/labs/${labId}/start`);
      assert.equal(r.status, 200);
      const started = await r.json();
      assert.equal(started.instance.status, "running");
      assert.equal(started.instance.provider, "external-research");
      assert.ok(!started.instance.targetIp, "no target IP on a knowledge session");
      r = await postq(`/api/labs/${labId}/submit`, { answers: { "question-1": entry.wrong["question-1"], "question-2": "  " } });
      const neg = await r.json();
      assert.equal(neg.results["question-1"].correct, false);
      assert.equal(neg.results["question-2"].correct, false);
      assert.ok(!neg.progress.complete);
      r = await postq(`/api/labs/${labId}/submit`, { answers: entry.answers });
      const done = await r.json();
      assert.ok(done.results["question-1"].correct && done.results["question-2"].correct);
      assert.ok(done.progress.complete);
      assert.equal(done.progress.objectiveDone, 2);
      const st = await (await get(`/api/labs/${labId}/status`)).json();
      assert.ok(st.progress.complete, "completion persists across reads");
      r = await postq(`/api/labs/${labId}/stop`);
      assert.equal((await r.json()).instance.status, "stopped");
      const st2 = await (await get(`/api/labs/${labId}/status`)).json();
      assert.ok(st2.progress.complete, "completion survives stop");
      // Reopen keeps completion (re-start is idempotent on progress).
      r = await postq(`/api/labs/${labId}/start`);
      assert.equal(r.status, 200);
      const st3 = await (await get(`/api/labs/${labId}/status`)).json();
      assert.ok(st3.progress.complete, "completion persists on reopen");
      await postq(`/api/labs/${labId}/stop`);
    }, { timeout: 60000 });
  }
});
