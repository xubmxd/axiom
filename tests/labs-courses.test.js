import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

// Isolated sqlite file for this test process.
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "axiom-lab-courses-"));
process.env.DATA_DIR = TMP;
process.env.LAB_PROVIDER = "local";

const REPO = path.resolve(import.meta.dirname, "..");

describe("course placement in definitions", () => {
  it("normalizes the canonical nested shape", async () => {
    const { normalizePlacement, validateDefinition } = await import("../server/labs/definitions.js");
    const def = JSON.parse(fs.readFileSync(path.join(REPO, "labs/module-06/6.2.1-whois/vm-01/lab.json"), "utf8"));
    assert.deepEqual(validateDefinition(def), []);
    const p = normalizePlacement(def);
    assert.equal(p.courseSlug, "core");
    assert.equal(p.courseTitle, "Core");
    assert.equal(p.courseSubtitle, "Core Certified Professional");
    assert.equal(p.moduleNumber, 6);
    assert.equal(p.moduleTitle, "Information Gathering");
    assert.equal(p.section, "6.2.1");
  });
  it("still accepts the legacy flat keys", async () => {
    const { normalizePlacement, validateDefinition } = await import("../server/labs/definitions.js");
    const legacy = {
      slug: "legacy-lab", title: "Legacy", courseSlug: "core",
      moduleNumber: 7, moduleName: "Scanning", section: "7.1",
      targets: [{ name: "VM #1" }],
      objectives: [{ key: "q", expectedHash: "a".repeat(64) }],
    };
    assert.deepEqual(validateDefinition(legacy), []);
    const p = normalizePlacement(legacy);
    assert.equal(p.courseSlug, "core");
    assert.equal(p.moduleNumber, 7);
    assert.equal(p.moduleTitle, "Scanning");
  });
  it("rejects definitions without a course", async () => {
    const { validateDefinition } = await import("../server/labs/definitions.js");
    const noCourse = {
      slug: "orphan", title: "Orphan", moduleNumber: 1,
      targets: [{ name: "VM #1" }],
      objectives: [{ key: "q", expectedHash: "a".repeat(64) }],
    };
    assert.ok(validateDefinition(noCourse).some((m) => m.includes("course")));
  });
});

describe("course catalog service", () => {
  let svc, db, userId, courseId;
  before(async () => {
    db = await import("../server/db.js");
    await db.initDb();
    svc = await import("../server/labs/service.js");
    const { createUser } = await import("../server/auth.js");
    const u = await createUser({ username: "coursetester", email: "c@test.local", displayName: "C", password: "password12345" });
    userId = u.id;
    const r = await svc.seedFromDefinitions(path.join(REPO, "labs"));
    assert.equal(r.labs, 1);
    assert.equal(r.courses, 1);
    await svc.seedFromDefinitions(path.join(REPO, "labs")); // idempotent
    const courses = await svc.listLabCourses();
    assert.equal(courses.length, 1);
    assert.equal(courses[0].slug, "core");
    assert.equal(courses[0].title, "Core");
    courseId = courses[0].id;
  });

  it("assigns the lab to Core with module/section names", async () => {
    const lab = await svc.getLab("slug", "m6-6-2-1-whois-vm1");
    assert.equal(lab.course_id, courseId);
    assert.equal(lab.module_number, 6);
    assert.equal(lab.module_name, "Information Gathering");
    assert.equal(lab.section_number, "6.2.1");
  });

  it("groups course → module → section → lab without duplicate modules", async () => {
    const modules = await svc.courseStructure(userId, courseId);
    assert.equal(modules.length, 1);
    assert.equal(modules[0].number, 6);
    assert.equal(modules[0].title, "Information Gathering");
    assert.equal(modules[0].sections.length, 1);
    assert.equal(modules[0].sections[0].section, "6.2.1");
    assert.equal(modules[0].sections[0].labs.length, 1);
    assert.equal(modules[0].sections[0].labs[0].state, "not-started");
  });

  it("tracks lab state: running reflects a live instance only", async () => {
    const lab = await svc.getLab("slug", "m6-6-2-1-whois-vm1");
    let s = await svc.labState(userId, lab);
    assert.equal(s.state, "not-started");
    // simulate a live instance row (no provider needed for state math)
    const inst = await svc.createInstance({ userId, labId: lab.id, provider: "local" });
    await svc.setInstanceStatus(inst, "running", { targetIp: "10.0.0.9" });
    s = await svc.labState(userId, lab);
    assert.equal(s.state, "running");
    assert.ok(s.running);
    let cur = await svc.getInstance(inst.id);
    cur = await svc.setInstanceStatus(cur, "stopping");
    await svc.setInstanceStatus(cur, "stopped");
    s = await svc.labState(userId, lab);
    assert.equal(s.state, "in-progress");
    // completing objectives flips to completed and stays there
    await svc.submitAnswer({ userId, lab, objectiveKey: "third-nameserver", answer: "ns3.megacorpone.com", instanceId: "" });
    await svc.submitAnswer({ userId, lab, objectiveKey: "registrar-whois", answer: "whois.gandi.net", instanceId: "" });
    s = await svc.labState(userId, lab);
    assert.equal(s.state, "completed");
  });

  it("aggregates course + module progress from existing progress rows", async () => {
    const cp = await svc.courseProgress(userId, courseId);
    assert.deepEqual(cp, { total: 1, completed: 1, inProgress: 0, running: 0, notStarted: 0, pct: 100 });
    const mp = await svc.moduleProgress(userId, courseId, 6);
    assert.deepEqual(mp, { total: 1, completed: 1 });
    const empty = await svc.moduleProgress(userId, courseId, 999);
    assert.deepEqual(empty, { total: 0, completed: 0 });
  });

  it("module progress is scoped to its course", async () => {
    // A same-numbered module in another course must not leak in.
    const now = new Date().toISOString();
    await db.run(`INSERT INTO lab_courses(id, slug, title, created_at, updated_at) VALUES(?,?,?,?,?)`, ["lc_other", "extra", "Extra", now, now]);
    await db.run(`INSERT INTO labs(id, slug, title, course_id, module_number, module_name, lab_number, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?)`,
      ["lab_other", "other-lab", "Other", "lc_other", 6, "Other Module", 1, now, now]);
    const mp = await svc.moduleProgress(userId, courseId, 6);
    assert.deepEqual(mp, { total: 1, completed: 1 });
    await db.run(`DELETE FROM labs WHERE id=?`, ["lab_other"]);
    await db.run(`DELETE FROM lab_courses WHERE id=?`, ["lc_other"]);
  });
});

describe("course routes (http)", () => {
  const PORT = 3457;
  const BASE = `http://127.0.0.1:${PORT}`;
  let child, cookie;
  before(async () => {
    child = spawn("node", ["server/index.js"], {
      cwd: REPO, env: { ...process.env, PORT: String(PORT), DATA_DIR: TMP, LAB_PROVIDER: "local" },
      stdio: "ignore",
    });
    // wait for boot
    const deadline = Date.now() + 20000;
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
      user = await createUser({ username: "httptester", email: "h@test.local", displayName: "H", password: "password12345" });
    } catch {
      user = await db.get(`SELECT * FROM users WHERE username=?`, ["httptester"]);
    }
    assert.ok(user);
    const r = await fetch(`${BASE}/login`, {
      method: "POST", redirect: "manual",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ identifier: "httptester", password: "password12345" }),
    });
    assert.equal(r.status, 302);
    cookie = (r.headers.get("set-cookie") || "").split(";")[0];
    assert.ok(cookie.startsWith("sid="));
  });
  after(() => { try { child.kill(); } catch {} });

  const get = (p, opts = {}) => fetch(`${BASE}${p}`, { redirect: "manual", headers: { Cookie: cookie }, ...opts });

  it("/labs lists courses, not labs", async () => {
    const r = await get("/labs");
    assert.equal(r.status, 200);
    const html = await r.text();
    assert.ok(html.includes("Choose a training path"));
    assert.ok(html.includes("Core"));
    assert.ok(!html.includes("m6-6-2-1-whois-vm1"), "catalog must not link individual labs");
  });

  it("/labs/core shows Module 6 → 6.2.1 → Lab 1", async () => {
    const r = await get("/labs/core");
    assert.equal(r.status, 200);
    const html = await r.text();
    assert.ok(html.includes("Module 6"));
    assert.ok(html.includes("Information Gathering"));
    assert.ok(html.includes("6.2.1"));
    assert.ok(html.includes("/labs/core/m6-6-2-1-whois-vm1"));
  });

  it("unknown course is a 404 page, not a crash", async () => {
    const r = await get("/labs/nosuchcourse");
    assert.equal(r.status, 404);
    assert.ok((await r.text()).includes("Training path not found"));
  });

  it("legacy lab URL redirects to the canonical course URL", async () => {
    const r = await get("/labs/m6-6-2-1-whois-vm1");
    assert.equal(r.status, 302);
    assert.equal(r.headers.get("location"), "/labs/core/m6-6-2-1-whois-vm1");
  });

  it("canonical detail page keeps full breadcrumbs + workspace", async () => {
    const r = await get("/labs/core/m6-6-2-1-whois-vm1");
    assert.equal(r.status, 200);
    const html = await r.text();
    for (const crumb of ["cyber range", "Core", "Module 6", "6.2.1", "Lab 1"]) assert.ok(html.includes(crumb), `missing crumb: ${crumb}`);
    assert.ok(html.includes("/labs/core"), "breadcrumb links back to the course");
    for (const marker of ["Lab Terminal", "Submit Answer", "Lab Progress", "Target Information"]) assert.ok(html.includes(marker));
  });

  it("unknown lab under a valid course is a 404", async () => {
    const r = await get("/labs/core/no-such-lab");
    assert.equal(r.status, 404);
  });

  it("API exposes courses + structure, and lab payloads carry course URLs", async () => {
    let r = await get("/api/labs/courses", { headers: { Cookie: cookie, Accept: "application/json" } });
    assert.equal(r.status, 200);
    const { courses } = await r.json();
    assert.equal(courses.length, 1);
    assert.equal(courses[0].slug, "core");
    r = await get("/api/labs/courses/core", { headers: { Cookie: cookie, Accept: "application/json" } });
    assert.equal(r.status, 200);
    const body = await r.json();
    assert.equal(body.modules.length, 1);
    assert.equal(body.modules[0].sections[0].labs[0].url, "/labs/core/m6-6-2-1-whois-vm1");
    r = await get("/api/labs/courses/nope", { headers: { Cookie: cookie, Accept: "application/json" } });
    assert.equal(r.status, 404);
    r = await get("/api/labs", { headers: { Cookie: cookie, Accept: "application/json" } });
    const { labs } = await r.json();
    assert.equal(labs[0].courseSlug, "core");
    assert.equal(labs[0].url, "/labs/core/m6-6-2-1-whois-vm1");
  });

  it("lab API requires auth", async () => {
    const r = await fetch(`${BASE}/api/labs/courses`);
    assert.equal(r.status, 401);
  });

  it("WHOIS lab lifecycle still works end-to-end (regression)", async () => {
    const labsRes = await get("/api/labs", { headers: { Cookie: cookie, Accept: "application/json" } });
    const labId = (await labsRes.json()).labs[0].id;
    const post = (p, body) => fetch(`${BASE}${p}`, {
      method: "POST", headers: { Cookie: cookie, "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    });
    // start → running with a real target IP
    let r = await post(`/api/labs/${labId}/start`);
    assert.equal(r.status, 200);
    let started = await r.json();
    assert.equal(started.instance.status, "running");
    assert.ok(started.instance.targetIp.startsWith("10."));
    // real TCP/43 against the provisioned endpoint
    const orch = await import("../server/labs/orchestrator.js");
    const ep = await orch.resolveEndpoint({ target_ip: started.instance.targetIp, target_port: 43, host_endpoint: started.instance.hostEndpoint });
    const out = await orch.whoisQuery(ep.host, ep.port, "megacorpone.com");
    assert.ok(/ns3\.megacorpone\.com/i.test(out));
    assert.ok(out.includes("whois.gandi.net"));
    // wrong rejected, right accepted
    r = await post(`/api/labs/${labId}/submit`, { answers: { "third-nameserver": "ns9.example.com" } });
    assert.equal((await r.json()).results["third-nameserver"].correct, false);
    r = await post(`/api/labs/${labId}/submit`, { answers: { "third-nameserver": "ns3.megacorpone.com", "registrar-whois": "whois.gandi.net" } });
    const done = await r.json();
    assert.ok(done.results["third-nameserver"].correct && done.results["registrar-whois"].correct);
    assert.ok(done.progress.complete);
    // course page now shows the lab completed
    const coursePage = await (await get("/labs/core")).text();
    assert.ok(coursePage.includes("Completed"));
    // reset + stop clean up
    r = await post(`/api/labs/${labId}/reset`);
    assert.equal((await r.json()).instance.resetCount, 1);
    r = await post(`/api/labs/${labId}/stop`);
    assert.equal((await r.json()).instance.status, "stopped");
  }, { timeout: 60000 });
});
