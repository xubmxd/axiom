import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

// Isolate: temp sqlite file + local provider before any server module loads.
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "axiom-labs-netcraft-"));
process.env.DATA_DIR = TMP;
process.env.LAB_PROVIDER = "local";

const REPO = path.resolve(import.meta.dirname, "..");
const SLUG = "m6-6-2-3-netcraft";
const DEF = path.join(REPO, "labs/module-06/6.2.3-netcraft/lab.json");

const APP_SERVER = "Apache";
const FONT_FW = "Font Awesome Web Fonts";
const ASN = "AS16276";

const SITEREPORT_URL = "https://sitereport.netcraft.com/?url=www.megacorpone.com";
const SITE_URL = "https://www.megacorpone.com";

function readDef() {
  return JSON.parse(fs.readFileSync(DEF, "utf8"));
}

describe("netcraft definition", () => {
  it("loads as its own exercise under Module 6 (not inside 6.2.1 or 6.2.2)", async () => {
    const { loadAllDefinitions, validateDefinition, normalizePlacement } = await import("../server/labs/definitions.js");
    const all = loadAllDefinitions(path.join(REPO, "labs"));
    const lab = all.find((l) => l.def.slug === SLUG);
    assert.ok(lab, "6.2.3 lab.json must be discovered");
    assert.deepEqual(validateDefinition(lab.def), []);
    const p = normalizePlacement(lab.def);
    assert.equal(p.courseSlug, "oscp");
    assert.equal(p.moduleNumber, 6);
    assert.equal(p.moduleTitle, "Information Gathering");
    assert.equal(p.section, "6.2.3");
    assert.equal(p.sectionTitle, "Netcraft");
    assert.equal(lab.def.labNumber, 1);
    assert.equal(lab.def.title, "6.2.3 Netcraft");
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

  it("keeps the three source objectives with hashed answers", async () => {
    const def = readDef();
    assert.equal(def.objectives.length, 3);
    assert.deepEqual(def.objectives.map((o) => o.key), ["application-server", "font-framework", "ipv4-asn"]);
    for (const o of def.objectives) assert.match(o.expectedHash, /^[0-9a-f]{64}$/);
    const joined = JSON.stringify(def.objectives);
    assert.ok(joined.includes("application server") && joined.includes("Client-Side Scripting Framework") && joined.includes("autonomous systems"),
      "the three distinct Netcraft data types stay separate objectives");
  });

  it("leaks no answers through the definition, hints, or research content", async () => {
    const def = readDef();
    const raw = fs.readFileSync(DEF, "utf8");
    for (const secret of [APP_SERVER, FONT_FW, ASN]) {
      assert.ok(!raw.includes(secret), `answer must not appear in plaintext: ${secret}`);
    }
    // "Apache" must not hide inside a longer word either (e.g. instructions)
    assert.ok(!/apache/i.test(raw), "no case variant of the server answer in the definition");
    assert.ok(!/font awesome/i.test(raw), "no case variant of the framework answer in the definition");
  });

  it("carries six progressive technique hints that do not reveal answers", async () => {
    const def = readDef();
    assert.equal(def.hints.length, 6);
    const joined = JSON.stringify(def.hints);
    assert.ok(!/apache|font awesome|as16276/i.test(joined));
    assert.ok(/netcraft/i.test(joined), "hints point at the Netcraft workflow");
    assert.ok(/autonomous/i.test(joined), "hints distinguish the ASN field");
  });

  it("defines per-lab research links (Netcraft site report + target site)", async () => {
    const def = readDef();
    assert.ok(def.research && Array.isArray(def.research.links) && def.research.links.length >= 2);
    const urls = def.research.links.map((l) => l.url);
    assert.ok(urls.includes(SITEREPORT_URL), "direct Netcraft site-report URL for the target hostname");
    assert.ok(urls.includes(SITE_URL), "target site link");
    assert.ok(urls.every((u) => u.startsWith("https://")), "external links are https only");
    assert.ok(!/apache|font awesome|as16276/i.test(JSON.stringify(def.research)), "research copy carries no answers");
  });
});

describe("netcraft service (sqlite)", () => {
  let svc, db, userId, lab;
  before(async () => {
    db = await import("../server/db.js");
    await db.initDb();
    svc = await import("../server/labs/service.js");
    const { createUser } = await import("../server/auth.js");
    const u = await createUser({ username: "netcrafttester", email: "nc@test.local", displayName: "NC", password: "password12345" });
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
    assert.equal((await svc.labHints(lab.id)).length, 6);
  });

  it("rejects wrong and plausible-but-incorrect answers", async () => {
    const wrong = [
      ["application-server", "nginx"], ["application-server", "Apache HTTPD"],
      ["application-server", "IIS"], ["application-server", ""],
      ["font-framework", "Font Awesome"], ["font-framework", "JavaScript"],
      ["font-framework", "Bootstrap"], ["font-framework", "Font Awesome Web"],
      ["font-framework", "   "],
      ["ipv4-asn", "AS15169"], ["ipv4-asn", "16276"],
      ["ipv4-asn", "AS00000"], ["ipv4-asn", ""],
    ];
    for (const [key, ans] of wrong) {
      const r = await svc.submitAnswer({ userId, lab, objectiveKey: key, answer: ans, instanceId: "li_nc" });
      assert.ok(r.ok && !r.correct, `${key}=${JSON.stringify(ans)} must fail`);
      assert.ok(!JSON.stringify(r).includes(ASN));
    }
    const p = await svc.labProgress(userId, lab.id);
    assert.equal(p.objectiveDone, 0);
  });

  it("accepts the documented answers with harmless formatting variants", async () => {
    const a = await svc.submitAnswer({ userId, lab, objectiveKey: "application-server", answer: "apache", instanceId: "li_nc" });
    assert.ok(a.correct && a.completed);
    const a2 = await svc.submitAnswer({ userId, lab, objectiveKey: "application-server", answer: "  APACHE ", instanceId: "li_nc" });
    assert.ok(a2.correct, "case/whitespace variants normalize");
    const b = await svc.submitAnswer({ userId, lab, objectiveKey: "font-framework", answer: "font awesome web fonts", instanceId: "li_nc" });
    assert.ok(b.correct);
    const b2 = await svc.submitAnswer({ userId, lab, objectiveKey: "font-framework", answer: " FONT AWESOME WEB FONTS ", instanceId: "li_nc" });
    assert.ok(b2.correct);
    const c = await svc.submitAnswer({ userId, lab, objectiveKey: "ipv4-asn", answer: "as16276", instanceId: "li_nc" });
    assert.ok(c.correct);
    const c2 = await svc.submitAnswer({ userId, lab, objectiveKey: "ipv4-asn", answer: " AS16276 ", instanceId: "li_nc" });
    assert.ok(c2.correct);
    const p = await svc.labProgress(userId, lab.id);
    assert.equal(p.objectiveDone, 3);
    assert.ok(p.complete);
    const again = await svc.labProgress(userId, lab.id);
    assert.ok(again.complete && again.objectiveDone === 3, "progress must persist");
  });

  it("objectives complete independently (no ordering requirement)", async () => {
    const { createUser } = await import("../server/auth.js");
    const other = await createUser({ username: "ncother", email: "nco@test.local", displayName: "NCO", password: "password12345" });
    const r = await svc.submitAnswer({ userId: other.id, lab, objectiveKey: "ipv4-asn", answer: ASN, instanceId: "li_nc2" });
    assert.ok(r.correct && r.completed, "Q3 completes without Q1/Q2");
    const p = await svc.labProgress(other.id, lab.id);
    assert.equal(p.objectiveDone, 1);
    assert.ok(!p.complete);
  });

  it("public lab reads never expose expected answers", async () => {
    for (const row of await svc.labTargets(lab.id)) {
      assert.ok(!/apache|font awesome|as16276/i.test(JSON.stringify(row)));
    }
    for (const row of await svc.labObjectives(lab.id)) {
      assert.ok(!/apache|font awesome|as16276/i.test(JSON.stringify(row)));
    }
    const labRow = await svc.getLab("slug", SLUG);
    assert.ok(!/apache|font awesome|as16276/i.test(JSON.stringify(labRow)));
    assert.ok(!/apache|font awesome|as16276/i.test(JSON.stringify(await svc.labProgress(userId, lab.id))));
    assert.ok(!/apache|font awesome|as16276/i.test(JSON.stringify(await svc.hintsFor(userId, lab.id))));
  });

  it("external-research provider provisions a logical session with no network footprint", async () => {
    const orch = await import("../server/labs/orchestrator.js");
    const details = await orch.providerFor("external-research").provision(lab, { id: "li_nc1" });
    assert.equal(details.targetIp, "");
    assert.equal(details.targetPort, 0);
    assert.equal(details.hostEndpoint, "");
    await orch.providerFor("external-research").destroy({ id: "li_nc1" });
  });

  it("osint terminal stays browser-scoped with no network tooling", async () => {
    const orch = await import("../server/labs/orchestrator.js");
    const osintLab = { slug: SLUG, environment_type: "osint" };
    const help = await orch.runTerminalCommand({}, "help", osintLab);
    assert.ok(/browser/i.test(help.output));
    const evil = await orch.runTerminalCommand({}, "rm -rf /", osintLab);
    assert.ok(/not available/i.test(evil.output));
  });

  it("existing labs keep their sections and answers (regression)", async () => {
    for (const slug of ["m6-6-2-1-whois-vm1", "m6-6-2-1-whois-vm2", "m6-6-2-1-whois-vm3", "m6-6-2-2-google-hacking"]) {
      assert.ok(await svc.getLab("slug", slug), `${slug} still registered`);
    }
    assert.equal(lab.section_number, "6.2.3", "Netcraft stays separate from 6.2.1 and 6.2.2");
    const { verifyAnswer } = await import("../server/labs/answers.js");
    const def = JSON.parse(fs.readFileSync(path.join(REPO, "labs/module-06/6.2.1-whois/vm-01/lab.json"), "utf8"));
    const byKey = Object.fromEntries(def.objectives.map((o) => [o.key, o]));
    assert.ok(verifyAnswer("ns3.megacorpone.com", byKey["third-nameserver"].expectedHash, "case-insensitive-exact"));
    const r = await svc.submitAnswer({ userId, lab: await svc.getLab("slug", "m6-6-2-1-whois-vm1"), objectiveKey: "third-nameserver", answer: "ns3.megacorpone.com", instanceId: "li_x" });
    assert.ok(r.correct);
  });
});

describe("netcraft routes (http)", () => {
  const PORT = 3460;
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
      user = await createUser({ username: "nchttp", email: "nch@test.local", displayName: "NCH", password: "password12345" });
    } catch {
      user = await db.get(`SELECT * FROM users WHERE username=?`, ["nchttp"]);
    }
    const r = await fetch(`${BASE}/login`, {
      method: "POST", redirect: "manual",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ identifier: "nchttp", password: "password12345" }),
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

  it("workspace shows Netcraft research links, no answers, no iframe", async () => {
    const r = await get(`/labs/oscp/${SLUG}`);
    assert.equal(r.status, 200);
    const html = await r.text();
    assert.ok(html.includes("External Research"), "research workspace must render");
    assert.ok(html.includes("6.2.3"), "section breadcrumb must render");
    assert.ok(html.includes(SITEREPORT_URL), "direct Netcraft site-report link present");
    assert.ok(html.includes(SITE_URL), "target site link present");
    assert.ok(html.includes('target="_blank"'), "research links open in new tabs");
    assert.ok(!html.includes("<iframe"), "third-party sites are never embedded");
    assert.ok(!html.includes("10.210.") && !html.includes("10.200."), "no fake lab-network IPs");
    assert.ok(!/apache/i.test(html), "workspace HTML must not leak the server answer");
    assert.ok(!/font awesome/i.test(html), "workspace HTML must not leak the framework answer");
    assert.ok(!html.includes(ASN), "workspace HTML must not leak the ASN answer");
  });

  it("hints API loads and reveals without leaking answers", async () => {
    const hints = (await (await get(`/api/labs/${labId}/hints`)).json()).hints;
    assert.equal(hints.length, 6);
    assert.ok(hints.every((h) => !h.revealed));
    const r = await post(`/api/labs/${labId}/hints/${hints[0].id}/reveal`, null);
    const body = await r.json();
    assert.ok(body.ok && body.hint.body);
    assert.ok(!/apache|font awesome|as16276/i.test(body.hint.body));
    const after = (await (await get(`/api/labs/${labId}/hints`)).json()).hints;
    assert.equal(after.filter((h) => h.revealed).length, 1, "reveal persists for that hint only");
  });

  it("6.2.2 workspace still shows its own Google research links (untouched)", async () => {
    const r = await get(`/labs/oscp/m6-6-2-2-google-hacking`);
    assert.equal(r.status, 200);
    const html = await r.text();
    assert.ok(html.includes("https://www.google.com"), "Google Hacking keeps its Google link");
    assert.ok(!html.includes("sitereport.netcraft.com"), "no Netcraft leakage into 6.2.2");
  });

  it("full flow: activate (no VM) → submit → progress persists", async () => {
    let r = await post(`/api/labs/${labId}/start`);
    assert.equal(r.status, 200);
    const started = await r.json();
    assert.equal(started.instance.status, "running");
    assert.equal(started.instance.provider, "external-research");
    assert.ok(!started.instance.targetIp, "no target IP on a research session");
    r = await post(`/api/labs/${labId}/submit`, { answers: { "application-server": "nginx" } });
    assert.equal((await r.json()).results["application-server"].correct, false);
    r = await post(`/api/labs/${labId}/submit`, {
      answers: { "application-server": APP_SERVER, "font-framework": FONT_FW, "ipv4-asn": ASN },
    });
    const done = await r.json();
    assert.ok(done.results["application-server"].correct);
    assert.ok(done.results["font-framework"].correct);
    assert.ok(done.results["ipv4-asn"].correct);
    assert.ok(done.progress.complete);
    const st = await (await get(`/api/labs/${labId}/status`)).json();
    assert.ok(st.progress.complete);
    r = await post(`/api/labs/${labId}/stop`);
    assert.equal((await r.json()).instance.status, "stopped");
    const st2 = await (await get(`/api/labs/${labId}/status`)).json();
    assert.ok(st2.progress.complete, "completion survives stop");
  }, { timeout: 60000 });
});
