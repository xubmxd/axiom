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
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "axiom-labs-smtp-"));
process.env.DATA_DIR = TMP;
process.env.LAB_PROVIDER = "local";

const REPO = path.resolve(import.meta.dirname, "..");
const SLUG = "m6-6-3-5-smtp";
const DEF = path.join(REPO, "labs/module-06/6.3.5-smtp/lab.json");
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

describe("smtp definition", () => {
  it("loads as its own exercise under Module 6 (new 6.3.5 section)", async () => {
    const { loadAllDefinitions, validateDefinition, normalizePlacement } = await import("../server/labs/definitions.js");
    const all = loadAllDefinitions(path.join(REPO, "labs"));
    const lab = all.find((l) => l.def.slug === SLUG);
    assert.ok(lab, "6.3.5 lab.json must be discovered");
    assert.deepEqual(validateDefinition(lab.def), []);
    const p = normalizePlacement(lab.def);
    assert.equal(p.courseSlug, "oscp");
    assert.equal(p.moduleNumber, 6);
    assert.equal(p.moduleTitle, "Information Gathering");
    assert.equal(p.section, "6.3.5");
    assert.equal(p.sectionTitle, "SMTP Enumeration");
    assert.equal(lab.def.labNumber, 1);
    assert.equal(lab.def.title, "6.3.5 SMTP Enumeration");
    const sections = new Set(all.filter((l) => normalizePlacement(l.def).moduleNumber === 6).map((l) => normalizePlacement(l.def).section));
    assert.deepEqual([...sections].sort(), ["6.2.1", "6.2.2", "6.2.3", "6.2.4", "6.3.1", "6.3.2", "6.3.3", "6.3.4", "6.3.5", "6.3.6"]);
  });

  it("declares an attacker, one SMTP target, and non-SMTP decoys", async () => {
    const def = readDef();
    assert.equal(def.environment.type, "multi-target");
    assert.equal(def.targets.length, 4);
    const byType = {};
    for (const t of def.targets) byType[t.type] = (byType[t.type] || 0) + 1;
    assert.equal(byType.attacker, 1, "attacker shell box present");
    assert.equal(byType["smtp-target"], 1, "exactly one SMTP server");
    assert.equal(byType["nmap-target"], 2, "decoys keep it a discovery exercise");
    for (const t of def.targets) {
      assert.ok(t.name && t.image && t.build, "each target needs name/image/build");
      assert.deepEqual(t.ports, [], "no service ports in the definition");
    }
    const smtp = def.targets.find((t) => t.type === "smtp-target");
    assert.equal(smtp.metadata?.role, "smtp-vrfy");
    assert.equal(smtp.metadata?.ipSuffix, 8);
    for (const t of def.targets) {
      assert.ok(!/smtp|vrfy|mail/i.test(t.name), "names stay service-neutral");
    }
  });

  it("has exactly one objective: the VRFY reply code", async () => {
    const def = readDef();
    assert.equal(def.objectives.length, 1);
    assert.deepEqual(def.objectives.map((o) => o.key), ["smtp-code"]);
    assert.equal(def.objectives[0].validation, "exact");
    assert.match(def.objectives[0].expectedHash, /^[0-9a-f]{64}$/);
  });

  it("stored hash matches 252 and nothing else guessable does", async () => {
    const { verifyAnswer } = await import("../server/labs/answers.js");
    const def = readDef();
    const o = def.objectives[0];
    assert.ok(verifyAnswer("252", o.expectedHash, "exact"));
    assert.ok(!verifyAnswer("250", o.expectedHash, "exact"));
    assert.ok(!verifyAnswer("550", o.expectedHash, "exact"));
    assert.ok(!verifyAnswer("", o.expectedHash, "exact"));
    assert.ok(verifyAnswer(" 252 ", o.expectedHash, "exact"), "exact trims surrounding whitespace");
  });

  it("leaks no answer, code, or host mapping", async () => {
    const raw = fs.readFileSync(DEF, "utf8");
    assert.ok(!raw.includes("AXIOM{"), "no flag material");
    assert.ok(!/252/.test(JSON.stringify(readDef().hints)), "hints must not name the code");
    assert.ok(!/252/.test(JSON.stringify(readDef().instructions)), "instructions must not name the code");
  });
});

describe("smtp service behavior", () => {
  it("banner, EHLO, VRFY root 252, VRFY unknown 550, QUIT", async () => {
    const { startSmtpRole } = await import("../server/labs/smtp-target.js");
    const srv = await startSmtpRole("smtp-vrfy", { host: "127.0.0.1", ports: { tcp25: 0 }, hostname: "mail" });
    const convo = (lines) => new Promise((resolve) => {
      const s = new net.Socket();
      let out = "";
      const t = setTimeout(() => { s.destroy(); resolve(out); }, 5000);
      s.on("error", () => { clearTimeout(t); resolve(out); });
      s.on("data", (d) => { out += d.toString("utf8"); });
      s.on("close", () => { clearTimeout(t); resolve(out); });
      s.connect(srv.ports[0], "127.0.0.1", async () => {
        for (const ln of lines) s.write(ln + "\r\n");
      });
    });
    try {
      const full = await convo(["EHLO kali", "VRFY root", "QUIT"]);
      assert.ok(/^220 .*ESMTP/.test(full), "banner");
      assert.ok(full.includes("250"), "EHLO accepted");
      assert.ok(/^252 /m.test(full), "VRFY root returns 252");
      assert.ok(full.includes("221"), "QUIT closes");
      const other = await convo(["VRFY admin", "QUIT"]);
      assert.ok(!/^252 /m.test(other), "other users never produce 252");
      assert.ok(/^550 /m.test(other), "unknown user rejected");
      const bad = await convo(["FROBNICATE", "VRFY", "QUIT"]);
      assert.ok(!/^252 /m.test(bad), "malformed commands never produce 252");
    } finally {
      await srv.close();
    }
  });

  it("ships the canonical module to the image (no drift)", async () => {
    for (const f of ["smtp-target.js"]) {
      const a = fs.readFileSync(path.join(REPO, "server/labs", f), "utf8");
      const b = fs.readFileSync(path.join(REPO, "lab-images/m6/smtp-635", f), "utf8");
      assert.equal(a, b, `${f} copy must match the canonical module`);
    }
    const dockerfile = fs.readFileSync(path.join(REPO, "lab-images/m6/smtp-635/Dockerfile"), "utf8");
    assert.ok(dockerfile.includes("USER smtptarget"), "target must not run as root");
    assert.ok(dockerfile.includes("TARGET_ROLE"), "personality comes from env, not the image");
    assert.ok(dockerfile.includes("cap_net_bind_service"));
    assert.ok(!/252|password|secret/i.test(dockerfile), "no answers in the image definition");
  });

  it("attacker image carries SMTP tooling (nmap, nc)", async () => {
    const dockerfile = fs.readFileSync(path.join(REPO, "lab-images/m6/attacker/Dockerfile"), "utf8");
    for (const pkg of ["nmap", "netcat-openbsd"]) {
      assert.ok(dockerfile.includes(pkg), `attacker needs ${pkg}`);
    }
  });

  it("image build contexts resolve", async () => {
    const { resolveBuildContext } = await import("../server/labs/orchestrator.js");
    assert.equal(resolveBuildContext("axiom-lab-smtp-635:latest", JSON.stringify({ build: "m6/smtp-635" })), path.resolve(REPO, "lab-images/m6/smtp-635"));
  });
});

describe("smtp service (sqlite) + local range", () => {
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
    const u = await createUser({ username: "smtptester", email: "smtp@test.local", displayName: "SMTP", password: "password12345" });
    userId = u.id;
    await svc.seedFromDefinitions(path.join(REPO, "labs"));
    lab = await svc.getLab("slug", SLUG);
    assert.ok(lab);
  });

  it("seeds attacker + SMTP target + decoys, one hash-only objective", async () => {
    const targets = await svc.labTargets(lab.id);
    assert.equal(targets.length, 4);
    assert.equal(targets.filter((t) => t.target_type === "attacker").length, 1);
    assert.equal(targets.filter((t) => t.target_type === "smtp-target").length, 1);
    assert.equal(targets.filter((t) => t.target_type === "nmap-target").length, 2);
    for (const t of targets) {
      assert.deepEqual(JSON.parse(t.service_ports), []);
      // Semantic fields only: random hex ids cannot carry answers, and
      // matching whole rows makes digit patterns flaky by construction.
      assert.ok(![t.name, t.hostname, t.os, t.image_reference, t.network_role, t.service_ports, t.metadata_json].join(" ").match(/252|AXIOM\{/));
    }
    const objectives = await svc.labObjectives(lab.id);
    assert.equal(objectives.length, 1);
    assert.ok(!("expected_value_hash" in objectives[0]), "hashes must never be served to clients");
    assert.equal((await svc.labHints(lab.id)).length, 3);
  });

  it("provisions an isolated range with .8 SMTP semantics", async function () {
    if (!haveSandbox) { console.log("  (skip: no sandbox)"); return; }
    const topo = await orch.nmapTopology(lab.id, "10.210.9.0/24");
    assert.equal(topo.subnet, "10.210.9.0/24");
    assert.equal(topo.attacker.ip, "10.210.9.2");
    assert.deepEqual(topo.boxes.map((b) => b.ip).sort(),
      ["10.210.9.151", "10.210.9.22", "10.210.9.8"]);
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

  it("real Nmap finds TCP/25 on one host, real nc+VRFY yields 252 (student path)", async function () {
    if (!haveSandbox || !await hostHas("nmap")) { console.log("  (skip: needs unshare + host nmap)"); return; }
    const tmp = await svc.createInstance({ userId, labId: lab.id, provider: "local" });
    const details = await orch.provisionInstance({ lab, instance: { ...tmp, user_id: userId } });
    const iid = tmp.id;
    const inst = await activate(svc, db, lab, tmp, details);
    const base = details.networkCidr.split(".").slice(0, 3).join(".");
    const sh = (command) => orch.runTerminalCommand(inst, command, lab).then((r) => r.output);
    try {
      const scan = await sh(`nmap -sV -p 25 -T4 --open ${base}.0/24 -oN smtp.txt && grep -c "25/tcp open" smtp.txt`);
      assert.equal(scan.trim().split("\n").pop().trim(), "1", "exactly one TCP/25 host");
      assert.ok((await sh(`cat smtp.txt`)).includes(`${base}.8`), "the SMTP host is the .8 role");
      const convo = await sh(`printf 'VRFY root\\r\\nQUIT\\r\\n' | nc -w 3 ${base}.8 25`);
      assert.ok(/^220 /m.test(convo), "banner over Netcat");
      const code = [...convo.matchAll(/^(\d{3}) /gm)].map((x) => x[1]).find((c) => c !== "220" && c !== "221");
      assert.equal(code, "252", "VRFY root reply code extracted from the dialogue");
      const r = await svc.submitAnswer({ userId, lab, objectiveKey: "smtp-code", answer: "252", instanceId: iid });
      assert.ok(r.correct && r.completed);
    } finally {
      await orch.destroyInstance(instRow(details, iid, lab.id));
      await svc.clearRuntimeFlags(iid).catch(() => {});
    }
  }, { timeout: 180000 });

  it("wrong codes fail; decoys stay silent on SMTP", async function () {
    if (!haveSandbox) { console.log("  (skip: no sandbox)"); return; }
    for (const ans of ["250", "550", "221", "25", "", "   ", "2522", "25 2"]) {
      const r = await svc.submitAnswer({ userId, lab, objectiveKey: "smtp-code", answer: ans, instanceId: "li_smtpx" });
      assert.ok(r.ok && !r.correct, `smtp-code=${JSON.stringify(ans)} must fail`);
    }
    const tmp = await svc.createInstance({ userId, labId: lab.id, provider: "local" });
    const details = await orch.provisionInstance({ lab, instance: { ...tmp, user_id: userId } });
    const iid = tmp.id;
    const inst = await activate(svc, db, lab, tmp, details);
    const base = details.networkCidr.split(".").slice(0, 3).join(".");
    const sh = (command) => orch.runTerminalCommand(inst, command, lab).then((r) => r.output);
    try {
      for (const decoy of [`${base}.22`, `${base}.151`]) {
        const probe = await sh(`nmap -p 25 --open -T4 ${decoy}`);
        assert.ok(!/25\/tcp\s+open/.test(probe), `decoy ${decoy} must not expose TCP/25`);
      }
    } finally {
      await orch.destroyInstance(instRow(details, iid, lab.id));
      await svc.clearRuntimeFlags(iid).catch(() => {});
    }
  }, { timeout: 180000 });

  it("reset keeps deterministic 252 behavior; stale subnets die", async function () {
    if (!haveSandbox) { console.log("  (skip: no sandbox)"); return; }
    const tmp1 = await svc.createInstance({ userId, labId: lab.id, provider: "local" });
    const d1 = await orch.provisionInstance({ lab, instance: { ...tmp1, user_id: userId } });
    const iid = tmp1.id;
    const inst = await activate(svc, db, lab, tmp1, d1);
    const base = d1.networkCidr.split(".").slice(0, 3).join(".");
    const sh = (command) => orch.runTerminalCommand(inst, command, lab).then((r) => r.output);
    try {
      const c1 = await sh(`printf 'VRFY root\\r\\nQUIT\\r\\n' | nc -w 3 ${base}.8 25`);
      assert.ok(/^252 /m.test(c1));
      await orch.destroyInstance(instRow(d1, iid, lab.id));
      await svc.clearRuntimeFlags(iid);
      const tmp2 = await svc.createInstance({ userId, labId: lab.id, provider: "local" });
      const d2 = await orch.provisionInstance({ lab, instance: { ...tmp2, user_id: userId } });
      const inst2 = await activate(svc, db, lab, tmp2, d2);
      const base2 = d2.networkCidr.split(".").slice(0, 3).join(".");
      const sh2 = (command) => orch.runTerminalCommand(inst2, command, lab).then((r) => r.output);
      const c2 = await sh2(`printf 'VRFY root\\r\\nQUIT\\r\\n' | nc -w 3 ${base2}.8 25`);
      assert.ok(/^252 /m.test(c2), "fresh instance answers identically");
      await orch.destroyInstance(instRow(d2, tmp2.id, lab.id));
      await svc.clearRuntimeFlags(tmp2.id);
    } catch (e) {
      await orch.destroyInstance(instRow({ providerReference: "" }, iid, lab.id)).catch(() => {});
      await svc.clearRuntimeFlags(iid).catch(() => {});
      throw e;
    }
  }, { timeout: 180000 });

  it("never leaks the answer through lab reads", async () => {
    for (const row of await svc.labTargets(lab.id)) {
      assert.ok(![row.name, row.hostname, row.os, row.image_reference, row.network_role, row.service_ports, row.metadata_json].join(" ").match(/252|AXIOM\{/));
    }
    for (const row of await svc.labObjectives(lab.id)) {
      assert.ok(![row.objective_key, row.title, row.description].join(" ").match(/252|AXIOM\{/));
    }
    const labRow = await svc.getLab("slug", SLUG);
    assert.ok(![labRow.title, labRow.description, labRow.section_number, labRow.tags].join(" ").match(/252|AXIOM\{/));
    const hints = await svc.hintsFor(userId, lab.id);
    assert.ok(!hints.map((h) => `${h.title} ${h.body || ""}`).join(" ").match(/252/));
  });
});

describe("smtp routes (http)", () => {
  const PORT = 3466;
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
      user = await createUser({ username: "smtphttp", email: "smtph@test.local", displayName: "SMTPH", password: "password12345" });
    } catch {
      user = await db.get(`SELECT * FROM users WHERE username=?`, ["smtphttp"]);
    }
    const r = await fetch(`${BASE}/login`, {
      method: "POST", redirect: "manual",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ identifier: "smtphttp", password: "password12345" }),
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

  it("workspace shows the range without the reply code", async () => {
    const r = await get(`/labs/oscp/${SLUG}`);
    assert.equal(r.status, 200);
    const html = await r.text();
    for (const crumb of ["6.3.5", "SMTP Enumeration", "Lab 1"]) assert.ok(html.includes(crumb), `missing: ${crumb}`);
    assert.ok(html.includes("kali"), "attacker shell framing present");
    assert.ok(!/\b252\b/.test(html), "no reply code in HTML");
    assert.ok(!html.includes("AXIOM{"), "no flag material in HTML");
    for (const marker of ["Attacker Terminal", "Submit Answer", "Lab Progress", "Connection"]) assert.ok(html.includes(marker));
  });

  it("lab API redacts deployment internals from target listings", async () => {
    const j = await (await get(`/api/labs/${labId}`)).json();
    assert.equal(j.targets.length, 4);
    const blob = JSON.stringify(j.targets);
    assert.ok(!/\b252\b/.test(blob));
    assert.ok(!blob.includes("service_ports") && !blob.includes("metadata_json"), "internals redacted");
    assert.ok(blob.includes("Attacker"), "neutral names still served");
  });

  it("full lifecycle over HTTP with real enumeration", async function () {
    const orch = await import("../server/labs/orchestrator.js");
    if (!await orch.unshareAvailable()) { console.log("  (skip: no sandbox)"); return; }
    const postq = (p, body) => fetch(`${BASE}${p}`, {
      method: "POST", headers: { Cookie: cookie, "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    });
    let r = await postq(`/api/labs/${labId}/start`);
    assert.equal(r.status, 200);
    const started = await r.json();
    assert.equal(started.instance.status, "running");
    const base = started.instance.networkCidr.split(".").slice(0, 3).join(".");
    const sh = (command) => postq(`/api/labs/${labId}/terminal`, { command }).then((x) => x.json()).then((j) => j.output);
    const scan = await sh(`nmap -p 25 --open -T4 ${base}.0/24 | grep -c "25/tcp open"`);
    assert.equal(scan.trim(), "1");
    const convo = await sh(`printf 'VRFY root\\r\\nQUIT\\r\\n' | nc -w 3 ${base}.8 25`);
    assert.ok(/^252 /m.test(convo), "VRFY root returns 252 over the terminal");
    r = await postq(`/api/labs/${labId}/submit`, { answers: { "smtp-code": "250" } });
    assert.equal((await r.json()).results["smtp-code"].correct, false);
    r = await postq(`/api/labs/${labId}/submit`, { answers: { "smtp-code": "252" } });
    const done = await r.json();
    assert.ok(done.results["smtp-code"].correct);
    assert.ok(done.progress.complete);
    r = await postq(`/api/labs/${labId}/reset`);
    assert.equal((await r.json()).instance.resetCount, 1);
    r = await postq(`/api/labs/${labId}/stop`);
    assert.equal((await r.json()).instance.status, "stopped");
    const st = await (await get(`/api/labs/${labId}/status`)).json();
    assert.ok(st.progress.complete, "completion survives stop");
  }, { timeout: 240000 });
});
