import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import dgram from "node:dgram";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { spawn } from "node:child_process";

// Isolate: temp sqlite file + local provider before any server module loads.
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "axiom-labs-snmp-"));
process.env.DATA_DIR = TMP;
process.env.LAB_PROVIDER = "local";

const REPO = path.resolve(import.meta.dirname, "..");
const SLUG = "m6-6-3-6-snmp";
const DEF = path.join(REPO, "labs/module-06/6.3.6-snmp/lab.json");
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

describe("snmp definition", () => {
  it("loads as its own exercise under Module 6 (new 6.3.6 section)", async () => {
    const { loadAllDefinitions, validateDefinition, normalizePlacement } = await import("../server/labs/definitions.js");
    const all = loadAllDefinitions(path.join(REPO, "labs"));
    const lab = all.find((l) => l.def.slug === SLUG);
    assert.ok(lab, "6.3.6 lab.json must be discovered");
    assert.deepEqual(validateDefinition(lab.def), []);
    const p = normalizePlacement(lab.def);
    assert.equal(p.courseSlug, "oscp");
    assert.equal(p.moduleNumber, 6);
    assert.equal(p.moduleTitle, "Information Gathering");
    assert.equal(p.section, "6.3.6");
    assert.equal(p.sectionTitle, "SNMP Enumeration");
    assert.equal(lab.def.labNumber, 1);
    assert.equal(lab.def.title, "6.3.6 SNMP Enumeration");
    const sections = new Set(all.filter((l) => normalizePlacement(l.def).moduleNumber === 6).map((l) => normalizePlacement(l.def).section));
    assert.deepEqual([...sections].sort(), ["6.2.1", "6.2.2", "6.2.3", "6.2.4", "6.3.1", "6.3.2", "6.3.3", "6.3.4", "6.3.5", "6.3.6"]);
  });

  it("declares an attacker, one SNMP target, and non-SNMP decoys", async () => {
    const def = readDef();
    assert.equal(def.environment.type, "multi-target");
    assert.equal(def.targets.length, 4);
    const byType = {};
    for (const t of def.targets) byType[t.type] = (byType[t.type] || 0) + 1;
    assert.equal(byType.attacker, 1, "attacker shell box present");
    assert.equal(byType["snmp-target"], 1, "exactly one SNMP server");
    assert.equal(byType["nmap-target"], 2, "decoys keep it a discovery exercise");
    for (const t of def.targets) {
      assert.ok(t.name && t.image && t.build, "each target needs name/image/build");
      assert.deepEqual(t.ports, [], "no service ports in the definition");
    }
    const snmp = def.targets.find((t) => t.type === "snmp-target");
    assert.equal(snmp.metadata?.role, "snmp");
    assert.equal(snmp.metadata?.ipSuffix, 151);
    for (const t of def.targets) {
      assert.ok(!/snmp|onesixtyone/i.test(t.name), "names stay service-neutral");
    }
  });

  it("has exactly two objectives: process and interface", async () => {
    const def = readDef();
    assert.equal(def.objectives.length, 2);
    assert.deepEqual(def.objectives.map((o) => o.key), ["snmp-process", "snmp-interface"]);
    for (const o of def.objectives) {
      assert.equal(o.validation, "case-insensitive-exact");
      assert.match(o.expectedHash, /^[0-9a-f]{64}$/);
    }
  });

  it("stored hashes match the canonical answers", async () => {
    const { verifyAnswer } = await import("../server/labs/answers.js");
    const def = readDef();
    const byKey = Object.fromEntries(def.objectives.map((o) => [o.key, o]));
    assert.ok(verifyAnswer("snmp.exe", byKey["snmp-process"].expectedHash, "case-insensitive-exact"));
    assert.ok(verifyAnswer("SNMP.EXE", byKey["snmp-process"].expectedHash, "case-insensitive-exact"));
    assert.ok(!verifyAnswer("snmpd", byKey["snmp-process"].expectedHash, "case-insensitive-exact"));
    assert.ok(verifyAnswer("Software Loopback Interface 1", byKey["snmp-interface"].expectedHash, "case-insensitive-exact"));
    assert.ok(!verifyAnswer("Ethernet0", byKey["snmp-interface"].expectedHash, "case-insensitive-exact"));
    assert.ok(!verifyAnswer("", byKey["snmp-interface"].expectedHash, "case-insensitive-exact"));
  });

  it("leaks no answers or host mapping", async () => {
    const raw = fs.readFileSync(DEF, "utf8");
    assert.ok(!raw.includes("AXIOM{"), "no flag material");
    assert.ok(!/snmp\.exe/i.test(JSON.stringify(readDef().hints)), "hints must not name the process");
    assert.ok(!/Loopback Interface 1/.test(JSON.stringify(readDef().hints)), "hints must not name the interface");
    assert.ok(!/snmp\.exe/i.test(JSON.stringify(readDef().instructions)), "instructions must not name the process");
  });
});

describe("snmp agent behavior", () => {
  it("Get/GetNext/GetBulk walk the deterministic MIB view", async () => {
    const { startSnmpAgent, buildSnmpGet, buildSnmpGetNext, buildSnmpGetBulk, parseSnmpResponse, OID_HR_SW_RUN_NAME, OID_IF_DESCR } = await import("../server/labs/snmp-target.js");
    const agent = await startSnmpAgent("snmp", { host: "127.0.0.1", ports: { udp161: 0 } });
    const port = agent.ports[0];
    const query = (buf) => new Promise((resolve) => {
      const s = dgram.createSocket("udp4");
      const t = setTimeout(() => { s.close(); resolve(null); }, 3000);
      s.on("message", (msg) => { clearTimeout(t); s.close(); resolve(msg); });
      s.on("error", () => { clearTimeout(t); resolve(null); });
      s.send(buf, port, "127.0.0.1");
    });
    try {
      // Get sysDescr.
      const r1 = parseSnmpResponse(await query(buildSnmpGet({ oid: [1, 3, 6, 1, 2, 1, 1, 1, 0], requestId: 7 })));
      assert.ok(r1 && r1.errorStatus === 0 && r1.requestId === 7);
      assert.ok(r1.pairs[0].value.includes("Windows"));
      // GetNext walks the process table in order and contains snmp.exe.
      const names = [];
      let cursor = OID_HR_SW_RUN_NAME.slice(0, -1);
      for (let i = 0; i < 20; i++) {
        const r = parseSnmpResponse(await query(buildSnmpGetNext({ oid: cursor })));
        assert.ok(r, "GetNext answers");
        // v1 end-of-table is a noSuchName error (what real agents send).
        if (r.errorStatus !== 0) break;
        const [oid, val] = [r.pairs[0].oid, r.pairs[0].value];
        if (oid.slice(0, OID_HR_SW_RUN_NAME.length).join(".") !== OID_HR_SW_RUN_NAME.join(".")) break;
        names.push(val);
        cursor = oid;
      }
      assert.ok(names.includes("snmp.exe"), "process table contains the SNMP server process");
      assert.equal(names.length, 12, "deterministic process count");
      // GetNext on the interface table starts with the loopback interface.
      const ri = parseSnmpResponse(await query(buildSnmpGetNext({ oid: OID_IF_DESCR.slice(0, -1) })));
      assert.equal(ri.pairs[0].value, "Software Loopback Interface 1");
      // Wrong community stays silent (real agent behavior).
      const t0 = Date.now();
      const silent = await query(buildSnmpGet({ community: "private", oid: [1, 3, 6, 1, 2, 1, 1, 1, 0] }));
      assert.equal(silent, null, "wrong community gets no response");
      assert.ok(Date.now() - t0 >= 2500, "client actually waited out the timeout");
      // v2c GetBulk returns the whole process table in one round trip.
      const rb = parseSnmpResponse(await query(buildSnmpGetBulk({ oid: OID_HR_SW_RUN_NAME.slice(0, -1) })));
      assert.ok(rb && rb.errorStatus === 0);
      assert.ok(rb.pairs.some((p) => p.value === "snmp.exe"));
    } finally {
      await agent.close();
    }
  });

  it("ships the canonical module to the image (no drift)", async () => {
    const a = fs.readFileSync(path.join(REPO, "server/labs/snmp-target.js"), "utf8");
    const b = fs.readFileSync(path.join(REPO, "lab-images/m6/snmp-636/snmp-target.js"), "utf8");
    assert.equal(a, b, "snmp-target.js copy must match the canonical module");
    const dockerfile = fs.readFileSync(path.join(REPO, "lab-images/m6/snmp-636/Dockerfile"), "utf8");
    assert.ok(dockerfile.includes("USER snmptarget"), "target must not run as root");
    assert.ok(dockerfile.includes("TARGET_ROLE"), "personality comes from env, not the image");
    assert.ok(dockerfile.includes("cap_net_bind_service"));
    assert.ok(!/snmp\.exe|Loopback/i.test(dockerfile), "no answers in the image definition");
  });

  it("attacker image carries SNMP tooling", async () => {
    const dockerfile = fs.readFileSync(path.join(REPO, "lab-images/m6/attacker/Dockerfile"), "utf8");
    assert.ok(dockerfile.includes("snmp"), "attacker needs net-snmp clients");
    assert.ok(dockerfile.includes("onesixtyone"), "attacker needs onesixtyone");
    assert.ok(fs.existsSync(path.join(REPO, "lab-images/m6/attacker/onesixtyone.c")), "onesixtyone vendored");
    assert.ok(fs.existsSync(path.join(REPO, "lab-images/m6/attacker/dict.txt")), "community wordlist present");
  });

  it("image build contexts resolve", async () => {
    const { resolveBuildContext } = await import("../server/labs/orchestrator.js");
    assert.equal(resolveBuildContext("axiom-lab-snmp-636:latest", JSON.stringify({ build: "m6/snmp-636" })), path.resolve(REPO, "lab-images/m6/snmp-636"));
  });
});

describe("snmp service (sqlite) + local range", () => {
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
    const u = await createUser({ username: "snmptester", email: "snmp@test.local", displayName: "SNMP", password: "password12345" });
    userId = u.id;
    await svc.seedFromDefinitions(path.join(REPO, "labs"));
    lab = await svc.getLab("slug", SLUG);
    assert.ok(lab);
  });

  it("seeds attacker + SNMP target + decoys, two hash-only objectives", async () => {
    const targets = await svc.labTargets(lab.id);
    assert.equal(targets.length, 4);
    assert.equal(targets.filter((t) => t.target_type === "attacker").length, 1);
    assert.equal(targets.filter((t) => t.target_type === "snmp-target").length, 1);
    assert.equal(targets.filter((t) => t.target_type === "nmap-target").length, 2);
    for (const t of targets) {
      assert.deepEqual(JSON.parse(t.service_ports), []);
      assert.ok(!JSON.stringify(t).match(/snmp\.exe|Loopback|AXIOM\{/i));
    }
    const objectives = await svc.labObjectives(lab.id);
    assert.equal(objectives.length, 2);
    assert.ok(!("expected_value_hash" in objectives[0]), "hashes must never be served to clients");
    assert.equal((await svc.labHints(lab.id)).length, 3);
  });

  it("provisions an isolated range with .151 SNMP semantics", async function () {
    if (!haveSandbox) { console.log("  (skip: no sandbox)"); return; }
    const topo = await orch.nmapTopology(lab.id, "10.210.9.0/24");
    assert.equal(topo.subnet, "10.210.9.0/24");
    assert.equal(topo.attacker.ip, "10.210.9.2");
    assert.deepEqual(topo.boxes.map((b) => b.ip).sort(),
      ["10.210.9.11", "10.210.9.151", "10.210.9.22"]);
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

  it("real onesixtyone finds the only SNMP server; snmpwalk yields both answers (student path)", async function () {
    if (!haveSandbox || !await hostHas("onesixtyone") || !await hostHas("snmpwalk")) { console.log("  (skip: needs unshare + onesixtyone + snmpwalk)"); return; }
    const tmp = await svc.createInstance({ userId, labId: lab.id, provider: "local" });
    const details = await orch.provisionInstance({ lab, instance: { ...tmp, user_id: userId } });
    const iid = tmp.id;
    const inst = await activate(svc, db, lab, tmp, details);
    const base = details.networkCidr.split(".").slice(0, 3).join(".");
    const sh = (command) => orch.runTerminalCommand(inst, command, lab).then((r) => r.output);
    try {
      const scan = await sh(`printf 'public\\nprivate\\nmanager\\n' > communities.txt && onesixtyone -c communities.txt ${base}.0/24`);
      const responders = [...scan.matchAll(/(\d+\.\d+\.\d+\.\d+) \[public\]/g)].map((m) => m[1]);
      assert.deepEqual(responders, [`${base}.151`], "onesixtyone identifies exactly one SNMP server");
      const procs = await sh(`snmpwalk -c public -v1 ${base}.151 1.3.6.1.2.1.25.4.2.1.2`);
      assert.ok(procs.includes("snmp.exe"), "process table names the SNMP server process");
      const ifaces = await sh(`snmpwalk -c public -v1 -Oa ${base}.151 1.3.6.1.2.1.2.2.1.2`);
      const first = ifaces.split("\n").find((l) => l.includes("ifDescr.1"));
      assert.ok(first && first.includes("Software Loopback Interface 1"), "first interface is the loopback");
      for (const [key, ans] of [["snmp-process", "snmp.exe"], ["snmp-interface", "Software Loopback Interface 1"]]) {
        const r = await svc.submitAnswer({ userId, lab, objectiveKey: key, answer: ans, instanceId: iid });
        assert.ok(r.correct, `${key} completes from enumerated values`);
      }
      const p = await svc.labProgress(userId, lab.id);
      assert.ok(p.complete, "both objectives complete");
    } finally {
      await orch.destroyInstance(instRow(details, iid, lab.id));
      await svc.clearRuntimeFlags(iid).catch(() => {});
    }
  }, { timeout: 240000 });

  it("wrong community is silent; decoys answer nothing; wrong answers fail", async function () {
    if (!haveSandbox || !await hostHas("snmpwalk")) { console.log("  (skip: needs unshare + snmpwalk)"); return; }
    for (const [key, ans] of [["snmp-process", "snmpd"], ["snmp-process", "svchost.exe"], ["snmp-process", ""], ["snmp-interface", "Ethernet0"], ["snmp-interface", "lo"], ["snmp-interface", ""]]) {
      const r = await svc.submitAnswer({ userId, lab, objectiveKey: key, answer: ans, instanceId: "li_snmpx" });
      assert.ok(r.ok && !r.correct, `${key}=${JSON.stringify(ans)} must fail`);
    }
    const tmp = await svc.createInstance({ userId, labId: lab.id, provider: "local" });
    const details = await orch.provisionInstance({ lab, instance: { ...tmp, user_id: userId } });
    const iid = tmp.id;
    const inst = await activate(svc, db, lab, tmp, details);
    const base = details.networkCidr.split(".").slice(0, 3).join(".");
    const sh = (command) => orch.runTerminalCommand(inst, command, lab).then((r) => r.output);
    try {
      const bad = await sh(`snmpget -v1 -c private -t 2 -r 0 ${base}.151 1.3.6.1.2.1.1.1.0`);
      assert.ok(/Timeout|No Response/i.test(bad), "wrong community gets no response");
      for (const decoy of [`${base}.22`, `${base}.11`]) {
        const d = await sh(`snmpget -v1 -c public -t 2 -r 0 ${decoy} 1.3.6.1.2.1.1.1.0`);
        assert.ok(/Timeout|No Response/i.test(d), `decoy ${decoy} answers nothing on SNMP`);
      }
      const other = await sh(`snmpwalk -v1 -c public -t 3 -r 0 ${base}.22 1.3.6.1.2.1.25.4.2.1.2`);
      assert.ok(!/snmp\.exe/i.test(other), "no snmp.exe outside the intended host");
    } finally {
      await orch.destroyInstance(instRow(details, iid, lab.id));
      await svc.clearRuntimeFlags(iid).catch(() => {});
    }
  }, { timeout: 240000 });

  it("reset keeps deterministic answers; interface order is stable", async function () {
    if (!haveSandbox || !await hostHas("snmpwalk")) { console.log("  (skip: needs unshare + snmpwalk)"); return; }
    const tmp1 = await svc.createInstance({ userId, labId: lab.id, provider: "local" });
    const d1 = await orch.provisionInstance({ lab, instance: { ...tmp1, user_id: userId } });
    const iid = tmp1.id;
    const inst = await activate(svc, db, lab, tmp1, d1);
    const base = d1.networkCidr.split(".").slice(0, 3).join(".");
    const sh = (command) => orch.runTerminalCommand(inst, command, lab).then((r) => r.output);
    try {
      const w1 = await sh(`snmpwalk -c public -v1 -Oa ${base}.151 1.3.6.1.2.1.2.2.1.2`);
      await orch.destroyInstance(instRow(d1, iid, lab.id));
      await svc.clearRuntimeFlags(iid);
      const tmp2 = await svc.createInstance({ userId, labId: lab.id, provider: "local" });
      const d2 = await orch.provisionInstance({ lab, instance: { ...tmp2, user_id: userId } });
      const inst2 = await activate(svc, db, lab, tmp2, d2);
      const base2 = d2.networkCidr.split(".").slice(0, 3).join(".");
      const sh2 = (command) => orch.runTerminalCommand(inst2, command, lab).then((r) => r.output);
      const w2 = await sh2(`snmpwalk -c public -v1 -Oa ${base2}.151 1.3.6.1.2.1.2.2.1.2`);
      assert.equal(w2, w1, "fresh instance enumerates identically");
      await orch.destroyInstance(instRow(d2, tmp2.id, lab.id));
      await svc.clearRuntimeFlags(tmp2.id);
    } catch (e) {
      await orch.destroyInstance(instRow({ providerReference: "" }, iid, lab.id)).catch(() => {});
      await svc.clearRuntimeFlags(iid).catch(() => {});
      throw e;
    }
  }, { timeout: 240000 });

  it("never leaks answers through lab reads", async () => {
    for (const row of await svc.labTargets(lab.id)) {
      assert.ok(!JSON.stringify(row).match(/snmp\.exe|Loopback|AXIOM\{/i));
    }
    for (const row of await svc.labObjectives(lab.id)) {
      assert.ok(!JSON.stringify(row).match(/snmp\.exe|Loopback|AXIOM\{/i));
    }
    const labRow = await svc.getLab("slug", SLUG);
    assert.ok(!JSON.stringify(labRow).match(/snmp\.exe|Loopback|AXIOM\{/i));
    assert.ok(!JSON.stringify(await svc.hintsFor(userId, lab.id)).match(/snmp\.exe|Loopback/i));
  });
});

describe("snmp routes (http)", () => {
  const PORT = 3467;
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
      user = await createUser({ username: "snmphttp", email: "snmph@test.local", displayName: "SNMPH", password: "password12345" });
    } catch {
      user = await db.get(`SELECT * FROM users WHERE username=?`, ["snmphttp"]);
    }
    const r = await fetch(`${BASE}/login`, {
      method: "POST", redirect: "manual",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ identifier: "snmphttp", password: "password12345" }),
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

  it("workspace shows the range without process or interface answers", async () => {
    const r = await get(`/labs/oscp/${SLUG}`);
    assert.equal(r.status, 200);
    const html = await r.text();
    for (const crumb of ["6.3.6", "SNMP Enumeration", "Lab 1"]) assert.ok(html.includes(crumb), `missing: ${crumb}`);
    assert.ok(html.includes("kali"), "attacker shell framing present");
    assert.ok(!html.includes("snmp.exe"), "no process answer in HTML");
    assert.ok(!html.includes("Loopback Interface 1"), "no interface answer in HTML");
    assert.ok(!html.includes("AXIOM{"), "no flag material in HTML");
    for (const marker of ["Attacker Terminal", "Submit Answer", "Lab Progress", "Connection"]) assert.ok(html.includes(marker));
  });

  it("lab API redacts deployment internals from target listings", async () => {
    const j = await (await get(`/api/labs/${labId}`)).json();
    assert.equal(j.targets.length, 4);
    const blob = JSON.stringify(j.targets);
    assert.ok(!blob.includes("snmp.exe") && !blob.includes("Loopback"));
    assert.ok(!blob.includes("service_ports") && !blob.includes("metadata_json"), "internals redacted");
    assert.ok(blob.includes("Attacker"), "neutral names still served");
  });

  it("full lifecycle over HTTP with real enumeration", async function () {
    const orch = await import("../server/labs/orchestrator.js");
    if (!await orch.unshareAvailable() || !await hostHas("onesixtyone") || !await hostHas("snmpwalk")) { console.log("  (skip: needs sandbox + SNMP tools)"); return; }
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
    const scan = await sh(`printf 'public\\nprivate\\nmanager\\n' > communities.txt && onesixtyone -c communities.txt ${base}.0/24 | grep -c public`);
    assert.equal(scan.trim().split("\n").pop().trim(), "1", "onesixtyone finds one public SNMP server");
    const procs = await sh(`snmpwalk -c public -v1 ${base}.151 1.3.6.1.2.1.25.4.2.1.2 | grep -c snmp.exe`);
    assert.equal(procs.trim().split("\n").pop().trim(), "1");
    r = await postq(`/api/labs/${labId}/submit`, { answers: { "snmp-process": "snmpd" } });
    assert.equal((await r.json()).results["snmp-process"].correct, false);
    r = await postq(`/api/labs/${labId}/submit`, {
      answers: {
        "snmp-process": "snmp.exe",
        "snmp-interface": /Software Loopback Interface 1/.exec(await sh(`snmpwalk -c public -v1 -Oa ${base}.151 1.3.6.1.2.1.2.2.1.2 | grep ifDescr.1`))[0],
      },
    });
    const done = await r.json();
    assert.ok(Object.values(done.results).every((x) => x.correct));
    assert.ok(done.progress.complete);
    assert.equal(done.progress.objectiveDone, 2);
    r = await postq(`/api/labs/${labId}/reset`);
    assert.equal((await r.json()).instance.resetCount, 1);
    r = await postq(`/api/labs/${labId}/stop`);
    assert.equal((await r.json()).instance.status, "stopped");
    const st = await (await get(`/api/labs/${labId}/status`)).json();
    assert.ok(st.progress.complete, "completion survives stop");
  }, { timeout: 300000 });
});
