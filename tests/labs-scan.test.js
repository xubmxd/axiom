import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import net from "node:net";
import dgram from "node:dgram";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { spawn } from "node:child_process";

// Isolate: temp sqlite file + local provider before any server module loads.
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "axiom-labs-scan-"));
process.env.DATA_DIR = TMP;
process.env.LAB_PROVIDER = "local";

const REPO = path.resolve(import.meta.dirname, "..");
const SLUG = "m6-6-3-2-port-scanning";
const DEF = path.join(REPO, "labs/module-06/6.3.2-port-scanning/lab.json");
const run = promisify(execFile);

function readDef() {
  return JSON.parse(fs.readFileSync(DEF, "utf8"));
}

describe("scan definition", () => {
  it("loads as its own exercise under Module 6 (new 6.3.2 section)", async () => {
    const { loadAllDefinitions, validateDefinition, normalizePlacement } = await import("../server/labs/definitions.js");
    const all = loadAllDefinitions(path.join(REPO, "labs"));
    const lab = all.find((l) => l.def.slug === SLUG);
    assert.ok(lab, "6.3.2 lab.json must be discovered");
    assert.deepEqual(validateDefinition(lab.def), []);
    const p = normalizePlacement(lab.def);
    assert.equal(p.courseSlug, "oscp");
    assert.equal(p.moduleNumber, 6);
    assert.equal(p.moduleTitle, "Information Gathering");
    assert.equal(p.section, "6.3.2");
    assert.equal(p.sectionTitle, "TCP/UDP Port Scanning Theory");
    assert.equal(lab.def.labNumber, 1);
    assert.equal(lab.def.title, "6.3.2 TCP/UDP Port Scanning Theory");
    const sections = new Set(all.filter((l) => normalizePlacement(l.def).moduleNumber === 6).map((l) => normalizePlacement(l.def).section));
    assert.deepEqual([...sections].sort(), ["6.2.1", "6.2.2", "6.2.3", "6.2.4", "6.3.1", "6.3.2", "6.3.3", "6.3.4", "6.3.5", "6.3.6"]);
  });

  it("declares a scan target with no port answers in the definition", async () => {
    const def = readDef();
    assert.equal(def.environment.type, "single-target");
    assert.equal(def.targets.length, 1);
    assert.equal(def.targets[0].name, "Scan Target");
    assert.equal(def.targets[0].type, "scan-target");
    assert.equal(def.targets[0].os, "Linux");
    assert.deepEqual(def.targets[0].ports, []);
    assert.equal(def.targets[0].image, "axiom-lab-scan-632:latest");
    assert.equal(def.targets[0].build, "m6/scan-632");
    assert.ok(!("targetPort" in (def.environment || {})), "no primary-port hint in the definition");
  });

  it("has three hashed objectives and leaks no answers", async () => {
    const def = readDef();
    assert.equal(def.objectives.length, 3);
    assert.deepEqual(def.objectives.map((o) => o.key), ["lowest-tcp", "highest-tcp", "first-udp"]);
    for (const o of def.objectives) assert.match(o.expectedHash, /^[0-9a-f]{64}$/);
    const raw = fs.readFileSync(DEF, "utf8");
    assert.ok(!raw.includes("9389"), "highest port must not appear");
    assert.ok(!raw.replace(/10000/g, "").includes("161"), "UDP answer must not appear");
    assert.ok(!/\b53\b/.test(raw), "no standalone 53 in the definition");
    assert.ok(!/\b(88|135|139)\b/.test(raw), "no supporting-port disclosure");
  });

  it("stored hashes match the exercise's expected answers", async () => {
    const { verifyAnswer } = await import("../server/labs/answers.js");
    const def = readDef();
    const byKey = Object.fromEntries(def.objectives.map((o) => [o.key, o]));
    assert.ok(verifyAnswer("53", byKey["lowest-tcp"].expectedHash, "case-insensitive-exact"));
    assert.ok(verifyAnswer("9389", byKey["highest-tcp"].expectedHash, "case-insensitive-exact"));
    assert.ok(verifyAnswer("161", byKey["first-udp"].expectedHash, "case-insensitive-exact"));
  });

  it("carries six technique hints that reveal no ports", async () => {
    const def = readDef();
    assert.equal(def.hints.length, 6);
    const joined = JSON.stringify(def.hints);
    assert.ok(!joined.includes("9389") && !joined.replace(/10000/g, "").includes("161"));
    assert.ok(!/\b53\b/.test(joined), "hints must not name ports");
  });

  it("example commands use ranges, never answer ports", async () => {
    const def = readDef();
    const cmds = JSON.stringify(def.instructions.commands);
    assert.ok(cmds.includes("1-10000") && cmds.includes("100-200"), "exercise ranges are the methodology");
    assert.ok(!cmds.includes("9389") && !cmds.replace(/10000/g, "").includes("161"));
    assert.ok(!/\bnc .* 53\b|\bnc .* 161\b|\bnc .* 9389\b/.test(cmds), "no single answer port in examples");
  });
});

describe("scan target behavior", () => {
  it("accepts TCP on the five service ports and refuses the rest", async () => {
    const { startScanTarget } = await import("../server/labs/scan-target.js");
    const srv = await startScanTarget({ host: "127.0.0.1" });
    try {
      const probe = (port) => new Promise((resolve) => {
        const s = new net.Socket();
        const t = setTimeout(() => { s.destroy(); resolve("timeout"); }, 2000);
        s.on("error", (e) => { clearTimeout(t); resolve(e.code || "error"); });
        s.connect(srv.tcp[53] && port === "map" ? 0 : port, "127.0.0.1", () => { clearTimeout(t); s.destroy(); resolve("open"); });
      });
      for (const p of Object.values(srv.tcp)) assert.equal(await probe(p), "open");
      assert.equal(await probe(54), "ECONNREFUSED", "closed TCP refuses");
      assert.equal(await probe(9390), "ECONNREFUSED");
    } finally {
      await srv.close();
    }
  });

  it("replies on UDP 123/161 and refuses closed UDP ports", async () => {
    const { startScanTarget } = await import("../server/labs/scan-target.js");
    const srv = await startScanTarget({ host: "127.0.0.1" });
    const ask = (port) => new Promise((resolve) => {
      const sock = dgram.createSocket("udp4");
      const timer = setTimeout(() => { try { sock.close(); } catch {} resolve("silent"); }, 1500);
      sock.on("error", () => { clearTimeout(timer); try { sock.close(); } catch {} resolve("refused"); });
      sock.on("message", (m) => { clearTimeout(timer); try { sock.close(); } catch {} resolve(m); });
      sock.connect(port, "127.0.0.1", () => sock.send(Buffer.alloc(0), (e) => { if (e) { clearTimeout(timer); try { sock.close(); } catch {} resolve("refused"); } }));
    });
    try {
      const ntp = await ask(srv.udp[123]);
      assert.ok(Buffer.isBuffer(ntp) && ntp.length === 48 && (ntp[0] & 0x07) === 4, "NTP server-mode reply");
      const snmp = await ask(srv.udp[161]);
      assert.ok(Buffer.isBuffer(snmp) && snmp[0] === 0x30, "SNMP BER reply");
      assert.equal(await ask(124), "refused", "closed UDP refuses via ICMP");
      assert.equal(await ask(160), "refused");
    } finally {
      await srv.close();
    }
  });
});

describe("scan image wiring", () => {
  it("resolves the scan build context and ships a hardened image", async () => {
    const { resolveBuildContext } = await import("../server/labs/orchestrator.js");
    assert.equal(
      resolveBuildContext("axiom-lab-scan-632:latest", JSON.stringify({ build: "m6/scan-632" })),
      path.resolve(REPO, "lab-images/m6/scan-632"),
    );
    assert.equal(resolveBuildContext("axiom-lab-scan-632:latest", "{}"), path.resolve(REPO, "lab-images/m6/scan-632"));
    const dockerfile = fs.readFileSync(path.join(REPO, "lab-images/m6/scan-632/Dockerfile"), "utf8");
    assert.ok(dockerfile.includes("USER scantarget"), "target must not run as root");
    assert.ok(dockerfile.includes("53/tcp") && dockerfile.includes("161/udp"));
    assert.ok(dockerfile.includes("cap_net_bind_service"), "unprivileged bind needs the capability, not root");
    // The image spec necessarily names service ports (deployment data, never
    // served to browsers); what matters is no answer-adjacent content.
    assert.ok(!/password|flag|answer|geheim|secret/i.test(dockerfile), "no answer material in the image definition");
  });

  it("ships the exact server module (no drift between providers)", async () => {
    const a = fs.readFileSync(path.join(REPO, "server/labs/scan-target.js"), "utf8");
    const b = fs.readFileSync(path.join(REPO, "lab-images/m6/scan-632/scan-target.js"), "utf8");
    assert.equal(a, b, "scan-target.js copy must match the canonical module");
  });

  it("encodes and parses the loopback port map without port identities leaking order assumptions", async () => {
    const { encodeScanEndpoint, resolveScanPorts } = await import("../server/labs/orchestrator.js");
    const ep = encodeScanEndpoint("127.0.0.1", [32001, 32002, 32003, 32004, 32005], [32123, 32161]);
    const parsed = resolveScanPorts({ host_endpoint: ep });
    assert.equal(parsed.host, "127.0.0.1");
    assert.deepEqual([...parsed.tcp.entries()], [[53, 32001], [88, 32002], [135, 32003], [139, 32004], [9389, 32005]]);
    assert.deepEqual([...parsed.udp.entries()], [[123, 32123], [161, 32161]]);
    assert.equal(resolveScanPorts({ host_endpoint: "127.0.0.1:53" }), null, "whois form is not a scan map");
    assert.equal(resolveScanPorts({ host_endpoint: "" }), null);
  });
});

describe("scan service (sqlite) + local target", () => {
  let svc, db, orch, userId, lab;
  before(async () => {
    db = await import("../server/db.js");
    await db.initDb();
    svc = await import("../server/labs/service.js");
    orch = await import("../server/labs/orchestrator.js");
    const { createUser } = await import("../server/auth.js");
    const u = await createUser({ username: "scantester", email: "scan@test.local", displayName: "Scan", password: "password12345" });
    userId = u.id;
    await svc.seedFromDefinitions(path.join(REPO, "labs"));
    lab = await svc.getLab("slug", SLUG);
    assert.ok(lab);
  });

  it("seeds the scan target + three hash-only objectives + six hints", async () => {
    const targets = await svc.labTargets(lab.id);
    assert.equal(targets.length, 1);
    assert.equal(targets[0].target_type, "scan-target");
    assert.equal(JSON.parse(targets[0].metadata_json).build, "m6/scan-632");
    assert.deepEqual(JSON.parse(targets[0].service_ports), []);
    const objectives = await svc.labObjectives(lab.id);
    assert.equal(objectives.length, 3);
    assert.ok(!("expected_value_hash" in objectives[0]), "hashes must never be served to clients");
    assert.equal((await svc.labHints(lab.id)).length, 6);
  });

  it("provisions a .151 target with the full mapped port space", async () => {
    const local = orch.providerFor("local");
    const details = await local.provision(lab, { id: "li_scan1" });
    try {
      assert.ok(details.targetIp.endsWith(".151"), `display IP ends in .151, got ${details.targetIp}`);
      assert.ok(details.targetIp.startsWith("10."), "display IP stays RFC1918");
      assert.equal(details.targetPort, 53);
      const parsed = orch.resolveScanPorts({ host_endpoint: details.hostEndpoint });
      assert.ok(parsed, "host endpoint carries the port map");
      assert.equal(parsed.tcp.size, 5);
      assert.equal(parsed.udp.size, 2);
    } finally {
      await local.destroy({ id: "li_scan1" });
    }
  });

  it("real OpenBSD nc against the mapped ports matches terminal-nc semantics", async () => {
    const local = orch.providerFor("local");
    const details = await local.provision(lab, { id: "li_scannc" });
    try {
      const parsed = orch.resolveScanPorts({ host_endpoint: details.hostEndpoint });
      const nc = (...args) => run("nc", args, { timeout: 20000 }).then((r) => r.stdout + r.stderr);
      // one open TCP + one closed TCP, verbose
      const one = await nc("-vz", "-w1", "127.0.0.1", String(parsed.tcp.get(53)));
      assert.ok(one.includes("succeeded!"), "real nc sees the open TCP listener");
      const closedPort = String(parsed.tcp.get(88) + 500 > 65535 ? 61000 : parsed.tcp.get(88) + 500);
      const closed = await nc("-vz", "-w1", "127.0.0.1", closedPort).then(
        (r) => r, (e) => String((e.stdout || "") + (e.stderr || "")));
      assert.ok(!closed.includes("succeeded"), "real nc reports the closed TCP port as failed");
      // UDP open port replies; closed port refuses
      const udp = await nc("-vz", "-u", "-w1", "127.0.0.1", String(parsed.udp.get(161)));
      assert.ok(udp.includes("succeeded!"), "real nc sees the open UDP responder");
    } finally {
      await local.destroy({ id: "li_scannc" });
    }
  });

  it("terminal nc finds lowest 53 / highest 9389 over the full 1-10000 range", async () => {
    const local = orch.providerFor("local");
    const details = await local.provision(lab, { id: "li_scanterm" });
    try {
      const inst = { id: "li_scanterm", target_ip: details.targetIp, target_port: 53, host_endpoint: details.hostEndpoint, provider: "local", network_cidr: details.networkCidr };
      const open = await orch.runTerminalCommand(inst, `nc -vz -w1 ${details.targetIp} 1-10000`, lab);
      const hits = [...open.output.matchAll(/port \[tcp\/[^\]]+\] succeeded/g)].length;
      const ports = [...open.output.matchAll(/Connection to \S+ (\d+) port/g)].map((m) => parseInt(m[1], 10));
      assert.deepEqual([...ports].sort((a, b) => a - b), [53, 88, 135, 139, 9389]);
      assert.equal(Math.min(...ports), 53, "lowest open TCP is 53");
      assert.equal(Math.max(...ports), 9389, "highest open TCP in range is 9389");
      assert.equal(hits, 5);
      const single = await orch.runTerminalCommand(inst, `nc -vz ${details.targetIp} 53`, lab);
      assert.ok(single.output.includes("53 port [tcp/domain] succeeded!"));
      const closed = await orch.runTerminalCommand(inst, `nc -vz ${details.targetIp} 54`, lab);
      assert.ok(!closed.output.includes("succeeded"), "closed TCP stays silent without -v");
      const foreign = await orch.runTerminalCommand(inst, "nc -vz 8.8.8.8 53", lab);
      assert.ok(/not reachable/i.test(foreign.output), "external scans rejected");
      const evil = await orch.runTerminalCommand(inst, "rm -rf /", lab);
      assert.ok(/not available/i.test(evil.output));
      const t = await orch.runTerminalCommand(inst, "targets", lab);
      assert.ok(t.output.includes("Scan Target") && !t.output.includes("9389"), "targets hides the port list");
    } finally {
      await local.destroy({ id: "li_scanterm" });
    }
  }, { timeout: 120000 });

  it("terminal nc UDP scan honors the 123 exclusion and 161 ordering", async () => {
    const local = orch.providerFor("local");
    const details = await local.provision(lab, { id: "li_scanudp" });
    try {
      const inst = { id: "li_scanudp", target_ip: details.targetIp, target_port: 53, host_endpoint: details.hostEndpoint, provider: "local", network_cidr: details.networkCidr };
      const udp = await orch.runTerminalCommand(inst, `nc -vz -u -w1 ${details.targetIp} 100-200`, lab);
      const ports = [...udp.output.matchAll(/Connection to \S+ (\d+) port/g)].map((m) => parseInt(m[1], 10));
      assert.ok(ports.includes(123), "UDP 123 observable");
      assert.ok(ports.includes(161), "UDP 161 observable");
      const qualifying = ports.filter((p) => p !== 123 && p >= 100 && p <= 200);
      assert.deepEqual(qualifying, [161], "161 is the first qualifying result after excluding 123");
      assert.ok(!ports.some((p) => p >= 100 && p < 161 && p !== 123), "no interference between 100 and 161");
    } finally {
      await local.destroy({ id: "li_scanudp" });
    }
  }, { timeout: 120000 });

  it("rejects wrong answers (neighbors, blanks, the lab address)", async () => {
    const wrong = [
      ["lowest-tcp", "52"], ["lowest-tcp", "54"], ["lowest-tcp", "88"],
      ["lowest-tcp", ""], ["lowest-tcp", "   "],
      ["highest-tcp", "9388"], ["highest-tcp", "9390"], ["highest-tcp", "10000"],
      ["highest-tcp", ""], ["highest-tcp", "139"],
      ["first-udp", "123"], ["first-udp", "160"], ["first-udp", "162"],
      ["first-udp", "124"], ["first-udp", ""], ["first-udp", "   "],
    ];
    for (const [key, ans] of wrong) {
      const r = await svc.submitAnswer({ userId, lab, objectiveKey: key, answer: ans, instanceId: "li_scanx" });
      assert.ok(r.ok && !r.correct, `${key}=${JSON.stringify(ans)} must fail`);
    }
    const p = await svc.labProgress(userId, lab.id);
    assert.equal(p.objectiveDone, 0);
  });

  it("accepts correct answers with normalization; progress aggregates", async () => {
    const a = await svc.submitAnswer({ userId, lab, objectiveKey: "lowest-tcp", answer: " 53 ", instanceId: "li_scanx" });
    assert.ok(a.correct && a.completed);
    const b = await svc.submitAnswer({ userId, lab, objectiveKey: "highest-tcp", answer: "9389", instanceId: "li_scanx" });
    assert.ok(b.correct);
    const c = await svc.submitAnswer({ userId, lab, objectiveKey: "first-udp", answer: "161", instanceId: "li_scanx" });
    assert.ok(c.correct);
    const p = await svc.labProgress(userId, lab.id);
    assert.equal(p.objectiveDone, 3);
    assert.ok(p.complete);
    const mod = await svc.moduleProgress(userId, lab.course_id, 6);
    assert.deepEqual(mod, { total: 12, completed: 1 });
  });

  it("reset and stop recycle the target with identical port state", async () => {
    const local = orch.providerFor("local");
    const d1 = await local.provision(lab, { id: "li_scanreset" });
    assert.ok(d1.targetIp.endsWith(".151"));
    await local.destroy({ id: "li_scanreset", provider_reference: d1.providerReference, network_name: d1.networkName });
    const d2 = await local.provision(lab, { id: "li_scanreset" });
    try {
      assert.ok(d2.targetIp.endsWith(".151"));
      const inst = { id: "li_scanreset", target_ip: d2.targetIp, target_port: 53, host_endpoint: d2.hostEndpoint, provider: "local", network_cidr: d2.networkCidr };
      const open = await orch.runTerminalCommand(inst, `nc -z -w1 ${d2.targetIp} 1-10000`, lab);
      const ports = [...open.output.matchAll(/Connection to \S+ (\d+) port/g)].map((m) => parseInt(m[1], 10));
      assert.deepEqual([...ports].sort((a, b) => a - b), [53, 88, 135, 139, 9389]);
    } finally {
      await local.destroy({ id: "li_scanreset" });
    }
  }, { timeout: 120000 });

  it("never leaks answers through lab reads", async () => {
    for (const row of await svc.labTargets(lab.id)) {
      assert.ok(!/\b9389\b/.test(JSON.stringify(row)));
    }
    for (const row of await svc.labObjectives(lab.id)) {
      assert.ok(!/\b9389\b/.test(JSON.stringify(row)));
    }
    const labRow = await svc.getLab("slug", SLUG);
    assert.ok(!/\b9389\b/.test(JSON.stringify(labRow)));
    assert.ok(!/\b9389\b/.test(JSON.stringify(await svc.labProgress(userId, lab.id))));
    const scanHints = await svc.hintsFor(userId, lab.id);
    assert.ok(!scanHints.map((h) => `${h.title} ${h.body || ""}`).join(" ").includes("9389"));
    const rawDef = fs.readFileSync(DEF, "utf8");
    assert.ok(!rawDef.includes("9389") && !rawDef.replace(/10000/g, "").includes("161") && !/\b53\b/.test(rawDef));
  });
});

describe("scan routes (http)", () => {
  const PORT = 3463;
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
      user = await createUser({ username: "scanhttp", email: "sh@test.local", displayName: "SH", password: "password12345" });
    } catch {
      user = await db.get(`SELECT * FROM users WHERE username=?`, ["scanhttp"]);
    }
    const r = await fetch(`${BASE}/login`, {
      method: "POST", redirect: "manual",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ identifier: "scanhttp", password: "password12345" }),
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

  it("workspace shows the .151 target and scan guidance without port answers", async () => {
    const r = await get(`/labs/oscp/${SLUG}`);
    assert.equal(r.status, 200);
    const html = await r.text();
    for (const crumb of ["6.3.2", "TCP/UDP Port Scanning Theory", "Lab 1"]) assert.ok(html.includes(crumb), `missing: ${crumb}`);
    assert.ok(html.includes("ends in .151"), "target discovery framing present");
    assert.ok(html.includes("nc -vz"), "Netcat guidance present");
    assert.ok(!/\b9389\b/.test(html), "no highest-port answer in HTML");
    assert.ok(!/\b161\b/.test(html.replace(/10000/g, "")), "no UDP answer in HTML");
    assert.ok(!/\b53\b/.test(html.replace(/<TARGET-IP>/g, "")), "no lowest-port answer in HTML");
    for (const marker of ["Lab Terminal", "Submit Answer", "Lab Progress", "Connection"]) assert.ok(html.includes(marker));
  });

  it("DNS workspace keeps its exact connection UI (regression)", async () => {
    const r = await get(`/labs/oscp/m6-6-3-1-dns-enumeration`);
    assert.equal(r.status, 200);
    const html = await r.text();
    assert.ok(html.includes("53/udp"), "DNS ports UI intact");
    assert.ok(!html.includes("nc -vz"), "no Netcat leakage into the DNS lab");
  });

  it("full lifecycle over HTTP: start → scan → submit → reset → stop", async () => {
    const postq = (p, body) => fetch(`${BASE}${p}`, {
      method: "POST", headers: { Cookie: cookie, "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    });
    let r = await postq(`/api/labs/${labId}/start`);
    assert.equal(r.status, 200);
    let started = await r.json();
    assert.equal(started.instance.status, "running");
    assert.ok(started.instance.targetIp.endsWith(".151"), "display IP ends in .151");
    assert.ok(started.instance.targetIp.startsWith("10."));
    const orch = await import("../server/labs/orchestrator.js");
    const svc = await import("../server/labs/service.js");
    const labRow = await svc.getLab("slug", SLUG);
    const t = await orch.runTerminalCommand(
      { ...started.instance, target_ip: started.instance.targetIp, host_endpoint: started.instance.hostEndpoint },
      `nc -vz -w1 ${started.instance.targetIp} 1-1000`, labRow);
    const ports = [...t.output.matchAll(/Connection to \S+ (\d+) port/g)].map((m) => parseInt(m[1], 10));
    assert.deepEqual([...ports].sort((a, b) => a - b), [53, 88, 135, 139], "1-1000 sweep finds the four low ports");
    r = await postq(`/api/labs/${labId}/submit`, { answers: { "lowest-tcp": "88" } });
    assert.equal((await r.json()).results["lowest-tcp"].correct, false);
    r = await postq(`/api/labs/${labId}/submit`, {
      answers: { "lowest-tcp": "53", "highest-tcp": "9389", "first-udp": "161" },
    });
    const done = await r.json();
    assert.ok(Object.values(done.results).every((x) => x.correct));
    assert.ok(done.progress.complete);
    assert.equal(done.progress.objectiveDone, 3);
    r = await postq(`/api/labs/${labId}/reset`);
    assert.equal((await r.json()).instance.resetCount, 1);
    r = await postq(`/api/labs/${labId}/stop`);
    assert.equal((await r.json()).instance.status, "stopped");
    const st = await (await get(`/api/labs/${labId}/status`)).json();
    assert.ok(st.progress.complete, "completion survives stop");
  }, { timeout: 120000 });
});
