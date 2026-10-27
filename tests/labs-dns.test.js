import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { spawn } from "node:child_process";

// Isolate: temp sqlite file + local provider before any server module loads.
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "axiom-labs-dns-"));
process.env.DATA_DIR = TMP;
process.env.LAB_PROVIDER = "local";

const REPO = path.resolve(import.meta.dirname, "..");
const SLUG = "m6-6-3-1-dns-enumeration";
const DEF = path.join(REPO, "labs/module-06/6.3.1-dns/lab.json");
const run = promisify(execFile);

function readDef() {
  return JSON.parse(fs.readFileSync(DEF, "utf8"));
}

describe("dns definition", () => {
  it("loads as its own exercise under Module 6 (new 6.3.1 section)", async () => {
    const { loadAllDefinitions, validateDefinition, normalizePlacement } = await import("../server/labs/definitions.js");
    const all = loadAllDefinitions(path.join(REPO, "labs"));
    const lab = all.find((l) => l.def.slug === SLUG);
    assert.ok(lab, "6.3.1 lab.json must be discovered");
    assert.deepEqual(validateDefinition(lab.def), []);
    const p = normalizePlacement(lab.def);
    assert.equal(p.courseSlug, "oscp");
    assert.equal(p.moduleNumber, 6);
    assert.equal(p.moduleTitle, "Information Gathering");
    assert.equal(p.section, "6.3.1");
    assert.equal(p.sectionTitle, "DNS Enumeration");
    assert.equal(lab.def.labNumber, 1);
    assert.equal(lab.def.title, "6.3.1 DNS Enumeration");
    const sections = new Set(all.filter((l) => normalizePlacement(l.def).moduleNumber === 6).map((l) => normalizePlacement(l.def).section));
    assert.deepEqual([...sections].sort(), ["6.2.1", "6.2.2", "6.2.3", "6.2.4", "6.3.1", "6.3.2", "6.3.3", "6.3.4", "6.3.5", "6.3.6"]);
  });

  it("declares a single-target UDP+TCP/53 DNS target", async () => {
    const def = readDef();
    assert.equal(def.environment.type, "single-target");
    assert.equal(def.environment.targetPort, 53);
    assert.equal(def.targets.length, 1);
    assert.equal(def.targets[0].name, "DNS Server");
    assert.equal(def.targets[0].type, "dns-server");
    assert.equal(def.targets[0].os, "Linux");
    assert.deepEqual(def.targets[0].ports, [53]);
    assert.equal(def.targets[0].image, "axiom-lab-dns-631:latest");
    assert.equal(def.targets[0].build, "m6/dns-631");
  });

  it("has four hashed objectives and leaks no answers", async () => {
    const def = readDef();
    assert.equal(def.objectives.length, 4);
    assert.deepEqual(def.objectives.map((o) => o.key), ["mx-priority", "txt-count", "siem-ip", "walkthrough-txt"]);
    for (const o of def.objectives) assert.match(o.expectedHash, /^[0-9a-f]{64}$/);
    const raw = fs.readFileSync(DEF, "utf8");
    assert.ok(!raw.includes("51.222.169.215"), "siem IP must not appear in plaintext");
    assert.ok(!raw.toLowerCase().includes("greetings from the txt"), "walkthrough text must not appear");
    assert.ok(!/"\s*20\s*"|[^\d]20[^\d.]/.test(raw.replace(/2-digit/g, "")), "MX answer must not appear");
  });

  it("stored hashes match the exercise's expected answers", async () => {
    const { verifyAnswer } = await import("../server/labs/answers.js");
    const def = readDef();
    const byKey = Object.fromEntries(def.objectives.map((o) => [o.key, o]));
    assert.ok(verifyAnswer("20", byKey["mx-priority"].expectedHash, "case-insensitive-exact"));
    assert.ok(verifyAnswer("2", byKey["txt-count"].expectedHash, "case-insensitive-exact"));
    assert.ok(verifyAnswer("51.222.169.215", byKey["siem-ip"].expectedHash, "case-insensitive-exact"));
    assert.ok(verifyAnswer("greetings from the TXT record body", byKey["walkthrough-txt"].expectedHash, "case-insensitive-exact"));
  });

  it("carries six progressive hints that reveal technique, not answers", async () => {
    const def = readDef();
    assert.equal(def.hints.length, 6);
    const joined = JSON.stringify(def.hints);
    assert.ok(!joined.includes("51.222.169.215") && !joined.toLowerCase().includes("greetings from the txt"));
    assert.ok(!/"\s*20\s*"|[^\d]20[^\d.]/.test(joined.replace(/2-digit/g, "")));
  });
});

describe("dns zone dataset", () => {
  it("encodes the exercise-critical facts", async () => {
    const { DNS_ZONES } = await import("../server/labs/dns-zones.js");
    const apex = DNS_ZONES["megacorpone.com"].filter((r) => r.name === "@");
    const prefs = apex.filter((r) => r.type === "MX").map((r) => r.data.preference).sort((a, b) => a - b);
    assert.deepEqual(prefs, [10, 20, 30]);
    assert.deepEqual([...prefs].sort((a, b) => a - b).slice(0, 2), [10, 20]);
    assert.equal(apex.filter((r) => r.type === "TXT").length, 2);
    assert.equal(DNS_ZONES["megacorpone.com"].find((r) => r.name === "siem" && r.type === "A").data, "51.222.169.215");
    assert.equal(DNS_ZONES["megacorptwo.com"].find((r) => r.name === "info" && r.type === "TXT").data[0], "greetings from the TXT record body");
    assert.ok(apex.some((r) => r.type === "SOA") && apex.filter((r) => r.type === "NS").length === 3);
  });

  it("resolves questions purely: answers, NXDOMAIN, NODATA, REFUSED", async () => {
    const { resolveQuestion } = await import("../server/labs/dns-server.js");
    const mx = resolveQuestion("megacorpone.com", "MX");
    assert.equal(mx.rcode, 0);
    assert.deepEqual(mx.answers.map((a) => a.data.preference).sort((a, b) => a - b), [10, 20, 30]);
    assert.ok(mx.additional.length >= 3, "MX glue rides along");
    assert.equal(resolveQuestion("megacorpone.com", "TXT").answers.length, 2);
    assert.equal(resolveQuestion("siem.megacorpone.com", "A").answers[0].data, "51.222.169.215");
    assert.equal(resolveQuestion("WWW.MEGACORPONE.COM", "A").answers[0].data, "192.0.2.80", "case-insensitive");
    assert.equal(resolveQuestion("nope.megacorpone.com", "A").rcode, 3);
    assert.ok(resolveQuestion("nope.megacorpone.com", "A").authority.length, "NXDOMAIN carries SOA");
    const nodata = resolveQuestion("megacorpone.com", "AAAA");
    assert.equal(nodata.rcode, 0);
    assert.equal(nodata.answers.length, 0);
    assert.equal(resolveQuestion("example.com", "A").rcode, 5, "out-of-zone refused");
    assert.equal(resolveQuestion("megacorpone.com", "AXFR").rcode, 5, "zone transfers refused");
    assert.ok(resolveQuestion("megacorpone.com", "ANY").answers.length >= 7, "ANY returns the apex set");
  });
});

describe("dns image wiring", () => {
  it("resolves the dns build context and ships a hardened image", async () => {
    const { resolveBuildContext } = await import("../server/labs/orchestrator.js");
    assert.equal(
      resolveBuildContext("axiom-lab-dns-631:latest", JSON.stringify({ build: "m6/dns-631" })),
      path.resolve(REPO, "lab-images/m6/dns-631"),
    );
    assert.equal(resolveBuildContext("axiom-lab-dns-631:latest", "{}"), path.resolve(REPO, "lab-images/m6/dns-631"));
    const dockerfile = fs.readFileSync(path.join(REPO, "lab-images/m6/dns-631/Dockerfile"), "utf8");
    assert.ok(dockerfile.includes("USER dns"), "target must not run as root");
    assert.ok(dockerfile.includes("53/udp") && dockerfile.includes("53/tcp"));
    assert.ok(dockerfile.includes("cap_net_bind_service"), "unprivileged bind to 53 needs the capability, not root");
  });

  it("ships the exact server modules (no drift between providers)", async () => {
    for (const f of ["dns-server.js", "dns-zones.js"]) {
      const a = fs.readFileSync(path.join(REPO, "server/labs", f), "utf8");
      const b = fs.readFileSync(path.join(REPO, "lab-images/m6/dns-631", f), "utf8");
      assert.equal(a, b, `${f} copy must match the canonical module`);
    }
  });
});

describe("dns service (sqlite) + local target", () => {
  let svc, db, orch, userId, lab;
  before(async () => {
    db = await import("../server/db.js");
    await db.initDb();
    svc = await import("../server/labs/service.js");
    orch = await import("../server/labs/orchestrator.js");
    const { createUser } = await import("../server/auth.js");
    const u = await createUser({ username: "dnstester", email: "dns@test.local", displayName: "DNS", password: "password12345" });
    userId = u.id;
    await svc.seedFromDefinitions(path.join(REPO, "labs"));
    lab = await svc.getLab("slug", SLUG);
    assert.ok(lab);
  });

  it("seeds the dns target + four hash-only objectives + six hints", async () => {
    const targets = await svc.labTargets(lab.id);
    assert.equal(targets.length, 1);
    assert.equal(targets[0].target_type, "dns-server");
    assert.equal(JSON.parse(targets[0].metadata_json).build, "m6/dns-631");
    assert.deepEqual(JSON.parse(targets[0].service_ports), [53]);
    const objectives = await svc.labObjectives(lab.id);
    assert.equal(objectives.length, 4);
    assert.ok(!("expected_value_hash" in objectives[0]), "hashes must never be served to clients");
    assert.equal((await svc.labHints(lab.id)).length, 6);
  });

  it("provisions a real UDP+TCP/53 target with an RFC1918 display IP", async () => {
    const local = orch.providerFor("local");
    const details = await local.provision(lab, { id: "li_dns1" });
    try {
      assert.ok(details.targetIp.startsWith("10."), "display IP stays RFC1918");
      assert.notEqual(details.targetIp, "51.222.169.215", "answer data is never the target address");
      assert.equal(details.targetPort, 53);
      assert.match(details.hostEndpoint, /^127\.0\.0\.1:\d+$/);
      const { dnsQuery } = await import("../server/labs/dns-client.js");
      const port = parseInt(details.hostEndpoint.split(":")[1], 10);
      const udp = await dnsQuery("127.0.0.1", port, "megacorpone.com", "MX");
      assert.equal(udp.answers.length, 3);
      const tcp = await dnsQuery("127.0.0.1", port, "megacorpone.com", "MX", { tcp: true });
      assert.equal(tcp.answers.length, 3);
    } finally {
      await local.destroy({ id: "li_dns1" });
    }
  });

  it("answers system dig over the provisioned endpoint (real tool, real protocol)", async () => {
    const local = orch.providerFor("local");
    const details = await local.provision(lab, { id: "li_dnsdig" });
    try {
      const port = details.hostEndpoint.split(":")[1];
      const at = (...args) => run("dig", [`@127.0.0.1`, "-p", port, ...args, "+short"], { timeout: 15000 }).then((r) => r.stdout);
      assert.deepEqual((await at("megacorpone.com", "MX")).trim().split("\n").map((l) => parseInt(l.split(" ")[0], 10)).sort((a, b) => a - b), [10, 20, 30]);
      assert.equal((await at("megacorpone.com", "TXT")).trim().split("\n").length, 2);
      assert.equal((await at("siem.megacorpone.com", "A")).trim(), "51.222.169.215");
      assert.equal((await at("info.megacorptwo.com", "TXT")).trim(), '"greetings from the TXT record body"');
      assert.equal((await at("megacorpone.com", "MX", "+tcp")).trim().split("\n").length, 3, "TCP transport works");
    } finally {
      await local.destroy({ id: "li_dnsdig" });
    }
    await assert.rejects(run("dig", ["@127.0.0.1", "-p", details.hostEndpoint.split(":")[1], "megacorpone.com", "MX", "+short", "+time=1", "+tries=1"], { timeout: 8000 }), "endpoint dies with the instance");
  });

  it("terminal dig/host/nslookup/dnsenum run live queries with correct scoping", async () => {
    const local = orch.providerFor("local");
    const details = await local.provision(lab, { id: "li_dnsterm" });
    try {
      const inst = { id: "li_dnsterm", target_ip: details.targetIp, target_port: 53, host_endpoint: details.hostEndpoint, provider: "local", network_cidr: details.networkCidr };
      const dig = await orch.runTerminalCommand(inst, `dig @${details.targetIp} megacorpone.com MX`, lab);
      assert.ok(dig.output.includes("status: NOERROR") && dig.output.includes("20 mail2.megacorpone.com."), "dig shows the live MX set");
      const short = await orch.runTerminalCommand(inst, "dig megacorpone.com TXT +short", lab);
      assert.equal(short.output.trim().split("\n").length, 2);
      const tcp = await orch.runTerminalCommand(inst, "dig megacorpone.com MX +tcp", lab);
      assert.ok(tcp.output.includes("(TCP)"));
      const foreign = await orch.runTerminalCommand(inst, "dig @8.8.8.8 megacorpone.com MX", lab);
      assert.ok(/not reachable/i.test(foreign.output), "external servers rejected");
      const ns = await orch.runTerminalCommand(inst, `nslookup -type=TXT info.megacorptwo.com ${details.targetIp}`, lab);
      assert.ok(ns.output.includes('text = "greetings from the TXT record body"'));
      const host = await orch.runTerminalCommand(inst, "host -t MX megacorpone.com", lab);
      assert.ok(host.output.includes("mail is handled by 20 mail2.megacorpone.com."));
      const e = await orch.runTerminalCommand(inst, `dnsenum --dnsserver ${details.targetIp} megacorpone.com`, lab);
      assert.ok(e.output.includes("51.222.169.215"), "bruteforce discovers siem from live queries");
      assert.ok(/refused/i.test(e.output), "AXFR refusal reported honestly");
      const t = await orch.runTerminalCommand(inst, "targets", lab);
      assert.ok(t.output.includes("DNS Server") && t.output.includes("53/udp+tcp (dns)"));
      const w = await orch.runTerminalCommand(inst, "whois megacorpone.com", lab);
      assert.ok(/No WHOIS service/i.test(w.output));
      const evil = await orch.runTerminalCommand(inst, "rm -rf /", lab);
      assert.ok(/not available/i.test(evil.output));
    } finally {
      await local.destroy({ id: "li_dnsterm" });
    }
  });

  it("survives malformed input, concurrency, and unknown names", async () => {
    const { startDnsServer } = await import("../server/labs/dns-server.js");
    const { dnsQuery } = await import("../server/labs/dns-client.js");
    const srv = await startDnsServer({ host: "127.0.0.1", port: 0 });
    try {
      const dgram = await import("node:dgram");
      const sock = dgram.createSocket("udp4");
      await new Promise((res, rej) => {
        sock.send(Buffer.from([0x00, 0x01, 0xff]), srv.port, "127.0.0.1", (e) => (e ? rej(e) : res()));
        setTimeout(res, 300);
      });
      sock.close();
      const batch = await Promise.all(Array.from({ length: 25 }, (_, i) =>
        dnsQuery("127.0.0.1", srv.port, i % 2 ? "megacorpone.com" : "siem.megacorpone.com", i % 2 ? "MX" : "A")));
      assert.equal(batch.length, 25);
      assert.ok(batch.every((r) => r.rcode === 0 && r.answers.length > 0), "server stays healthy");
      const nx = await dnsQuery("127.0.0.1", srv.port, "ghost.megacorpone.com", "A");
      assert.equal(nx.rcode, 3);
    } finally {
      await srv.close();
    }
  });

  it("rejects wrong answers (including the lab address and off-by-ones)", async () => {
    const wrong = [
      ["mx-priority", "10"], ["mx-priority", "30"], ["mx-priority", "2"],
      ["mx-priority", ""], ["mx-priority", "   "],
      ["txt-count", "1"], ["txt-count", "3"], ["txt-count", ""],
      ["siem-ip", "10.200.9.10"], ["siem-ip", "51.222.169.214"], ["siem-ip", "51.222.169.216"],
      ["siem-ip", "192.0.2.80"], ["siem-ip", ""],
      ["walkthrough-txt", "greetings"], ["walkthrough-txt", "hello from the txt record"],
      ["walkthrough-txt", ""],
    ];
    for (const [key, ans] of wrong) {
      const r = await svc.submitAnswer({ userId, lab, objectiveKey: key, answer: ans, instanceId: "li_dnsx" });
      assert.ok(r.ok && !r.correct, `${key}=${JSON.stringify(ans)} must fail`);
    }
    const p = await svc.labProgress(userId, lab.id);
    assert.equal(p.objectiveDone, 0);
  });

  it("accepts correct answers with normalization; progress aggregates", async () => {
    const a = await svc.submitAnswer({ userId, lab, objectiveKey: "mx-priority", answer: " 20 ", instanceId: "li_dnsx" });
    assert.ok(a.correct && a.completed);
    const b = await svc.submitAnswer({ userId, lab, objectiveKey: "txt-count", answer: "2", instanceId: "li_dnsx" });
    assert.ok(b.correct);
    const c = await svc.submitAnswer({ userId, lab, objectiveKey: "siem-ip", answer: "51.222.169.215", instanceId: "li_dnsx" });
    assert.ok(c.correct);
    const d = await svc.submitAnswer({ userId, lab, objectiveKey: "walkthrough-txt", answer: "GREETINGS FROM THE TXT RECORD BODY", instanceId: "li_dnsx" });
    assert.ok(d.correct, "sensible case differences normalize");
    const p = await svc.labProgress(userId, lab.id);
    assert.equal(p.objectiveDone, 4);
    assert.ok(p.complete);
    const mod = await svc.moduleProgress(userId, lab.course_id, 6);
    assert.deepEqual(mod, { total: 12, completed: 1 });
  });

  it("reset and stop recycle the target with a clean identical dataset", async () => {
    const local = orch.providerFor("local");
    const d1 = await local.provision(lab, { id: "li_dnsreset" });
    const { dnsQuery } = await import("../server/labs/dns-client.js");
    const p1 = d1.hostEndpoint.split(":")[1];
    assert.equal((await dnsQuery("127.0.0.1", parseInt(p1, 10), "siem.megacorpone.com", "A")).answers[0].data, "51.222.169.215");
    await local.destroy({ id: "li_dnsreset", provider_reference: d1.providerReference, network_name: d1.networkName });
    await assert.rejects(dnsQuery("127.0.0.1", parseInt(p1, 10), "siem.megacorpone.com", "A", { timeoutMs: 1500 }), "destroyed target goes silent");
    const d2 = await local.provision(lab, { id: "li_dnsreset" });
    try {
      const p2 = d2.hostEndpoint.split(":")[1];
      assert.equal((await dnsQuery("127.0.0.1", parseInt(p2, 10), "siem.megacorpone.com", "A")).answers[0].data, "51.222.169.215");
      assert.equal((await dnsQuery("127.0.0.1", parseInt(p2, 10), "megacorpone.com", "TXT")).answers.length, 2);
    } finally {
      await local.destroy({ id: "li_dnsreset" });
    }
  });

  it("never leaks answers through lab reads", async () => {
    for (const row of await svc.labTargets(lab.id)) {
      assert.ok(!JSON.stringify(row).includes("51.222.169.215"));
    }
    for (const row of await svc.labObjectives(lab.id)) {
      assert.ok(!JSON.stringify(row).includes("51.222.169.215"));
    }
    const labRow = await svc.getLab("slug", SLUG);
    assert.ok(!JSON.stringify(labRow).includes("51.222.169.215"));
    assert.ok(!JSON.stringify(await svc.labProgress(userId, lab.id)).includes("51.222.169.215"));
    assert.ok(!JSON.stringify(await svc.hintsFor(userId, lab.id)).includes("51.222.169.215"));
    const rawDef = fs.readFileSync(DEF, "utf8");
    assert.ok(!rawDef.includes("51.222.169.215") && !rawDef.toLowerCase().includes("greetings from the txt"));
  });
});

describe("dns routes (http)", () => {
  const PORT = 3462;
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
      user = await createUser({ username: "dnshttp", email: "dnsh@test.local", displayName: "DNSH", password: "password12345" });
    } catch {
      user = await db.get(`SELECT * FROM users WHERE username=?`, ["dnshttp"]);
    }
    const r = await fetch(`${BASE}/login`, {
      method: "POST", redirect: "manual",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ identifier: "dnshttp", password: "password12345" }),
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

  it("workspace shows the DNS target, dig guidance, and leaks nothing", async () => {
    const r = await get(`/labs/oscp/${SLUG}`);
    assert.equal(r.status, 200);
    const html = await r.text();
    for (const crumb of ["6.3.1", "DNS Enumeration", "Lab 1"]) assert.ok(html.includes(crumb), `missing: ${crumb}`);
    assert.ok(html.includes("53/udp"), "DNS ports advertised");
    assert.ok(html.includes("dig @"), "dig guidance present");
    assert.ok(html.includes("dnsenum --dnsserver"), "automation guidance present");
    assert.ok(!html.includes("51.222.169.215"), "no answer IP in HTML");
    assert.ok(!html.toLowerCase().includes("greetings from the txt"), "no walkthrough text in HTML");
    for (const marker of ["Lab Terminal", "Submit Answer", "Lab Progress", "Connection"]) assert.ok(html.includes(marker));
  });

  it("whois workspaces keep their exact connection UI (regression)", async () => {
    const r = await get(`/labs/oscp/m6-6-2-1-whois-vm1`);
    assert.equal(r.status, 200);
    const html = await r.text();
    assert.ok(html.includes("43/tcp (whois)"));
    assert.ok(!html.includes("53/udp"), "no DNS leakage into WHOIS labs");
  });

  it("full lifecycle over HTTP: start → enumerate → submit → reset → stop", async () => {
    const postq = (p, body) => fetch(`${BASE}${p}`, {
      method: "POST", headers: { Cookie: cookie, "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    });
    let r = await postq(`/api/labs/${labId}/start`);
    assert.equal(r.status, 200);
    let started = await r.json();
    assert.equal(started.instance.status, "running");
    assert.ok(started.instance.targetIp.startsWith("10."));
    assert.equal(started.instance.targetPort, 53);
    // terminal enumeration over the same live path
    const orch = await import("../server/labs/orchestrator.js");
    const svc = await import("../server/labs/service.js");
    const labRow = await svc.getLab("slug", SLUG);
    const ep = await orch.resolveDnsEndpoint({ target_ip: started.instance.targetIp, target_port: 53, host_endpoint: started.instance.hostEndpoint });
    assert.ok(ep.udpPort > 0 && ep.tcpPort > 0, "both transports mapped");
    const t = await orch.runTerminalCommand(
      { ...started.instance, target_ip: started.instance.targetIp, host_endpoint: started.instance.hostEndpoint },
      "dnsenum megacorpone.com", labRow);
    assert.ok(t.output.includes("51.222.169.215"), "terminal automation discovers siem");
    // wrong rejected, right accepted
    r = await postq(`/api/labs/${labId}/submit`, { answers: { "mx-priority": "10" } });
    assert.equal((await r.json()).results["mx-priority"].correct, false);
    r = await postq(`/api/labs/${labId}/submit`, {
      answers: {
        "mx-priority": "20", "txt-count": "2",
        "siem-ip": "51.222.169.215", "walkthrough-txt": "greetings from the TXT record body",
      },
    });
    const done = await r.json();
    assert.ok(Object.values(done.results).every((x) => x.correct));
    assert.ok(done.progress.complete);
    assert.equal(done.progress.objectiveDone, 4);
    r = await postq(`/api/labs/${labId}/reset`);
    assert.equal((await r.json()).instance.resetCount, 1);
    r = await postq(`/api/labs/${labId}/stop`);
    assert.equal((await r.json()).instance.status, "stopped");
    const st = await (await get(`/api/labs/${labId}/status`)).json();
    assert.ok(st.progress.complete, "completion survives stop");
  }, { timeout: 60000 });
});
