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
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "axiom-labs-smb-"));
process.env.DATA_DIR = TMP;
process.env.LAB_PROVIDER = "local";

const REPO = path.resolve(import.meta.dirname, "..");
const SLUG = "m6-6-3-4-smb";
const DEF = path.join(REPO, "labs/module-06/6.3.4-smb/lab.json");
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

describe("smb definition", () => {
  it("loads as its own exercise under Module 6 (new 6.3.4 section)", async () => {
    const { loadAllDefinitions, validateDefinition, normalizePlacement } = await import("../server/labs/definitions.js");
    const all = loadAllDefinitions(path.join(REPO, "labs"));
    const lab = all.find((l) => l.def.slug === SLUG);
    assert.ok(lab, "6.3.4 lab.json must be discovered");
    assert.deepEqual(validateDefinition(lab.def), []);
    const p = normalizePlacement(lab.def);
    assert.equal(p.courseSlug, "oscp");
    assert.equal(p.moduleNumber, 6);
    assert.equal(p.moduleTitle, "Information Gathering");
    assert.equal(p.section, "6.3.4");
    assert.equal(p.sectionTitle, "SMB Enumeration");
    assert.equal(lab.def.labNumber, 1);
    assert.equal(lab.def.title, "6.3.4 SMB Enumeration");
    const sections = new Set(all.filter((l) => normalizePlacement(l.def).moduleNumber === 6).map((l) => normalizePlacement(l.def).section));
    assert.deepEqual([...sections].sort(), ["6.2.1", "6.2.2", "6.2.3", "6.2.4", "6.3.1", "6.3.2", "6.3.3", "6.3.4", "6.3.5", "6.3.6"]);
  });

  it("declares an attacker, ten SMB targets, and two non-SMB decoys", async () => {
    const def = readDef();
    assert.equal(def.environment.type, "multi-target");
    assert.equal(def.targets.length, 13);
    const byType = {};
    for (const t of def.targets) byType[t.type] = (byType[t.type] || 0) + 1;
    assert.equal(byType.attacker, 1, "attacker shell box present");
    assert.equal(byType["smb-target"], 10, "ten SMB servers for the 445 count");
    assert.equal(byType["nmap-target"], 2, "two decoys without SMB");
    for (const t of def.targets) {
      assert.ok(t.name && t.image && t.build, "each target needs name/image/build");
      assert.deepEqual(t.ports, [], "no service ports in the definition");
    }
    const smbRoles = def.targets.filter((t) => t.type === "smb-target").map((t) => t.metadata?.role).sort();
    assert.deepEqual(smbRoles, ["smb", "smb", "smb", "smb", "smb", "smb", "smb", "smb", "smb-alfred", "smb-dc"]);
    const smbSuffixes = def.targets.filter((t) => t.type === "smb-target").map((t) => t.metadata?.ipSuffix).sort((a, b) => a - b);
    assert.deepEqual(smbSuffixes, [11, 12, 13, 14, 15, 16, 60, 61, 62, 151]);
    const alfred = def.targets.find((t) => t.metadata?.role === "smb-alfred");
    assert.equal(alfred.metadata.ipSuffix, 61);
    const dc = def.targets.find((t) => t.metadata?.role === "smb-dc");
    assert.equal(dc.metadata.ipSuffix, 151);
    assert.equal(dc.hostname, "dc01");
    // Topic Exercise group is designated but the alfred host is not named.
    const topic = def.targets.filter((t) => /^Topic Exercise/.test(t.name));
    assert.equal(topic.length, 3);
    for (const t of def.targets) {
      assert.ok(!/alfred|ADMIN\$|flag/i.test(t.name), "names stay neutral about answers");
    }
  });

  it("has three objectives: count, shares, runtime flag", async () => {
    const def = readDef();
    assert.equal(def.objectives.length, 3);
    assert.deepEqual(def.objectives.map((o) => o.key), ["smb-count", "admin-shares", "alfred-flag"]);
    const byKey = Object.fromEntries(def.objectives.map((o) => [o.key, o]));
    assert.equal(byKey["smb-count"].validation, "exact");
    assert.equal(byKey["admin-shares"].validation, "comma-list");
    assert.equal(byKey["alfred-flag"].validation, "flag");
    for (const o of def.objectives) assert.match(o.expectedHash, /^[0-9a-f]{64}$/);
  });

  it("stored hashes match the canonical answers; flag placeholder matches nothing guessable", async () => {
    const { verifyAnswer } = await import("../server/labs/answers.js");
    const def = readDef();
    const byKey = Object.fromEntries(def.objectives.map((o) => [o.key, o]));
    assert.ok(verifyAnswer("10", byKey["smb-count"].expectedHash, "exact"));
    assert.ok(verifyAnswer("ADMIN$,C$,IPC$", byKey["admin-shares"].expectedHash, "comma-list"));
    assert.ok(verifyAnswer("ADMIN$, C$, IPC$", byKey["admin-shares"].expectedHash, "comma-list"));
    assert.ok(!verifyAnswer("AXIOM{anything}", byKey["alfred-flag"].expectedHash, "flag"));
    assert.ok(!verifyAnswer("flag", byKey["alfred-flag"].expectedHash, "flag"));
  });

  it("leaks no answers, counts, shares, flags, or host mapping", async () => {
    const def = readDef();
    const raw = fs.readFileSync(DEF, "utf8");
    assert.ok(!raw.includes("AXIOM{"), "no flag material");
    assert.ok(!/ADMIN\$/.test(JSON.stringify(def.hints)), "hints must not name the shares");
    assert.ok(!JSON.stringify(def.hints).includes("192.168.50"), "no canonical IPs in hints");
    // "alfred" belongs to the exercise statement only; the served target
    // listing (names/hostnames) must not map it. Metadata roles are
    // deployment internals redacted from the API (covered below).
    const listing = def.targets.map((t) => `${t.name} ${t.hostname}`).join(" ");
    assert.ok(!/alfred/i.test(listing), "target names/hostnames never map alfred");
    assert.ok(!/ADMIN\$/.test(JSON.stringify(def.targets)), "targets never name shares");
  });
});

describe("smb range spec", () => {
  it("share inventory: dc exactly the admin shares, alfred names user + flag", async () => {
    const { shareSpecs, SMB_ROLES } = await import("../server/labs/smb-range.js");
    assert.ok(SMB_ROLES.has("smb") && SMB_ROLES.has("smb-dc") && SMB_ROLES.has("smb-alfred"));
    assert.deepEqual(shareSpecs("smb-dc", "AXIOM{X}").map((s) => s.name), ["ADMIN$", "C$"]);
    assert.deepEqual(shareSpecs("smb", "AXIOM{X}").map((s) => s.name), ["public"]);
    const al = shareSpecs("smb-alfred", "AXIOM{FLAG1}");
    assert.deepEqual(al.map((s) => s.name), ["users", "backup"]);
    assert.ok(al[0].comment.includes("alfred"), "users share points at alfred");
    assert.ok(al[1].comment.includes("AXIOM{FLAG1}"), "backup comment carries the flag");
    assert.ok(!al[0].comment.includes("AXIOM{"), "user pointer and flag stay on separate shares");
    assert.ok(!JSON.stringify(shareSpecs("smb", "AXIOM{X}")).includes("alfred"), "generic hosts never name alfred");
    assert.ok(!JSON.stringify(shareSpecs("smb-dc", "AXIOM{X}")).includes("AXIOM{"), "dc never carries a flag");
  });

  it("smb.conf is 445-only, guest-readable, anonymous-friendly, flag-scoped", async () => {
    const { buildSmbConf } = await import("../server/labs/smb-range.js");
    const dc = buildSmbConf("smb-dc", { host: "10.0.0.151", flag: "AXIOM{FLAG1}" });
    assert.ok(dc.includes("smb ports = 445") && dc.includes("disable netbios = yes"));
    assert.ok(dc.includes("[ADMIN$]") && dc.includes("[C$]"));
    assert.ok(!dc.includes("[public]") && !dc.includes("AXIOM{"), "dc has no extra shares or flags");
    const al = buildSmbConf("smb-alfred", { host: "10.0.0.61", flag: "AXIOM{FLAG1}" });
    assert.ok(al.includes("AXIOM{FLAG1}") && al.includes("alfred"));
    assert.equal((al.match(/AXIOM\{FLAG1\}/g) || []).length, 1, "flag in exactly one share comment");
    const g = buildSmbConf("smb", { host: "10.0.0.11", flag: "AXIOM{FLAG1}" });
    assert.ok(g.includes("[public]") && !g.includes("AXIOM{") && !g.includes("alfred"));
  });

  it("net view shim queries live SMB and delegates everything else", async () => {
    const { NET_VIEW_SHIM } = await import("../server/labs/smb-range.js");
    assert.ok(NET_VIEW_SHIM.includes("smbclient -L"), "shim performs a live query");
    assert.ok(NET_VIEW_SHIM.includes('exec /usr/bin/net "$@"'), "non-view usage delegates to real net");
    assert.ok(!/ADMIN\$|alfred|AXIOM\{/.test(NET_VIEW_SHIM), "shim carries no answers");
  });

  it("ships the canonical range module to the image (no drift)", async () => {
    const a = fs.readFileSync(path.join(REPO, "server/labs/smb-range.js"), "utf8");
    const b = fs.readFileSync(path.join(REPO, "lab-images/m6/smb-634/smb-range.js"), "utf8");
    assert.equal(a, b, "smb-range.js copy must match the canonical module");
    const dockerfile = fs.readFileSync(path.join(REPO, "lab-images/m6/smb-634/Dockerfile"), "utf8");
    assert.ok(dockerfile.includes("samba"), "target image installs real Samba");
    assert.ok(dockerfile.includes("FLAG_SMB"), "per-instance flag comes from env, not the image");
    assert.ok(!/AXIOM\{|password|secret/i.test(dockerfile), "no secrets in the image definition");
  });

  it("attacker image carries SMB enumeration tooling", async () => {
    const dockerfile = fs.readFileSync(path.join(REPO, "lab-images/m6/attacker/Dockerfile"), "utf8");
    for (const pkg of ["nmap", "smbclient", "freerdp2-x11"]) {
      assert.ok(dockerfile.includes(pkg), `attacker needs ${pkg}`);
    }
    assert.ok(fs.existsSync(path.join(REPO, "lab-images/m6/attacker/enum4linux.pl")), "enum4linux vendored");
    const { NET_VIEW_SHIM } = await import("../server/labs/smb-range.js");
    assert.equal(fs.readFileSync(path.join(REPO, "lab-images/m6/attacker/net"), "utf8"), NET_VIEW_SHIM);
  });

  it("orchestrator resolves the smb image build context and per-role probes", async () => {
    const { resolveBuildContext } = await import("../server/labs/orchestrator.js");
    assert.equal(resolveBuildContext("axiom-lab-smb-634:latest", JSON.stringify({ build: "m6/smb-634" })), path.resolve(REPO, "lab-images/m6/smb-634"));
  });
});

describe("smb service (sqlite) + local range", () => {
  let svc, db, orch, userId, lab;
  let haveSandbox = true, haveSmb = true, haveNmap = true;
  before(async () => {
    db = await import("../server/db.js");
    await db.initDb();
    svc = await import("../server/labs/service.js");
    orch = await import("../server/labs/orchestrator.js");
    haveSandbox = await orch.unshareAvailable();
    haveSmb = await hostHas("smbclient") && await (async () => {
      try {
        await run("/usr/bin/python3", ["-c", "import impacket.smbserver"], { timeout: 15000 });
        return true;
      } catch {
        try {
          await run("python3", ["-c", "import impacket.smbserver"], { timeout: 15000 });
          return true;
        } catch { return false; }
      }
    })();
    haveNmap = await hostHas("nmap");
    if (!haveSandbox) console.log("  (skip range tests: no unshare sandbox on this host)");
    if (!haveSmb) console.log("  (skip smb tests: need smbserver.py + smbclient on this host)");
    const { createUser } = await import("../server/auth.js");
    const u = await createUser({ username: "smbtester", email: "smb@test.local", displayName: "SMB", password: "password12345" });
    userId = u.id;
    await svc.seedFromDefinitions(path.join(REPO, "labs"));
    lab = await svc.getLab("slug", SLUG);
    assert.ok(lab);
  });

  it("seeds attacker + ten smb targets + two decoys, three hash-only objectives", async () => {
    const targets = await svc.labTargets(lab.id);
    assert.equal(targets.length, 13);
    assert.equal(targets.filter((t) => t.target_type === "attacker").length, 1);
    assert.equal(targets.filter((t) => t.target_type === "smb-target").length, 10);
    assert.equal(targets.filter((t) => t.target_type === "nmap-target").length, 2);
    for (const t of targets) {
      assert.deepEqual(JSON.parse(t.service_ports), []);
      assert.ok(!JSON.stringify(t).match(/AXIOM\{|ADMIN\$/));
    }
    const objectives = await svc.labObjectives(lab.id);
    assert.equal(objectives.length, 3);
    assert.ok(!("expected_value_hash" in objectives[0]), "hashes must never be served to clients");
    assert.equal((await svc.labHints(lab.id)).length, 4);
  });

  it("provisions an isolated range with ten 445 listeners plus decoys", async function () {
    if (!haveSandbox || !haveSmb) { console.log("  (skip: needs sandbox + smb tooling)"); return; }
    const topo = await orch.nmapTopology(lab.id, "10.210.9.0/24");
    assert.equal(topo.subnet, "10.210.9.0/24");
    assert.equal(topo.attacker.ip, "10.210.9.2");
    assert.equal(topo.boxes.length, 12);
    const tmp = await svc.createInstance({ userId, labId: lab.id, provider: "local" });
    const details = await orch.provisionInstance({ lab, instance: { ...tmp, user_id: userId } });
    const iid = tmp.id;
    const inst = await activate(svc, db, lab, tmp, details);
    try {
      assert.ok(details.targetIp.endsWith(".2"), "instance IP is the attacker");
      assert.match(details.providerReference, /nmap-multi/);
    } finally {
      await orch.destroyInstance(instRow(details, iid, lab.id));
      await svc.clearRuntimeFlags(iid).catch(() => {});
    }
  });

  it("real nmap 445 sweep counts exactly ten SMB hosts (Q1 methodology)", async function () {
    if (!haveSandbox || !haveSmb || !haveNmap) { console.log("  (skip: needs sandbox + smb + nmap)"); return; }
    const tmp = await svc.createInstance({ userId, labId: lab.id, provider: "local" });
    const details = await orch.provisionInstance({ lab, instance: { ...tmp, user_id: userId } });
    const iid = tmp.id;
    const inst = await activate(svc, db, lab, tmp, details);
    const base = details.networkCidr.split(".").slice(0, 3).join(".");
    const sh = (command) => orch.runTerminalCommand(inst, command, lab).then((r) => r.output);
    try {
      // The -oN header itself contains "--open", so count the port line
      // students are taught to filter for (see Hint 1), not bare "open".
      const out = await sh(`nmap -p 445 --open -T4 ${base}.0/24 -oN smb.txt && grep -c "445/tcp open" smb.txt`);
      const count = out.trim().split("\n").pop().trim();
      assert.equal(count, "10", `expected ten 445-open hosts, got: ${out.slice(-200)}`);
      const decoy = await sh(`nmap -p 445 --open -T4 ${base}.21 ${base}.22`);
      assert.ok(!/445\/tcp\s+open/.test(decoy), "decoys must not expose 445");
      const r = await svc.submitAnswer({ userId, lab, objectiveKey: "smb-count", answer: "10", instanceId: iid });
      assert.ok(r.correct && r.completed);
    } finally {
      await orch.destroyInstance(instRow(details, iid, lab.id));
      await svc.clearRuntimeFlags(iid).catch(() => {});
    }
  }, { timeout: 240000 });

  it("net view against dc01 reports the three admin shares (Q2 methodology)", async function () {
    if (!haveSandbox || !haveSmb) { console.log("  (skip: needs sandbox + smb tooling)"); return; }
    const tmp = await svc.createInstance({ userId, labId: lab.id, provider: "local" });
    const details = await orch.provisionInstance({ lab, instance: { ...tmp, user_id: userId } });
    const iid = tmp.id;
    const inst = await activate(svc, db, lab, tmp, details);
    const base = details.networkCidr.split(".").slice(0, 3).join(".");
    const sh = (command) => orch.runTerminalCommand(inst, command, lab).then((r) => r.output);
    try {
      const via = await sh(`smbclient -L //${base}.151 -N`);
      for (const s of ["ADMIN$", "C$", "IPC$"]) assert.ok(via.includes(s), `smbclient lists ${s}`);
      const view = await sh(`net view \\\\dc01`);
      for (const s of ["ADMIN$", "C$", "IPC$"]) assert.ok(view.includes(s), `net view lists ${s}`);
      assert.ok(view.includes("completed successfully"), "windows-style completion");
      const viewIp = await sh(`net view \\\\${base}.151`);
      for (const s of ["ADMIN$", "C$", "IPC$"]) assert.ok(viewIp.includes(s), "net view works by IP too");
      const r = await svc.submitAnswer({ userId, lab, objectiveKey: "admin-shares", answer: "ADMIN$,C$,IPC$", instanceId: iid });
      assert.ok(r.correct && r.completed);
      const spaced = await svc.submitAnswer({ userId, lab, objectiveKey: "admin-shares", answer: "ADMIN$, C$, IPC$", instanceId: iid });
      assert.ok(spaced.correct, "comma spacing normalizes");
      const generic = await sh(`smbclient -L //${base}.11 -N`);
      // Impacket uppercases share names; match case-insensitively.
      assert.ok(/public/i.test(generic) && !generic.includes("ADMIN$"), "generic host has no admin shares");
    } finally {
      await orch.destroyInstance(instRow(details, iid, lab.id));
      await svc.clearRuntimeFlags(iid).catch(() => {});
    }
  }, { timeout: 240000 });

  it("enum4linux finds alfred and the share-comment flag (Q3 methodology)", async function () {
    if (!haveSandbox || !haveSmb || !await hostHas("enum4linux")) { console.log("  (skip: needs sandbox + smb + enum4linux)"); return; }
    const tmp = await svc.createInstance({ userId, labId: lab.id, provider: "local" });
    const details = await orch.provisionInstance({ lab, instance: { ...tmp, user_id: userId } });
    const iid = tmp.id;
    const inst = await activate(svc, db, lab, tmp, details);
    const base = details.networkCidr.split(".").slice(0, 3).join(".");
    const sh = (command) => orch.runTerminalCommand(inst, command, lab).then((r) => r.output);
    try {
      // Narrow to the Topic Exercise group the way the exercise scopes it.
      const found = [];
      for (const oct of [60, 61, 62]) {
        const e = await sh(`enum4linux ${base}.${oct}`);
        if (/alfred/i.test(e)) found.push(oct);
      }
      assert.deepEqual(found, [61], "only the intended Topic host names alfred");
      const e61 = await sh(`enum4linux ${base}.61`);
      assert.ok(/backup/i.test(e61), "enum4linux shows the backup share");
      const m = /AXIOM\{[0-9a-f]{32}\}/.exec(e61);
      assert.ok(m, "flag retrieved through genuine enum4linux share enumeration");
      const r = await svc.submitAnswer({ userId, lab, objectiveKey: "alfred-flag", answer: m[0], instanceId: iid });
      assert.ok(r.correct && r.completed, "retrieved flag validates");
      const e60 = await sh(`smbclient -L //${base}.60 -N`);
      assert.ok(!/AXIOM\{[0-9a-f]{32}\}/.test(e60), "sibling topic host carries no flag");
      const p = await svc.labProgress(userId, lab.id);
      assert.ok(p.complete, "all three objectives complete");
    } finally {
      await orch.destroyInstance(instRow(details, iid, lab.id));
      await svc.clearRuntimeFlags(iid).catch(() => {});
    }
  }, { timeout: 300000 });

  it("wrong answers fail: counts, shares, flags, blanks", async () => {
    const wrong = [
      ["smb-count", "9"], ["smb-count", "11"], ["smb-count", "12"], ["smb-count", ""],
      ["smb-count", "ten"],
      ["admin-shares", "ADMIN$,C$"], ["admin-shares", "ADMIN$,C$,IPC$,D$"],
      ["admin-shares", "C$,ADMIN$,IPC$"], ["admin-shares", ""],
      ["alfred-flag", "AXIOM{00000000000000000000000000000000}"],
      ["alfred-flag", ""],
      ["alfred-flag", "alfred"],
    ];
    for (const [key, ans] of wrong) {
      const r = await svc.submitAnswer({ userId, lab, objectiveKey: key, answer: ans, instanceId: "li_smbx" });
      assert.ok(r.ok && !r.correct, `${key}=${JSON.stringify(ans)} must fail`);
      assert.ok(!JSON.stringify(r).match(/AXIOM\{[0-9a-f]{32}\}/), "no flag material in responses");
    }
  });

  it("reset rotates the flag; stale flags die with the instance", async function () {
    if (!haveSandbox || !haveSmb) { console.log("  (skip: needs sandbox + smb tooling)"); return; }
    const tmp1 = await svc.createInstance({ userId, labId: lab.id, provider: "local" });
    const d1 = await orch.provisionInstance({ lab, instance: { ...tmp1, user_id: userId } });
    const iid = tmp1.id;
    const inst = await activate(svc, db, lab, tmp1, d1);
    const base = d1.networkCidr.split(".").slice(0, 3).join(".");
    const sh = (command) => orch.runTerminalCommand(inst, command, lab).then((r) => r.output);
    try {
      const f1 = /AXIOM\{[0-9a-f]{32}\}/.exec(await sh(`smbclient -L //${base}.61 -N`))[0];
      assert.ok((await svc.submitAnswer({ userId, lab, objectiveKey: "alfred-flag", answer: f1, instanceId: iid })).correct);
      await orch.destroyInstance(instRow(d1, iid, lab.id));
      await svc.clearRuntimeFlags(iid);
      const tmp2 = await svc.createInstance({ userId, labId: lab.id, provider: "local" });
      const d2 = await orch.provisionInstance({ lab, instance: { ...tmp2, user_id: userId } });
      const inst2 = await activate(svc, db, lab, tmp2, d2);
      const base2 = d2.networkCidr.split(".").slice(0, 3).join(".");
      const sh2 = (command) => orch.runTerminalCommand(inst2, command, lab).then((r) => r.output);
      const f2 = /AXIOM\{[0-9a-f]{32}\}/.exec(await sh2(`smbclient -L //${base2}.61 -N`))[0];
      assert.notEqual(f2, f1, "fresh instance mints a fresh flag");
      const stale = await svc.submitAnswer({ userId, lab, objectiveKey: "alfred-flag", answer: f1, instanceId: tmp2.id });
      assert.ok(!stale.correct, "pre-reset flag no longer validates");
      await orch.destroyInstance(instRow(d2, tmp2.id, lab.id));
      await svc.clearRuntimeFlags(tmp2.id);
    } catch (e) {
      await orch.destroyInstance(instRow({ providerReference: "" }, iid, lab.id)).catch(() => {});
      await svc.clearRuntimeFlags(iid).catch(() => {});
      throw e;
    }
  }, { timeout: 240000 });

  it("never leaks answers or flags through lab reads", async () => {
    for (const row of await svc.labTargets(lab.id)) {
      assert.ok(!JSON.stringify(row).match(/AXIOM\{|ADMIN\$/));
    }
    for (const row of await svc.labObjectives(lab.id)) {
      assert.ok(!JSON.stringify(row).match(/AXIOM\{|ADMIN\$/));
    }
    const labRow = await svc.getLab("slug", SLUG);
    assert.ok(!JSON.stringify(labRow).match(/AXIOM\{|ADMIN\$/));
    assert.ok(!JSON.stringify(await svc.labProgress(userId, lab.id)).match(/AXIOM\{[0-9a-f]{32}\}/));
    for (const h of await svc.hintsFor(userId, lab.id)) {
      assert.ok(!JSON.stringify(h).match(/AXIOM\{|ADMIN\$/));
    }
  });
});

describe("smb routes (http)", () => {
  const PORT = 3465;
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
      user = await createUser({ username: "smbhttp", email: "smbh@test.local", displayName: "SMBH", password: "password12345" });
    } catch {
      user = await db.get(`SELECT * FROM users WHERE username=?`, ["smbhttp"]);
    }
    const r = await fetch(`${BASE}/login`, {
      method: "POST", redirect: "manual",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ identifier: "smbhttp", password: "password12345" }),
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

  it("workspace shows the range without shares, flags, or host mapping", async () => {
    const r = await get(`/labs/oscp/${SLUG}`);
    assert.equal(r.status, 200);
    const html = await r.text();
    for (const crumb of ["6.3.4", "SMB Enumeration", "Lab 1"]) assert.ok(html.includes(crumb), `missing: ${crumb}`);
    assert.ok(html.includes("kali"), "attacker shell framing present");
    assert.ok(html.includes("dc01"), "dc01 named for the net view workflow");
    assert.ok(!html.includes("ADMIN$"), "no share answers in HTML");
    assert.ok(!html.includes("AXIOM{"), "no flag material in HTML");
    // "alfred" appears only in the exercise statement (source-established);
    // the target list must never map it to a host.
    assert.ok(!html.includes("smb-alfred"), "no role mapping in HTML");
    assert.ok(!/topic-vm2[^<]*alfred|alfred[^<]*topic-vm2/i.test(html), "no alfred host mapping in HTML");
    for (const marker of ["Attacker Terminal", "Submit Answer", "Lab Progress", "Connection"]) assert.ok(html.includes(marker));
  });

  it("lab API redacts deployment internals from target listings", async () => {
    const j = await (await get(`/api/labs/${labId}`)).json();
    assert.equal(j.targets.length, 13);
    const blob = JSON.stringify(j.targets);
    assert.ok(!blob.includes("AXIOM{") && !blob.includes("ADMIN$"));
    assert.ok(!blob.includes("service_ports") && !blob.includes("metadata_json"), "internals redacted");
    assert.ok(blob.includes("dc01"), "neutral names still served");
  });

  it("full lifecycle over HTTP with real enumeration", async function () {
    const orch = await import("../server/labs/orchestrator.js");
    if (!await orch.unshareAvailable()) { console.log("  (skip: no sandbox)"); return; }
    const svc = await import("../server/labs/service.js");
    const postq = (p, body) => fetch(`${BASE}${p}`, {
      method: "POST", headers: { Cookie: cookie, "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    });
    let r = await postq(`/api/labs/${labId}/start`);
    assert.equal(r.status, 200);
    const started = await r.json();
    assert.equal(started.instance.status, "running");
    assert.ok(started.instance.networkCidr.startsWith("10.200."));
    const base = started.instance.networkCidr.split(".").slice(0, 3).join(".");
    const sh = (command) => postq(`/api/labs/${labId}/terminal`, { command }).then((x) => x.json()).then((j) => j.output);
    const count = await sh(`nmap -p 445 --open -T4 ${base}.0/24 | grep -c "445/tcp open"`);
    assert.equal(count.trim(), "10", "terminal 445 sweep counts ten");
    const view = await sh(`net view \\\\dc01`);
    for (const s of ["ADMIN$", "C$", "IPC$"]) assert.ok(view.includes(s));
    r = await postq(`/api/labs/${labId}/submit`, { answers: { "smb-count": "11" } });
    assert.equal((await r.json()).results["smb-count"].correct, false);
    const flag = /AXIOM\{[0-9a-f]{32}\}/.exec(await sh(`enum4linux ${base}.61`))[0];
    r = await postq(`/api/labs/${labId}/submit`, {
      answers: { "smb-count": "10", "admin-shares": "ADMIN$,C$,IPC$", "alfred-flag": flag },
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
  }, { timeout: 300000 });
});
