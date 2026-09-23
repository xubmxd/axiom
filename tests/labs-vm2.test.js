import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// Isolate: temp sqlite file + local provider before any server module loads.
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "axiom-labs-vm2-"));
process.env.DATA_DIR = TMP;
process.env.LAB_PROVIDER = "local";

const REPO = path.resolve(import.meta.dirname, "..");
const VM2_SLUG = "m6-6-2-1-whois-vm2";
const VM2_DEF = path.join(REPO, "labs/module-06/6.2.1-whois/vm-02/lab.json");

function readDef() {
  return JSON.parse(fs.readFileSync(VM2_DEF, "utf8"));
}

describe("vm2 definition", () => {
  it("loads under the existing 6.2.1 exercise (not a new module/section)", async () => {
    const { loadAllDefinitions, normalizePlacement } = await import("../server/labs/definitions.js");
    const all = loadAllDefinitions(path.join(REPO, "labs"));
    const vm2 = all.find((l) => l.def.slug === VM2_SLUG);
    assert.ok(vm2, "vm-02/lab.json must be discovered");
    assert.equal(vm2.def.title, "6.2.1 Whois Enumeration");
    assert.equal(vm2.def.machineName, "VM #2");
    assert.equal(vm2.def.labNumber, 2);
    const p = normalizePlacement(vm2.def);
    assert.equal(p.courseSlug, "core");
    assert.equal(p.courseTitle, "Core");
    assert.equal(p.moduleNumber, 6);
    assert.equal(p.moduleTitle, "Information Gathering");
    assert.equal(p.section, "6.2.1");
    assert.equal(p.sectionTitle, "Whois Enumeration");
  });

  it("declares a single-target TCP/43 WHOIS target for VM #2", async () => {
    const def = readDef();
    assert.equal(def.targets.length, 1);
    assert.equal(def.targets[0].name, "VM #2");
    assert.equal(def.targets[0].type, "whois-server");
    assert.equal(def.targets[0].os, "Linux");
    assert.deepEqual(def.targets[0].ports, [43]);
    assert.equal(def.targets[0].image, "axiom-lab-whois-vm2:latest");
    assert.equal(def.targets[0].build, "m6/whois-vm2");
    assert.equal(def.environment.targetPort, 43);
  });

  it("has one flag submission validated server-side via hash", async () => {
    const def = readDef();
    assert.equal(def.objectives.length, 1);
    assert.equal(def.objectives[0].key, "flag");
    assert.equal(def.objectives[0].validation, "flag");
    assert.match(def.objectives[0].expectedHash, /^[0-9a-f]{64}$/);
  });

  it("leaks no flag through the definition file", async () => {
    const raw = fs.readFileSync(VM2_DEF, "utf8");
    assert.ok(!raw.includes("AXIOM{"), "flag must never be baked into lab.json");
    assert.ok(raw.includes("offensive-security.com"), "queried domain is public instruction");
  });

  it("instructs the documented query pattern without revealing the flag", async () => {
    const def = readDef();
    const joined = JSON.stringify(def.instructions);
    assert.ok(joined.includes("whois offensive-security.com -h <TARGET-IP>"));
    assert.ok(!joined.includes("AXIOM{"));
  });
});

describe("vm2 whois dataset", () => {
  it("serves a realistic record with the flag inside the DNS section", async () => {
    const { buildVm2WhoisResponse } = await import("../server/labs/whois-data.js");
    const out = buildVm2WhoisResponse("offensive-security.com", "AXIOM{deadbeef0123456789abcdef01234567}");
    for (const section of [
      "Domain Name:", "Registry Domain ID:", "Registrar WHOIS Server:",
      "Registrar URL:", "Updated Date:", "Creation Date:",
      "Registry Expiry Date:", "Registrar:", "Registrar IANA ID:",
      "Domain Status:", "Name Server:", "DNSSEC:",
    ]) assert.ok(out.includes(section), `missing section: ${section}`);
    const dnsLines = out.split(/\r?\n/).filter((l) => /^DNS[\s:]/.test(l));
    assert.ok(dnsLines.length >= 3, "must expose a clearly identifiable DNS section");
    const flagLine = dnsLines.find((l) => l.includes("AXIOM{"));
    assert.ok(flagLine, "flag must live inside the DNS section");
    assert.ok(!/^Domain Name/m.test(flagLine));
  });

  it("answers case-insensitively and rejects unknown domains", async () => {
    const { buildVm2WhoisResponse } = await import("../server/labs/whois-data.js");
    const a = buildVm2WhoisResponse("OFFENSIVE-SECURITY.COM", "AXIOM{x}");
    assert.ok(a.includes("DNS TXT:"));
    assert.ok(buildVm2WhoisResponse("domain offensive-security.com", "AXIOM{x}").includes("DNS TXT:"));
    assert.ok(buildVm2WhoisResponse("megacorpone.com", "AXIOM{x}").startsWith("No match"));
    assert.ok(buildVm2WhoisResponse("no-such-domain-xyz.test", "AXIOM{x}").startsWith("No match"));
    assert.ok(buildVm2WhoisResponse("ns1.offensive-security.com", "AXIOM{x}").includes("Server Name:"));
  });

  it("maps labs to their own domains, defaulting to VM #1", async () => {
    const { labDomain, LAB_DOMAIN, VM2_DOMAIN } = await import("../server/labs/whois-data.js");
    assert.equal(labDomain("m6-6-2-1-whois-vm2"), VM2_DOMAIN);
    assert.equal(labDomain({ slug: "m6-6-2-1-whois-vm2" }), VM2_DOMAIN);
    assert.equal(labDomain("m6-6-2-1-whois-vm1"), LAB_DOMAIN);
    assert.equal(labDomain("unknown"), LAB_DOMAIN);
    assert.equal(labDomain(null), LAB_DOMAIN);
  });

  it("leaves the VM #1 dataset byte-identical", async () => {
    const { buildWhoisResponse } = await import("../server/labs/whois-data.js");
    const out = buildWhoisResponse("megacorpone.com");
    assert.equal(out.length, 1078);
    assert.ok(/ns3\.megacorpone\.com/i.test(out));
    assert.ok(out.includes("whois.gandi.net"));
    assert.ok(!out.includes("AXIOM{"), "VM #1 must never carry a flag");
    assert.ok(!out.toLowerCase().includes("offensive-security"));
  });
});

describe("runtime flags", () => {
  it("mints unique Axiom-namespaced flags", async () => {
    const svc = await import("../server/labs/service.js");
    const a = svc.mintFlagValue();
    const b = svc.mintFlagValue();
    assert.match(a, /^AXIOM\{[0-9a-f]{32}\}$/);
    assert.notEqual(a, b);
  });

  it("round-trips ensure/get/clear per instance", async () => {
    const db = await import("../server/db.js");
    try { await db.initDb(); } catch {}
    const svc = await import("../server/labs/service.js");
    const row = await svc.ensureRuntimeFlag({ instanceId: "li_flagtest", labId: "lab_x", userId: "u_x" });
    assert.match(row.flag_value, /^AXIOM\{[0-9a-f]{32}\}$/);
    assert.match(row.flag_hash, /^[0-9a-f]{64}$/);
    assert.equal((await svc.ensureRuntimeFlag({ instanceId: "li_flagtest" })).flag_value, row.flag_value);
    assert.equal((await svc.getRuntimeFlag("li_flagtest", "flag")).flag_value, row.flag_value);
    await svc.clearRuntimeFlags("li_flagtest");
    assert.equal(await svc.getRuntimeFlag("li_flagtest", "flag"), null);
    const fresh = await svc.ensureRuntimeFlag({ instanceId: "li_flagtest" });
    assert.notEqual(fresh.flag_value, row.flag_value);
    await svc.clearRuntimeFlags("li_flagtest");
  });
});

describe("vm2 service (sqlite)", () => {
  let svc, db, orch, userId, lab, vm1;
  before(async () => {
    db = await import("../server/db.js");
    await db.initDb();
    svc = await import("../server/labs/service.js");
    orch = await import("../server/labs/orchestrator.js");
    const { createUser } = await import("../server/auth.js");
    const u = await createUser({ username: "vm2tester", email: "vm2@test.local", displayName: "VM2", password: "password12345" });
    userId = u.id;
    await svc.seedFromDefinitions(path.join(REPO, "labs"));
    lab = await svc.getLab("slug", VM2_SLUG);
    vm1 = await svc.getLab("slug", "m6-6-2-1-whois-vm1");
    assert.ok(lab && vm1);
  });

  it("shares the course/module/section with VM #1 and seeds hash-only objectives", async () => {
    assert.equal(lab.course_id, vm1.course_id);
    assert.equal(lab.module_number, 6);
    assert.equal(lab.section_number, "6.2.1");
    assert.equal(lab.lab_number, 2);
    const targets = await svc.labTargets(lab.id);
    assert.equal(targets.length, 1);
    assert.equal(targets[0].target_type, "whois-server");
    assert.equal(JSON.parse(targets[0].metadata_json).build, "m6/whois-vm2");
    const objectives = await svc.labObjectives(lab.id);
    assert.equal(objectives.length, 1);
    assert.ok(!("expected_value_hash" in objectives[0]), "hashes must never be served to clients");
  });

  it("full smoke: provision → TCP/43 → DNS flag → submit → reset → stop", async () => {
    const iid = "li_vm2smoke1";
    const local = orch.providerFor("local");
    const details = await local.provision(lab, { id: iid });
    try {
      assert.ok(details.targetIp.startsWith("10."));
      assert.equal(details.targetPort, 43);
      const stored = await svc.getRuntimeFlag(iid, "flag");
      assert.ok(stored?.flag_value, "provisioning mints the runtime flag");

      // real TCP/43 query against the provisioned endpoint
      const { host, port } = await orch.resolveEndpoint(
        { target_ip: details.targetIp, target_port: 43, host_endpoint: details.hostEndpoint },
        "offensive-security.com",
      );
      const out = await orch.whoisQuery(host, port, "offensive-security.com");
      assert.ok(out.includes("Name Server"), "realistic record shape");
      const dnsSection = out.split(/\r?\n/).filter((l) => /^DNS[\s:]/.test(l));
      assert.ok(dnsSection.length >= 3, "DNS section present");
      assert.ok(dnsSection.join("\n").includes(stored.flag_value), "runtime flag inside the DNS section");
      assert.ok(!out.includes("megacorpone.com"), "no cross-lab leakage");

      // terminal goes over the same real path, scoped to this lab
      const inst = { id: iid, target_ip: details.targetIp, target_port: 43, host_endpoint: details.hostEndpoint, provider: "local", network_cidr: details.networkCidr };
      const t = await orch.runTerminalCommand(inst, `whois offensive-security.com -h ${details.targetIp}`, lab);
      assert.ok(t.output.includes(stored.flag_value), "terminal returns the live target response");
      const help = await orch.runTerminalCommand(inst, "help", lab);
      assert.ok(help.output.includes("offensive-security.com"));
      const dig = await orch.runTerminalCommand(inst, "dig offensive-security.com NS", lab);
      assert.ok(dig.output.includes("ns1.offensive-security.com"));
      const evil = await orch.runTerminalCommand(inst, "whois offensive-security.com -h evil.example", lab);
      assert.ok(/not reachable/i.test(evil.output));

      // wrong flag fails without revealing anything; right flag completes
      const bad = await svc.submitAnswer({ userId, lab, objectiveKey: "flag", answer: "AXIOM{00000000000000000000000000000000}", instanceId: iid });
      assert.ok(bad.ok && !bad.correct);
      assert.ok(!JSON.stringify(bad).includes(stored.flag_value));
      const good = await svc.submitAnswer({ userId, lab, objectiveKey: "flag", answer: stored.flag_value, instanceId: iid });
      assert.ok(good.ok && good.correct && good.completed);
      const p = await svc.labProgress(userId, lab.id);
      assert.ok(p.complete);

      // reset rotates the secret: old flag dies, new flag works, target serves it
      await local.destroy({ id: iid, provider_reference: details.providerReference, network_name: details.networkName });
      await svc.clearRuntimeFlags(iid);
      const details2 = await local.provision(lab, { id: iid });
      try {
        const stored2 = await svc.getRuntimeFlag(iid, "flag");
        assert.notEqual(stored2.flag_value, stored.flag_value);
        const stale = await svc.submitAnswer({ userId, lab, objectiveKey: "flag", answer: stored.flag_value, instanceId: iid });
        assert.ok(!stale.correct, "pre-reset flag must not validate after reset");
        const ep2 = await orch.resolveEndpoint(
          { target_ip: details2.targetIp, target_port: 43, host_endpoint: details2.hostEndpoint },
          "offensive-security.com",
        );
        const out2 = await orch.whoisQuery(ep2.host, ep2.port, "offensive-security.com");
        assert.ok(out2.includes(stored2.flag_value), "reset environment serves the fresh flag");
        const good2 = await svc.submitAnswer({ userId, lab, objectiveKey: "flag", answer: stored2.flag_value, instanceId: iid });
        assert.ok(good2.correct);
      } finally {
        await local.destroy({ id: iid, provider_reference: details2.providerReference, network_name: details2.networkName });
      }
      await svc.clearRuntimeFlags(iid);
      assert.equal(await svc.getRuntimeFlag(iid, "flag"), null);
      await assert.rejects(orch.whoisQuery("127.0.0.1", details.hostEndpoint.split(":")[1], "offensive-security.com", 1500));
    } finally {
      await local.destroy({ id: iid }).catch(() => {});
      await svc.clearRuntimeFlags(iid).catch(() => {});
    }
  });

  it("VM #1 still answers its own domain on its own target (regression)", async () => {
    const local = orch.providerFor("local");
    const d1 = await local.provision(vm1, { id: "li_vm1reg" });
    try {
      const out = await orch.whoisQuery("127.0.0.1", d1.hostEndpoint.split(":")[1], "megacorpone.com");
      assert.ok(/ns3\.megacorpone\.com/i.test(out));
      assert.ok(out.includes("whois.gandi.net"));
      const miss = await orch.whoisQuery("127.0.0.1", d1.hostEndpoint.split(":")[1], "offensive-security.com");
      assert.ok(miss.startsWith("No match"), "VM #1 knows nothing of VM #2's domain");
    } finally {
      await local.destroy({ id: "li_vm1reg", provider_reference: d1.providerReference, network_name: d1.networkName });
    }
    const r = await svc.submitAnswer({ userId, lab: vm1, objectiveKey: "third-nameserver", answer: "ns3.megacorpone.com", instanceId: "li_x" });
    assert.ok(r.correct);
  });

  it("never leaks the flag through lab reads", async () => {
    const iid = "li_vm2leak";
    const stored = await svc.ensureRuntimeFlag({ instanceId: iid, labId: lab.id, userId });
    try {
      for (const row of await svc.labTargets(lab.id)) {
        assert.ok(!JSON.stringify(row).includes(stored.flag_value));
      }
      for (const row of await svc.labObjectives(lab.id)) {
        assert.ok(!JSON.stringify(row).includes(stored.flag_value));
      }
      const labRow = await svc.getLab("slug", VM2_SLUG);
      assert.ok(!JSON.stringify(labRow).includes(stored.flag_value));
      assert.ok(!JSON.stringify(await svc.labProgress(userId, lab.id)).includes(stored.flag_value));
      assert.ok(!JSON.stringify(await svc.hintsFor(userId, lab.id)).includes(stored.flag_value));
    } finally {
      await svc.clearRuntimeFlags(iid);
    }
  });

  it("course and module progress include Lab 2 automatically", async () => {
    const cp = await svc.courseProgress(userId, lab.course_id);
    assert.equal(cp.total, 3);
    const mp = await svc.moduleProgress(userId, lab.course_id, 6);
    assert.equal(mp.total, 3);
  });
});

describe("vm2 image wiring", () => {
  it("resolves the vm2 build context and ships a hardened image", async () => {
    const { resolveBuildContext } = await import("../server/labs/orchestrator.js");
    assert.equal(
      resolveBuildContext("axiom-lab-whois-vm2:latest", JSON.stringify({ build: "m6/whois-vm2" })),
      path.resolve(REPO, "lab-images/m6/whois-vm2"),
    );
    assert.equal(resolveBuildContext("axiom-lab-whois-vm2:latest", "{}"), path.resolve(REPO, "lab-images/m6/whois-vm2"));
    const dockerfile = fs.readFileSync(path.join(REPO, "lab-images/m6/whois-vm2/Dockerfile"), "utf8");
    assert.ok(dockerfile.includes("USER whois"), "target must not run as root");
    assert.ok(dockerfile.includes("EXPOSE 43"));
    const py = fs.readFileSync(path.join(REPO, "lab-images/m6/whois-vm2/whois.py"), "utf8");
    assert.ok(py.includes("AXIOM_WHOIS_FLAG"), "flag injected at provisioning, never baked in");
    assert.ok(!py.includes("megacorpone"), "no VM #1 behavior inside the VM #2 image");
    assert.ok(py.includes("DNS TXT:"), "flag served inside the DNS section");
  });
});
