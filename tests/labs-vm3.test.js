import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// Isolate: temp sqlite file + local provider before any server module loads.
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "axiom-labs-vm3-"));
process.env.DATA_DIR = TMP;
process.env.LAB_PROVIDER = "local";

const REPO = path.resolve(import.meta.dirname, "..");
const VM3_SLUG = "m6-6-2-1-whois-vm3";
const VM3_DEF = path.join(REPO, "labs/module-06/6.2.1-whois/vm-03/lab.json");
const TECH_EMAIL = "tech@example.net";

function readDef() {
  return JSON.parse(fs.readFileSync(VM3_DEF, "utf8"));
}

describe("vm3 definition", () => {
  it("loads under the existing 6.2.1 exercise (not a new module/section)", async () => {
    const { loadAllDefinitions, normalizePlacement } = await import("../server/labs/definitions.js");
    const all = loadAllDefinitions(path.join(REPO, "labs"));
    assert.equal(all.length, 3);
    const vm3 = all.find((l) => l.def.slug === VM3_SLUG);
    assert.ok(vm3, "vm-03/lab.json must be discovered");
    assert.equal(vm3.def.title, "6.2.1 Whois Enumeration");
    assert.equal(vm3.def.machineName, "VM #3");
    assert.equal(vm3.def.labNumber, 3);
    const p = normalizePlacement(vm3.def);
    assert.equal(p.courseSlug, "core");
    assert.equal(p.courseTitle, "Core");
    assert.equal(p.moduleNumber, 6);
    assert.equal(p.moduleTitle, "Information Gathering");
    assert.equal(p.section, "6.2.1");
    assert.equal(p.sectionTitle, "Whois Enumeration");
  });

  it("declares a single-target TCP/43 WHOIS target for VM #3", async () => {
    const def = readDef();
    assert.equal(def.targets.length, 1);
    assert.equal(def.targets[0].name, "VM #3");
    assert.equal(def.targets[0].type, "whois-server");
    assert.equal(def.targets[0].os, "Linux");
    assert.deepEqual(def.targets[0].ports, [43]);
    assert.equal(def.targets[0].image, "axiom-lab-whois-vm3:latest");
    assert.equal(def.targets[0].build, "m6/whois-vm3");
    assert.equal(def.environment.targetPort, 43);
  });

  it("has one Tech Email objective validated server-side via hash", async () => {
    const def = readDef();
    assert.equal(def.objectives.length, 1);
    assert.equal(def.objectives[0].key, "tech-email");
    assert.equal(def.objectives[0].validation, "case-insensitive-exact");
    assert.match(def.objectives[0].expectedHash, /^[0-9a-f]{64}$/);
  });

  it("stored hash matches the Tech Email from the WHOIS record", async () => {
    const { verifyAnswer } = await import("../server/labs/answers.js");
    const { TECH_EMAIL: recordEmail } = await import("../server/labs/whois-data.js");
    const def = readDef();
    assert.equal(recordEmail, TECH_EMAIL);
    assert.ok(verifyAnswer(TECH_EMAIL, def.objectives[0].expectedHash, "case-insensitive-exact"));
    assert.ok(verifyAnswer("  TECH@EXAMPLE.NET  ", def.objectives[0].expectedHash, "case-insensitive-exact"));
  });

  it("leaks no answer through the definition file", async () => {
    const raw = fs.readFileSync(VM3_DEF, "utf8");
    assert.ok(!raw.includes(TECH_EMAIL), "answer must never be baked into lab.json");
    assert.ok(raw.includes("example.net"), "queried domain is public instruction");
  });

  it("instructs the documented query pattern without revealing the answer", async () => {
    const def = readDef();
    const joined = JSON.stringify(def.instructions);
    assert.ok(joined.includes("whois example.net -h <TARGET-IP>"));
    assert.ok(!joined.includes(TECH_EMAIL));
  });
});

describe("vm3 whois dataset", () => {
  it("serves a realistic record with a discoverable Tech Email", async () => {
    const { buildVm3WhoisResponse } = await import("../server/labs/whois-data.js");
    const out = buildVm3WhoisResponse("example.net");
    for (const section of [
      "Domain Name:", "Registry Domain ID:", "Registrar WHOIS Server:",
      "Registrar URL:", "Updated Date:", "Creation Date:",
      "Registry Expiry Date:", "Registrar:", "Registrar IANA ID:",
      "Domain Status:", "Name Server:", "DNSSEC:", "DNS Status:",
      "Tech Email:",
    ]) assert.ok(out.includes(section), `missing section: ${section}`);
    const techLine = out.split(/\r?\n/).find((l) => l.startsWith("Tech Email:"));
    assert.ok(techLine, "Tech Email must be its own record line");
    assert.ok(techLine.includes(TECH_EMAIL));
    assert.ok(!out.includes("AXIOM{"), "VM #3 carries no flag");
  });

  it("answers case-insensitively and rejects unknown domains", async () => {
    const { buildVm3WhoisResponse } = await import("../server/labs/whois-data.js");
    assert.ok(buildVm3WhoisResponse("EXAMPLE.NET").includes(TECH_EMAIL));
    assert.ok(buildVm3WhoisResponse("domain example.net").includes(TECH_EMAIL));
    assert.ok(buildVm3WhoisResponse("megacorpone.com").startsWith("No match"));
    assert.ok(buildVm3WhoisResponse("no-such-domain-xyz.test").startsWith("No match"));
    assert.ok(buildVm3WhoisResponse("ns2.example.net").includes("Server Name:"));
  });

  it("maps VM #3 to the example.net domain", async () => {
    const { labDomain, labZone, VM2_DOMAIN } = await import("../server/labs/whois-data.js");
    assert.equal(labDomain("m6-6-2-1-whois-vm3"), VM2_DOMAIN);
    assert.equal(labDomain({ slug: "m6-6-2-1-whois-vm3" }), VM2_DOMAIN);
    assert.equal(labZone("m6-6-2-1-whois-vm3").domain, "example.net");
  });

  it("leaves the VM #1 dataset byte-identical", async () => {
    const { buildWhoisResponse } = await import("../server/labs/whois-data.js");
    const out = buildWhoisResponse("megacorpone.com");
    assert.equal(out.length, 1078);
    assert.ok(/ns3\.megacorpone\.com/i.test(out));
    assert.ok(out.includes("whois.gandi.net"));
    assert.ok(!out.toLowerCase().includes("example"));
  });

  it("leaves the VM #2 dataset intact (flag still in DNS section)", async () => {
    const { buildVm2WhoisResponse } = await import("../server/labs/whois-data.js");
    const out = buildVm2WhoisResponse("example.net", "AXIOM{deadbeef0123456789abcdef01234567}");
    assert.equal(out.length, 878);
    assert.ok(out.includes("DNS TXT: axiom-verification=AXIOM{deadbeef0123456789abcdef01234567}"));
    assert.ok(!out.includes("Tech Email:"));
  });
});

describe("vm3 service (sqlite)", () => {
  let svc, db, orch, userId, lab;
  before(async () => {
    db = await import("../server/db.js");
    await db.initDb();
    svc = await import("../server/labs/service.js");
    orch = await import("../server/labs/orchestrator.js");
    const { createUser } = await import("../server/auth.js");
    const u = await createUser({ username: "vm3tester", email: "vm3@test.local", displayName: "VM3", password: "password12345" });
    userId = u.id;
    await svc.seedFromDefinitions(path.join(REPO, "labs"));
    lab = await svc.getLab("slug", VM3_SLUG);
    assert.ok(lab);
  });

  it("shares the course/module/section with VM #1 + VM #2, hash-only objective", async () => {
    const vm1 = await svc.getLab("slug", "m6-6-2-1-whois-vm1");
    const vm2 = await svc.getLab("slug", "m6-6-2-1-whois-vm2");
    assert.equal(lab.course_id, vm1.course_id);
    assert.equal(lab.course_id, vm2.course_id);
    assert.equal(lab.module_number, 6);
    assert.equal(lab.section_number, "6.2.1");
    assert.equal(lab.lab_number, 3);
    const targets = await svc.labTargets(lab.id);
    assert.equal(targets.length, 1);
    assert.equal(targets[0].target_type, "whois-server");
    assert.equal(JSON.parse(targets[0].metadata_json).build, "m6/whois-vm3");
    const objectives = await svc.labObjectives(lab.id);
    assert.equal(objectives.length, 1);
    assert.ok(!("expected_value_hash" in objectives[0]), "hashes must never be served to clients");
  });

  it("full smoke: provision → TCP/43 → Tech Email → submit → reset → stop", async () => {
    const iid = "li_vm3smoke1";
    const local = orch.providerFor("local");
    const details = await local.provision(lab, { id: iid });
    try {
      assert.ok(details.targetIp.startsWith("10."));
      assert.equal(details.targetPort, 43);
      assert.equal(await svc.getRuntimeFlag(iid, "flag"), null, "static lab mints no runtime flag");

      // real TCP/43 query against the provisioned endpoint
      const { host, port } = await orch.resolveEndpoint(
        { target_ip: details.targetIp, target_port: 43, host_endpoint: details.hostEndpoint },
        "example.net",
      );
      const out = await orch.whoisQuery(host, port, "example.net");
      assert.ok(out.includes("Name Server"), "realistic record shape");
      assert.ok(out.includes("DNS Status:"), "DNS information present");
      const techLine = out.split(/\r?\n/).find((l) => l.startsWith("Tech Email:"));
      assert.ok(techLine && techLine.includes(TECH_EMAIL), "Tech Email discoverable in the response");

      // terminal goes over the same real path, scoped to this lab
      const inst = { id: iid, target_ip: details.targetIp, target_port: 43, host_endpoint: details.hostEndpoint, provider: "local", network_cidr: details.networkCidr };
      const t = await orch.runTerminalCommand(inst, `whois example.net -h ${details.targetIp}`, lab);
      assert.ok(t.output.includes(TECH_EMAIL), "terminal returns the live target response");
      const help = await orch.runTerminalCommand(inst, "help", lab);
      assert.ok(help.output.includes("example.net"));
      const targets = await orch.runTerminalCommand(inst, "targets", lab);
      assert.ok(targets.output.includes("VM #3"), "terminal names this lab's target");

      // wrong fails silently; case/space variants pass; exact passes; progress completes
      const bad = await svc.submitAnswer({ userId, lab, objectiveKey: "tech-email", answer: "admin@example.net", instanceId: iid });
      assert.ok(bad.ok && !bad.correct);
      assert.ok(!JSON.stringify(bad).includes(TECH_EMAIL));
      const variant = await svc.submitAnswer({ userId, lab, objectiveKey: "tech-email", answer: "  TECH@EXAMPLE.NET ", instanceId: iid });
      assert.ok(variant.correct, "reasonable case/whitespace differences normalize");
      const p = await svc.labProgress(userId, lab.id);
      assert.ok(p.complete);

      // reset keeps the static answer working on a fresh environment
      await local.destroy({ id: iid, provider_reference: details.providerReference, network_name: details.networkName });
      await svc.clearRuntimeFlags(iid);
      const details2 = await local.provision(lab, { id: iid });
      try {
        const ep2 = await orch.resolveEndpoint(
          { target_ip: details2.targetIp, target_port: 43, host_endpoint: details2.hostEndpoint },
          "example.net",
        );
        const out2 = await orch.whoisQuery(ep2.host, ep2.port, "example.net");
        assert.ok(out2.includes(TECH_EMAIL), "reset environment serves the same record");
        const good2 = await svc.submitAnswer({ userId, lab, objectiveKey: "tech-email", answer: TECH_EMAIL, instanceId: iid });
        assert.ok(good2.correct);
      } finally {
        await local.destroy({ id: iid, provider_reference: details2.providerReference, network_name: details2.networkName });
      }
      await svc.clearRuntimeFlags(iid);
      await assert.rejects(orch.whoisQuery("127.0.0.1", details.hostEndpoint.split(":")[1], "example.net", 1500));
    } finally {
      await local.destroy({ id: iid }).catch(() => {});
      await svc.clearRuntimeFlags(iid).catch(() => {});
    }
  });

  it("VM #1 still answers its own domain (regression)", async () => {
    const local = orch.providerFor("local");
    const d1 = await local.provision(await svc.getLab("slug", "m6-6-2-1-whois-vm1"), { id: "li_vm1reg3" });
    try {
      const out = await orch.whoisQuery("127.0.0.1", d1.hostEndpoint.split(":")[1], "megacorpone.com");
      assert.ok(/ns3\.megacorpone\.com/i.test(out));
      assert.ok(out.includes("whois.gandi.net"));
    } finally {
      await local.destroy({ id: "li_vm1reg3", provider_reference: d1.providerReference, network_name: d1.networkName });
    }
    const r = await svc.submitAnswer({ userId, lab: await svc.getLab("slug", "m6-6-2-1-whois-vm1"), objectiveKey: "third-nameserver", answer: "ns3.megacorpone.com", instanceId: "li_x" });
    assert.ok(r.correct);
  });

  it("VM #2 still serves its runtime flag (regression)", async () => {
    const local = orch.providerFor("local");
    const vm2 = await svc.getLab("slug", "m6-6-2-1-whois-vm2");
    const iid = "li_vm2reg3";
    const d2 = await local.provision(vm2, { id: iid });
    try {
      const stored = await svc.getRuntimeFlag(iid, "flag");
      assert.ok(stored?.flag_value);
      const out = await orch.whoisQuery("127.0.0.1", d2.hostEndpoint.split(":")[1], "example.net");
      assert.ok(out.includes(stored.flag_value));
      assert.ok(!out.includes("Tech Email:"));
      const good = await svc.submitAnswer({ userId, lab: vm2, objectiveKey: "flag", answer: stored.flag_value, instanceId: iid });
      assert.ok(good.correct);
    } finally {
      await local.destroy({ id: iid, provider_reference: d2.providerReference, network_name: d2.networkName });
      await svc.clearRuntimeFlags(iid).catch(() => {});
    }
  });

  it("never leaks the answer through lab reads", async () => {
    for (const row of await svc.labTargets(lab.id)) {
      assert.ok(!JSON.stringify(row).includes(TECH_EMAIL));
    }
    for (const row of await svc.labObjectives(lab.id)) {
      assert.ok(!JSON.stringify(row).includes(TECH_EMAIL));
    }
    const labRow = await svc.getLab("slug", VM3_SLUG);
    assert.ok(!JSON.stringify(labRow).includes(TECH_EMAIL));
    assert.ok(!JSON.stringify(await svc.labProgress(userId, lab.id)).includes(TECH_EMAIL));
    assert.ok(!JSON.stringify(await svc.hintsFor(userId, lab.id)).includes(TECH_EMAIL));
  });

  it("course and module progress include Lab 3 automatically", async () => {
    const cp = await svc.courseProgress(userId, lab.course_id);
    assert.equal(cp.total, 3);
    const mp = await svc.moduleProgress(userId, lab.course_id, 6);
    assert.equal(mp.total, 3);
  });
});

describe("vm3 image wiring", () => {
  it("resolves the vm3 build context and ships a hardened image", async () => {
    const { resolveBuildContext } = await import("../server/labs/orchestrator.js");
    assert.equal(
      resolveBuildContext("axiom-lab-whois-vm3:latest", JSON.stringify({ build: "m6/whois-vm3" })),
      path.resolve(REPO, "lab-images/m6/whois-vm3"),
    );
    assert.equal(resolveBuildContext("axiom-lab-whois-vm3:latest", "{}"), path.resolve(REPO, "lab-images/m6/whois-vm3"));
    const dockerfile = fs.readFileSync(path.join(REPO, "lab-images/m6/whois-vm3/Dockerfile"), "utf8");
    assert.ok(dockerfile.includes("USER whois"), "target must not run as root");
    assert.ok(dockerfile.includes("EXPOSE 43"));
    const py = fs.readFileSync(path.join(REPO, "lab-images/m6/whois-vm3/whois.py"), "utf8");
    assert.ok(py.includes("Tech Email:"), "answer served from the WHOIS record");
    assert.ok(!py.includes("megacorpone"), "no VM #1 behavior inside the VM #3 image");
    assert.ok(!py.includes("AXIOM{"), "no flag machinery inside the VM #3 image");
  });
});
