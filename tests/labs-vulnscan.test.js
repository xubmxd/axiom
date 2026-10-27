import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

// Isolate: temp sqlite file + local provider before any server module loads.
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "axiom-labs-vulnscan-"));
process.env.DATA_DIR = TMP;
process.env.LAB_PROVIDER = "local";

const REPO = path.resolve(import.meta.dirname, "..");

const LABS = {
  install: { section: "7.2.1", slug: "m7-7-2-1-installing-nessus", file: "labs/module-07/7.2.1-installing-nessus/lab.json" },
  components: { section: "7.2.2", slug: "m7-7-2-2-nessus-components", file: "labs/module-07/7.2.2-nessus-components/lab.json" },
  scan: { section: "7.2.3", slug: "m7-7-2-3-vuln-scan", file: "labs/module-07/7.2.3-vuln-scan/lab.json" },
  analyze: { section: "7.2.4", slug: "m7-7-2-4-analyzing-results", file: "labs/module-07/7.2.4-analyzing-results/lab.json" },
  auth: { section: "7.2.5", slug: "m7-7-2-5-auth-scan", file: "labs/module-07/7.2.5-auth-scan/lab.json" },
  plugins: { section: "7.2.6", slug: "m7-7-2-6-nessus-plugins", file: "labs/module-07/7.2.6-nessus-plugins/lab.json" },
};

function readDef(key) {
  return JSON.parse(fs.readFileSync(path.join(REPO, LABS[key].file), "utf8"));
}

describe("vulnscan definitions", () => {
  it("all six labs load under Module 7 with exact sections", async () => {
    const { loadAllDefinitions, validateDefinition, normalizePlacement } = await import("../server/labs/definitions.js");
    const all = loadAllDefinitions(path.join(REPO, "labs"));
    const titles = {
      install: "7.2.1 Installing Nessus",
      components: "7.2.2 Nessus Components",
      scan: "7.2.3 Performing a Vulnerability Scan",
      analyze: "7.2.4 Analyzing the Results",
      auth: "7.2.5 Performing an Authenticated Vulnerability Scan",
      plugins: "7.2.6 Working with Nessus Plugins",
    };
    for (const [key, entry] of Object.entries(LABS)) {
      const lab = all.find((l) => l.def.slug === entry.slug);
      assert.ok(lab, `${entry.slug} must be discovered`);
      assert.deepEqual(validateDefinition(lab.def), [], `${entry.slug} must validate`);
      const p = normalizePlacement(lab.def);
      assert.equal(p.courseSlug, "oscp");
      assert.equal(p.moduleNumber, 7);
      assert.equal(p.moduleTitle, "Vulnerability Scanning");
      assert.equal(p.section, entry.section);
      assert.equal(lab.def.title, titles[key]);
      assert.equal(lab.def.labNumber, 1);
    }
    const sections = new Set(all.filter((l) => normalizePlacement(l.def).moduleNumber === 7).map((l) => normalizePlacement(l.def).section));
    assert.deepEqual([...sections].sort(), ["7.1.1", "7.1.2", "7.1.3", "7.2.1", "7.2.2", "7.2.3", "7.2.4", "7.2.5", "7.2.6"]);
  });

  it("7.2.1 is a single-objective theory lab with no infrastructure", () => {
    const def = readDef("install");
    assert.equal(def.environment.type, "theory");
    assert.equal(def.objectives.length, 1);
    assert.equal(def.objectives[0].key, "service-command");
    assert.equal(def.objectives[0].validation, "exact");
    assert.match(def.objectives[0].expectedHash, /^[0-9a-f]{64}$/);
    assert.equal(def.targets.length, 1);
  });

  it("7.2.2 is a console lab with two objectives", () => {
    const def = readDef("components");
    assert.equal(def.environment.type, "scanner");
    assert.equal(def.objectives.length, 2);
    assert.deepEqual(def.objectives.map((o) => o.key), ["template-category", "web-users"]);
    assert.equal(def.targets.length, 1);
    assert.equal(def.targets[0].type, "scanner-console");
  });

  it("7.2.3/7.2.4/7.2.5/7.2.6 own scanner ranges with exact objectives", () => {
    const expectations = {
      scan: [["apache-maturity", "jetty-version", "sitemap-flag"], 4],
      analyze: [["analysis-maturity", "analysis-version"], 4],
      auth: [["patch-usn", "ssh-kernel"], 4],
      plugins: [["patch-date"], 4],
    };
    for (const [key, [keys, targets]] of Object.entries(expectations)) {
      const def = readDef(key);
      assert.equal(def.environment.type, "scanner", key);
      assert.deepEqual(def.objectives.map((o) => o.key), keys, key);
      for (const o of def.objectives) assert.match(o.expectedHash, /^[0-9a-f]{64}$/);
      const range = def.targets.filter((t) => t.type === "scanner-target");
      assert.equal(range.length, targets, `${key} has four range targets`);
      assert.ok(!def.targets.some((t) => t.type === "attacker"), `${key} has no attacker shell`);
      for (const t of def.targets) {
        assert.ok(t.name && t.image && t.build, "each target needs name/image/build");
        assert.deepEqual(t.ports, [], "no service ports in the definition");
      }
    }
    // 7.2.4 invents no source question: its objectives analyze the same
    // source-backed 7.2.3 discoveries (documented in the fidelity report).
    const a43 = readDef("scan").objectives.map((o) => o.expectedHash).sort();
    const a44 = readDef("analyze").objectives.map((o) => o.expectedHash).sort();
    assert.deepEqual(a44, a43.filter((h) => a44.includes(h)), "7.2.4 answers are a subset of 7.2.3 answers");
  });

  it("stored hashes match every known answer", async () => {
    const { verifyAnswer } = await import("../server/labs/answers.js");
    const cases = [
      ["install", "service-command", "sudo systemctl start nessusd", "exact"],
      ["components", "template-category", "vulnerabilities", "case-insensitive-exact"],
      ["components", "web-users", "1024", "exact"],
      ["scan", "apache-maturity", "functional", "case-insensitive-exact"],
      ["scan", "jetty-version", "9.4.43.v20210629", "exact"],
      ["analyze", "analysis-maturity", "functional", "case-insensitive-exact"],
      ["analyze", "analysis-version", "9.4.43.v20210629", "exact"],
      ["auth", "patch-usn", "USN-5079-1", "exact"],
      ["auth", "ssh-kernel", "5.4.0-42-generic", "exact"],
      ["plugins", "patch-date", "January 26,2021", "exact"],
    ];
    for (const [lab, key, ans, validation] of cases) {
      const def = readDef(lab);
      const o = def.objectives.find((x) => x.key === key);
      assert.ok(verifyAnswer(ans, o.expectedHash, validation), `${lab}/${key} accepts the source answer`);
    }
  });

  it("hints never state graded values; framing terms stay in objectives", () => {
    const banned = ["sudo systemctl start nessusd", "1024", "functional", "9.4.43", "USN-5079-1", "5.4.0-42", "January 26,2021", "AXIOM{"];
    for (const key of Object.keys(LABS)) {
      const def = readDef(key);
      const hints = JSON.stringify(def.hints);
      for (const b of banned) assert.ok(!hints.includes(b), `${key} hint leaks ${b}`);
      const instr = JSON.stringify(def.instructions);
      for (const b of banned) assert.ok(!instr.includes(b), `${key} instructions leak ${b}`);
    }
    // Answer terms appear in objectives by design (the questions themselves);
    // hints must not restate them as answers.
    const c = readDef("components");
    assert.ok(!JSON.stringify(c.hints).toLowerCase().includes("vulnerabilities"));
  });
});

describe("scanner engine + targets (no DB)", () => {
  it("port specifications parse strictly", async () => {
    const { parsePorts } = await import("../server/labs/scanner-engine.js");
    assert.deepEqual(parsePorts("80"), [80]);
    assert.deepEqual(parsePorts("80, 8080,9999"), [80, 8080, 9999]);
    assert.deepEqual(parsePorts("20-22"), [20, 21, 22]);
    for (const bad of ["", "abc", "0", "65536", "80-79", "1-5000", "80; rm"]) {
      assert.throws(() => parsePorts(bad), /port|ports/i, `rejects ${JSON.stringify(bad)}`);
    }
  });

  it("plugin filter matches by name/family and rejects nothing silently", async () => {
    const { matchPlugins, PLUGINS } = await import("../server/labs/scanner-plugins.js");
    assert.equal(matchPlugins("").length, Object.keys(PLUGINS).length);
    assert.ok(matchPlugins("apache").every((p) => /apache/i.test(p.name + p.family)));
    assert.ok(matchPlugins("apache").length >= 1);
    assert.ok(matchPlugins("patch report").some((p) => p.id === "ax-curl-usn"));
    assert.deepEqual(matchPlugins("zzz-no-such-plugin"), []);
  });

  it("live roles: Apache traversal, Jetty header, crawlable graphs with one flag page", async () => {
    const { startScanRole } = await import("../server/labs/vuln-targets.js");
    const { crawlSite, tcpConnect } = await import("../server/labs/scanner-engine.js");
    const apache = await startScanRole("scan-apache", { host: "127.0.0.1" });
    const jetty = await startScanRole("scan-jetty", { host: "127.0.0.1" });
    const webA = await startScanRole("scan-web-a", { host: "127.0.0.1" });
    const webB = await startScanRole("scan-web-b", { host: "127.0.0.1", flag: "AXIOM{testflag}" });
    try {
      const get = (port, p) => new Promise((resolve) => {
        import("node:http").then(({ default: http }) => {
          http.get({ host: "127.0.0.1", port, path: p, timeout: 4000 }, (res) => {
            let b = "";
            res.on("data", (d) => { b += d; });
            res.on("end", () => resolve({ status: res.statusCode, server: res.headers.server, body: b }));
          }).on("error", () => resolve(null));
        });
      });
      const a = await get(apache.ports.http80, "/");
      assert.ok(a.server.includes("2.4.49"), "Apache banner observable");
      const trav = await get(apache.ports.http80, "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd");
      assert.equal(trav.status, 200);
      assert.ok(trav.body.includes("root:x:0:0:root:"), "traversal behavior observable");
      const plain = await get(apache.ports.http80, "/index.html");
      assert.equal(plain.status, 200, "benign paths stay benign");
      const j = await get(jetty.ports.http8080, "/");
      assert.ok(j.server.includes("9.4.43.v20210629"), "Jetty version observable");
      for (const [h, key] of [[apache, "http9999"], [jetty, "http9999"], [webA, "http9999"]]) {
        const pages = await crawlSite("127.0.0.1", h.ports[key], { maxPages: 60 });
        assert.ok(pages.length >= 3, "graph crawls multiple pages");
        for (const p of pages) {
          const content = await get(h.ports[key], p.path);
          assert.ok(!/AXIOM\{testflag\}/.test(content.body), "no flag outside graph D");
        }
      }
      const pagesB = await crawlSite("127.0.0.1", webB.ports.http9999, { maxPages: 60 });
      const flagged = [];
      for (const p of pagesB) {
        const content = await get(webB.ports.http9999, p.path);
        if (/AXIOM\{testflag\}/.test(content.body)) flagged.push(p);
      }
      assert.equal(flagged.length, 1, "exactly one crawled page carries the flag");
      assert.ok(flagged[0].path.split("/").length > 2, "flag page is discovered through links, not at root");
      assert.ok(await tcpConnect("127.0.0.1", apache.ports.http80, 2000));
      assert.ok(!await tcpConnect("127.0.0.1", 1, 500));
    } finally {
      await apache.close(); await jetty.close(); await webA.close(); await webB.close();
    }
  });

  it("live SSH sidecar: genuine auth, fixture facts, wrong password fails", async () => {
    const { startScanRole } = await import("../server/labs/vuln-targets.js");
    const { sshExec } = await import("../server/labs/scanner-engine.js");
    const h = await startScanRole("scan-apache", { host: "127.0.0.1", ssh: { user: "scanner", password: "pw-for-test", port: 0 } });
    try {
      assert.ok(h.sshPort > 0, "sidecar reports its bound port");
      const uname = await sshExec({ host: "127.0.0.1", port: h.sshPort, user: "scanner", password: "pw-for-test", command: "uname -a" });
      assert.ok(uname.output.includes("5.4.0-42-generic"));
      const inv = JSON.parse((await sshExec({ host: "127.0.0.1", port: h.sshPort, user: "scanner", password: "pw-for-test", command: "cat /etc/axiom-scan/inventory.json" })).output);
      assert.equal(inv.os.version, "21.04");
      assert.equal(inv.packages.curl.filter((e) => e.oses.includes("Ubuntu 21.04")).length, 1);
      await assert.rejects(
        sshExec({ host: "127.0.0.1", port: h.sshPort, user: "scanner", password: "wrong", command: "uname -a" }),
        /authentication failed/i
      );
    } finally {
      await h.close();
    }
  });

  it("ships canonical modules to the image (no drift)", async () => {
    for (const f of ["vuln-targets.js", "vuln-ssh-server.py"]) {
      const a = fs.readFileSync(path.join(REPO, "server/labs", f), "utf8");
      const b = fs.readFileSync(path.join(REPO, "lab-images/m7/scan-723", f), "utf8");
      assert.equal(a, b, `${f} copy must match the canonical module`);
    }
    const dockerfile = fs.readFileSync(path.join(REPO, "lab-images/m7/scan-723/Dockerfile"), "utf8");
    assert.ok(dockerfile.includes("TARGET_ROLE"), "personality comes from env, not the image");
    assert.ok(!/USN-5079|5\.4\.0-42|January 26|AXIOM\{/i.test(dockerfile), "no answers in the image definition");
  });

  it("image build context resolves", async () => {
    const { resolveBuildContext } = await import("../server/labs/orchestrator.js");
    assert.equal(resolveBuildContext("axiom-lab-scan-723:latest", JSON.stringify({ build: "m7/scan-723" })), path.resolve(REPO, "lab-images/m7/scan-723"));
  });
});

describe("vulnscan service + HTTP E2E", () => {
  const PORT = 3469;
  const BASE = `http://127.0.0.1:${PORT}`;
  let child, cookie;
  const labIds = {};
  before(async () => {
    const db = await import("../server/db.js");
    await db.initDb();
    const svc = await import("../server/labs/service.js");
    const { createUser } = await import("../server/auth.js");
    try {
      await createUser({ username: "vulnhttp", email: "vh@test.local", displayName: "VH", password: "password12345" });
    } catch { /* exists on re-runs */ }
    await svc.seedFromDefinitions(path.join(REPO, "labs"));
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
    const r = await fetch(`${BASE}/login`, {
      method: "POST", redirect: "manual",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ identifier: "vulnhttp", password: "password12345" }),
    });
    assert.equal(r.status, 302);
    cookie = (r.headers.get("set-cookie") || "").split(";")[0];
    const found = (await (await fetch(`${BASE}/api/labs`, { headers: { Cookie: cookie } })).json()).labs;
    for (const [key, entry] of Object.entries(LABS)) {
      labIds[key] = found.find((l) => l.slug === entry.slug).id;
      assert.ok(labIds[key], entry.slug);
    }
  });
  after(() => { try { child.kill(); } catch {} });

  const get = (p, opts = {}) => fetch(`${BASE}${p}`, { redirect: "manual", headers: { Cookie: cookie }, ...opts });
  const post = (p, body) => fetch(`${BASE}${p}`, {
    method: "POST", headers: { Cookie: cookie, "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const start = async (key) => {
    const r = await post(`/api/labs/${labIds[key]}/start`);
    assert.equal(r.status, 200);
    return r.json();
  };
  const launch = async (key, config) => {
    const r = await post(`/api/labs/${labIds[key]}/scanner/scans`, config);
    const j = await r.json();
    assert.equal(r.status, 200, `launch failed: ${JSON.stringify(j).slice(0, 200)}`);
    return j.scan;
  };
  const waitJob = async (key, jobId, timeoutMs = 120000) => {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const j = await (await get(`/api/labs/${labIds[key]}/scanner/scans/${jobId}`)).json();
      if (j.scan.status === "complete") return j;
      if (j.scan.status === "failed") throw new Error(`scan failed: ${j.scan.error}`);
      if (Date.now() > deadline) throw new Error("scan did not complete in time");
      await new Promise((r) => setTimeout(r, 1500));
    }
  };
  const submit = async (key, answers) => (await (await post(`/api/labs/${labIds[key]}/submit`, { answers })).json());

  it("7.2.1 student path: start, wrong rejected, command accepted, persistence", async () => {
    await start("install");
    let r = await submit("install", { "service-command": "systemctl start nessusd" });
    assert.equal(r.results["service-command"].correct, false, "partial command rejected");
    r = await submit("install", { "service-command": "" });
    assert.equal(r.results["service-command"].correct, false, "blank rejected");
    r = await submit("install", { "service-command": "SUDO SYSTEMCTL START NESSUSD" });
    assert.equal(r.results["service-command"].correct, false, "command semantics preserved (case-sensitive)");
    r = await submit("install", { "service-command": "  sudo systemctl start nessusd  " });
    assert.ok(r.results["service-command"].correct, "surrounding whitespace normalized");
    assert.ok(r.progress.complete, "single objective completes the lab");
    const st = await (await get(`/api/labs/${labIds.install}/status`)).json();
    assert.ok(st.progress.complete, "completion persists");
    await post(`/api/labs/${labIds.install}/stop`);
    const st2 = await (await get(`/api/labs/${labIds.install}/status`)).json();
    assert.ok(st2.progress.complete, "completion survives stop");
  });

  it("7.2.1 workspace has no terminal, no fake daemon, no answer", async () => {
    const html = await (await get(`/labs/oscp/${LABS.install.slug}`)).text();
    assert.ok(html.includes("7.2.1") && html.includes("Installing Nessus"));
    assert.ok(!html.includes("termForm"), "no terminal card");
    assert.ok(!html.includes("sudo systemctl start nessusd"), "no command answer in HTML");
    assert.ok(!html.includes("expectedHash"), "no answer metadata");
    for (const marker of ["Submit Answer", "Lab Progress", "Connection", "Notes"]) assert.ok(html.includes(marker));
  });

  it("7.2.2 student path: inspect console state, answer both, negatives", async () => {
    await start("components");
    const cfg = await (await get(`/api/labs/${labIds.components}/scanner/config`)).json();
    assert.deepEqual(cfg.categories, ["DISCOVERY", "COMPLIANCE", "VULNERABILITIES"]);
    assert.equal(cfg.advanced.concurrentWebUsers, 1024, "value comes from live configuration");
    const html = await (await get(`/labs/oscp/${LABS.components.slug}`)).text();
    assert.ok(!html.toLowerCase().includes("vulnerabilities"), "landing page must not print the category answer");
    assert.ok(!/\b1024\b/.test(html), "landing page must not print the settings value");
    let r = await submit("components", { "template-category": "discovery", "web-users": "1024" });
    assert.equal(r.results["template-category"].correct, false);
    assert.equal(r.results["web-users"].correct, true, "one correct answer completes only its objective");
    assert.ok(!r.progress.complete);
    r = await submit("components", { "template-category": "VULNERABILITIES", "web-users": "2048" });
    assert.equal(r.results["template-category"].correct, true, "case normalized");
    assert.equal(r.results["web-users"].correct, false);
    r = await submit("components", { "template-category": "vulnerabilities", "web-users": "1024" });
    assert.ok(r.progress.complete, "2/2 completes the lab");
    await post(`/api/labs/${labIds.components}/stop`);
  });

  it("7.2.3 student path: full scan finds Apache maturity", async function () {
    const { instance } = await start("scan");
    const base = instance.networkCidr.split(".").slice(0, 3).join(".");
    const cfg = await (await get(`/api/labs/${labIds.scan}/scanner/config`)).json();
    assert.equal(cfg.targets.length, 4, "four-target range");
    const job = await launch("scan", {
      name: "full", template: "basic",
      targets: cfg.targets.map((t) => t.ip), ports: "80,8080,9999",
    });
    const done = await waitJob("scan", job.id);
    const apache = done.findings.filter((f) => f.pluginId === "ax-apache-traversal");
    assert.equal(apache.length, 1, "exactly one Apache finding from real detection");
    assert.ok(apache[0].targetIp.endsWith(".151"), "Apache finding on VM #1");
    assert.equal(apache[0].details["Exploit Code Maturity"], "functional");
    const r = await submit("scan", { "apache-maturity": "functional" });
    assert.ok(r.results["apache-maturity"].correct);
    // Bad scan configuration is rejected, not silently fixed.
    const bad = await post(`/api/labs/${labIds.scan}/scanner/scans`, { name: "x", ports: "abc" });
    assert.equal(bad.status, 400);
    const foreign = await post(`/api/labs/${labIds.scan}/scanner/scans`, { name: "x", ports: "80", targets: ["10.99.99.99"] });
    assert.equal(foreign.status, 400, "foreign targets rejected");
  }, { timeout: 240000 });

  it("7.2.3 port-8080 scan: Jetty version from observable behavior", async function () {
    const { instance } = await start("scan");
    const base = instance.networkCidr.split(".").slice(0, 3).join(".");
    const job = await launch("scan", {
      name: "8080-only", template: "basic",
      targets: [`${base}.151`, `${base}.11`, `${base}.12`, `${base}.13`], ports: "8080",
    });
    const done = await waitJob("scan", job.id);
    assert.ok(!done.findings.some((f) => f.pluginId === "ax-apache-traversal"), "8080-only scan never probes :80 findings");
    const jetty = done.findings.filter((f) => f.pluginId === "ax-http-multiple");
    assert.equal(jetty.length, 1, "exactly one grouped Jetty finding");
    assert.equal(jetty[0].details["HTTP Server Type and Version"], "9.4.43.v20210629");
    const r = await submit("scan", { "jetty-version": "9.4.43.v20210629" });
    assert.ok(r.results["jetty-version"].correct);
    const w = await submit("scan", { "jetty-version": "9.4.44.v20210629" });
    assert.ok(!w.results["jetty-version"].correct, "near-miss versions rejected");
  }, { timeout: 240000 });

  it("7.2.3 sitemap workflow: real crawl discovers the flag page", async function () {
    const { instance } = await start("scan");
    const base = instance.networkCidr.split(".").slice(0, 3).join(".");
    // Webapp crawling requires the assessment flag: without it, no sitemap.
    const plain = await launch("scan", {
      name: "no-webapp", template: "basic",
      targets: [`${base}.13`], ports: "9999",
      assessment: { mode: "default", webapp: false },
    });
    const plainDone = await waitJob("scan", plain.id);
    assert.equal(plainDone.sitemap.length, 0, "no crawl without web-application assessment");
    const job = await launch("scan", {
      name: "webapp", template: "basic",
      targets: [`${base}.151`, `${base}.11`, `${base}.12`, `${base}.13`], ports: "9999",
      assessment: { mode: "custom", webapp: true },
    });
    const done = await waitJob("scan", job.id);
    assert.ok(done.sitemap.length >= 10, "crawler discovers pages across hosts");
    const byHost = new Map();
    for (const p of done.sitemap) byHost.set(p.targetIp, (byHost.get(p.targetIp) || 0) + 1);
    assert.equal(byHost.size, 4, "all four web services crawled");
    assert.ok(!JSON.stringify(done.sitemap).match(/AXIOM\{[0-9a-f]{32}\}/), "sitemap metadata carries no flag");
    // Every listed page opens; exactly one holds the flag.
    let flag = "";
    for (const p of done.sitemap) {
      const r = await get(`/api/labs/${labIds.scan}/scanner/page?jobId=${job.id}&url=${encodeURIComponent(p.url)}`);
      const body = await r.json();
      assert.equal(r.status, 200, `page opens: ${p.url}`);
      const m = /AXIOM\{[0-9a-f]{32}\}/.exec(body.page.html || "");
      if (m) {
        assert.equal(flag, "", "flag in exactly one discovered page");
        flag = m[0];
        assert.ok(p.path.split("/").length > 2, "flag page found through links, not at root");
      }
    }
    assert.ok(flag, "flag retrieved from a discovered page");
    // Undiscovered URLs are not fetchable (no open proxy).
    const bad = await get(`/api/labs/${labIds.scan}/scanner/page?jobId=${job.id}&url=${encodeURIComponent(`http://${base}.13:9999/admin`)}`);
    assert.equal(bad.status, 404);
    const r = await submit("scan", { "sitemap-flag": flag });
    assert.ok(r.results["sitemap-flag"].correct);
    assert.ok(r.progress.complete, "3/3 completes the lab");
    const wrong = await submit("scan", { "sitemap-flag": "AXIOM{00000000000000000000000000000000}" });
    assert.ok(!wrong.results["sitemap-flag"].correct);
  }, { timeout: 300000 });

  it("7.2.3 reset rotates the sitemap flag; stale flags die", async function () {
    const first = await start("scan");
    const base1 = first.instance.networkCidr.split(".").slice(0, 3).join(".");
    const j1 = await launch("scan", {
      name: "w", template: "basic", targets: [`${base1}.13`], ports: "9999",
      assessment: { mode: "custom", webapp: true },
    });
    const d1 = await waitJob("scan", j1.id);
    let f1 = "";
    for (const p of d1.sitemap) {
      const body = await (await get(`/api/labs/${labIds.scan}/scanner/page?jobId=${j1.id}&url=${encodeURIComponent(p.url)}`)).json();
      const m = /AXIOM\{[0-9a-f]{32}\}/.exec(body.page.html || "");
      if (m) { f1 = m[0]; break; }
    }
    assert.ok(f1, "flag retrieved before reset");
    await post(`/api/labs/${labIds.scan}/reset`);
    const st = await (await get(`/api/labs/${labIds.scan}/status`)).json();
    const base2 = st.instance.networkCidr.split(".").slice(0, 3).join(".");
    const j2 = await launch("scan", {
      name: "w2", template: "basic", targets: [`${base2}.13`], ports: "9999",
      assessment: { mode: "custom", webapp: true },
    });
    const d2 = await waitJob("scan", j2.id);
    assert.ok(d2.sitemap.length > 0, "range works after reset");
    const old = await submit("scan", { "sitemap-flag": f1 });
    assert.ok(!old.results["sitemap-flag"].correct, "pre-reset flag no longer validates");
    await post(`/api/labs/${labIds.scan}/stop`);
  }, { timeout: 300000 });

  it("7.2.4 analysis: findings UI over a real scan, no invented exercise", async function () {
    const { instance } = await start("analyze");
    const base = instance.networkCidr.split(".").slice(0, 3).join(".");
    const labRow = await (await get(`/api/labs/${labIds.analyze}`)).json();
    assert.deepEqual(labRow.objectives.map((o) => o.objective_key), ["analysis-maturity", "analysis-version"]);
    const job = await launch("analyze", {
      name: "analyze", template: "basic",
      targets: [`${base}.151`, `${base}.11`, `${base}.12`, `${base}.13`], ports: "80,8080",
    });
    const done = await waitJob("analyze", job.id);
    assert.ok(done.findings.length >= 2, "real findings to analyze");
    const ap = done.findings.find((f) => f.pluginId === "ax-apache-traversal");
    const jt = done.findings.find((f) => f.pluginId === "ax-http-multiple");
    assert.ok(ap && jt, "both source-backed discoveries present");
    // Finding details endpoint exposes the same evidence the UI shows.
    const det = await (await get(`/api/labs/${labIds.analyze}/scanner/findings/${ap.id}`)).json();
    assert.equal(det.finding.details["Exploit Code Maturity"], "functional");
    assert.ok(det.finding.remediation, "remediation present");
    assert.ok(!JSON.stringify(det).match(/expectedHash|answer"|flag/));
    let r = await submit("analyze", { "analysis-maturity": "unproven", "analysis-version": "9.4.43.v20210629" });
    assert.equal(r.results["analysis-maturity"].correct, false);
    assert.equal(r.results["analysis-version"].correct, true);
    assert.ok(!r.progress.complete, "one correct answer is not completion");
    r = await submit("analyze", { "analysis-maturity": "functional", "analysis-version": "9.4.43.v20210629" });
    assert.ok(r.progress.complete, "2/2 completes the lab");
    await post(`/api/labs/${labIds.analyze}/stop`);
  }, { timeout: 240000 });

  it("7.2.5 authenticated scan: Patch Report USN + SSH kernel", async function () {
    const { instance } = await start("auth");
    const base = instance.networkCidr.split(".").slice(0, 3).join(".");
    // Credentials come from the owner-scoped Connection tab, nothing else.
    const html = await (await get(`/labs/oscp/${LABS.auth.slug}`)).text();
    const user = /SSH username<\/dt><dd class="mono">([^<]+)<\/dd>/.exec(html)?.[1];
    const password = /SSH password<\/dt><dd class="mono">([^<]+) <button/.exec(html)?.[1];
    assert.equal(user, "scanner");
    assert.ok(password && !password.includes("AXIOM{"), "per-session password, never flag-formatted");
    // Unauthenticated scan finds no auth findings (proves auth matters).
    const anon = await launch("auth", { name: "anon", template: "basic", targets: [`${base}.151`], ports: "22" });
    const anonDone = await waitJob("auth", anon.id);
    assert.ok(!anonDone.findings.some((f) => f.family === "Patch Report"), "no patch findings without credentials");
    // Wrong password authenticates nothing.
    const bad = await launch("auth", {
      name: "bad", template: "basic", targets: [`${base}.151`], ports: "22",
      auth: { user: "scanner", password: "wrong-password" },
    });
    const badDone = await waitJob("auth", bad.id);
    assert.ok(!badDone.findings.some((f) => f.family === "Patch Report"), "wrong password yields no findings");
    // Genuine authenticated scan.
    const job = await launch("auth", {
      name: "auth", template: "basic", targets: [`${base}.151`], ports: "22",
      auth: { user, password },
    });
    const done = await waitJob("auth", job.id);
    const curl = done.findings.filter((f) => f.family === "Patch Report");
    assert.ok(curl.length >= 2, "multiple curl findings enumerated");
    const hirsute = curl.filter((f) => (f.details["Affected releases"] || "").split(", ").includes("Ubuntu 21.04"));
    assert.equal(hirsute.length, 1, "exactly one curl finding affects Ubuntu 21.04");
    assert.equal(hirsute[0].details["USN"], "USN-5079-1");
    const osf = done.findings.find((f) => f.pluginId === "ax-ssh-os-ident");
    assert.ok(osf, "SSH identification finding present");
    assert.ok(osf.evidence.includes("uname -a"), "evidence cites the uname channel");
    assert.ok(osf.details["Data provenance"].includes("genuine SSH"), "fixture provenance labeled");
    let r = await submit("auth", { "patch-usn": "USN-5079-2", "ssh-kernel": "5.4.0-42-generic" });
    assert.equal(r.results["patch-usn"].correct, false, "sibling USN rejected");
    assert.equal(r.results["ssh-kernel"].correct, true);
    r = await submit("auth", { "patch-usn": "USN-5079-1", "ssh-kernel": "5.4.0-42-generic" });
    assert.ok(r.progress.complete, "2/2 completes the lab");
    await post(`/api/labs/${labIds.auth}/stop`);
  }, { timeout: 300000 });

  it("7.2.6 plugin filter isolates the finding; Patch Pub Date validates", async function () {
    const { instance } = await start("plugins");
    const base = instance.networkCidr.split(".").slice(0, 3).join(".");
    const all = [`${base}.151`, `${base}.11`, `${base}.12`, `${base}.13`];
    const open = await launch("plugins", { name: "open", template: "basic", targets: all, ports: "80,8080" });
    const openDone = await waitJob("plugins", open.id);
    assert.ok(openDone.findings.length >= 2, "unfiltered scan surfaces multiple findings");
    const filt = await launch("plugins", {
      name: "filtered", template: "basic", targets: all, ports: "80,8080", pluginFilter: "apache",
    });
    const filtDone = await waitJob("plugins", filt.id);
    assert.ok(filtDone.findings.length >= 1, "filter keeps the Apache finding");
    assert.ok(filtDone.findings.every((f) => f.pluginId === "ax-apache-traversal"), "filter excludes everything else");
    const det = await (await get(`/api/labs/${labIds.plugins}/scanner/findings/${filtDone.findings[0].id}`)).json();
    assert.equal(det.finding.details["Patch Pub Date"], "January 26,2021");
    let r = await submit("plugins", { "patch-date": "January 26, 2021" });
    assert.equal(r.results["patch-date"].correct, false, "exact source wording required");
    r = await submit("plugins", { "patch-date": "January 26,2021" });
    assert.ok(r.results["patch-date"].correct && r.progress.complete);
    await post(`/api/labs/${labIds.plugins}/stop`);
  }, { timeout: 300000 });

  it("scanner APIs never leak validators, secrets, or cross-instance jobs", async () => {
    const { instance } = await start("scan");
    const base = instance.networkCidr.split(".").slice(0, 3).join(".");
    const job = await launch("scan", { name: "leak", template: "basic", targets: [`${base}.151`], ports: "80" });
    const done = await waitJob("scan", job.id);
    const blob = JSON.stringify(done);
    assert.ok(!blob.match(/expectedHash|expected_value_hash|flag_value|flag-value/i), "no validator metadata");
    assert.ok(!blob.match(/"answer"\s*:/), "no answer field");
    assert.ok(!blob.match(/scan-[0-9a-f]{16}/), "no SSH password in scan payloads");
    // Cross-lab job access is rejected.
    await start("analyze");
    const cross = await get(`/api/labs/${labIds.analyze}/scanner/scans/${job.id}`);
    assert.equal(cross.status, 404, "jobs are instance-scoped");
    await post(`/api/labs/${labIds.scan}/stop`);
    await post(`/api/labs/${labIds.analyze}/stop`);
  }, { timeout: 240000 });
});
