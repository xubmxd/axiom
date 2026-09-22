import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// Isolate: temp sqlite file before any server module loads.
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "axiom-labs-vpn-"));
process.env.DATA_DIR = TMP;
process.env.LAB_PROVIDER = "local";
delete process.env.VPN_ENABLED;
delete process.env.VPN_ENDPOINT_HOST;

const REPO = path.resolve(import.meta.dirname, "..");

describe("vpn pure helpers", () => {
  it("generates unique wg-compatible keypairs", async () => {
    const vpn = await import("../server/labs/vpn.js");
    const a = vpn.generateKeypair();
    const b = vpn.generateKeypair();
    assert.ok(vpn.isWgKey(a.privateKey) && vpn.isWgKey(a.publicKey));
    assert.notEqual(a.privateKey, b.privateKey);
    assert.notEqual(a.publicKey, b.publicKey);
    assert.ok(!vpn.isWgKey("") && !vpn.isWgKey("not-a-key") && !vpn.isWgKey("a".repeat(44)));
  });

  it("renders a complete client pack with no server secret", async () => {
    const vpn = await import("../server/labs/vpn.js");
    const kp = vpn.generateKeypair();
    const conf = vpn.buildClientConf({
      privateKey: kp.privateKey, clientIp: "10.212.0.7",
      serverPublicKey: kp.publicKey, endpointHost: "vpn.example.local",
      endpointPort: 51820, allowedIps: "10.210.0.0/16",
    });
    assert.ok(conf.includes("[Interface]") && conf.includes("[Peer]"));
    assert.ok(conf.includes(`PrivateKey = ${kp.privateKey}`));
    assert.ok(conf.includes("Address = 10.212.0.7/32"));
    assert.ok(conf.includes("Endpoint = vpn.example.local:51820"));
    assert.ok(conf.includes("AllowedIPs = 10.210.0.0/16"));
    assert.ok(conf.includes("PersistentKeepalive = 25"));
    assert.equal(conf.match(/PrivateKey = /g).length, 1);
  });

  it("derives addressing from env with collision guard", async () => {
    const vpn = await import("../server/labs/vpn.js");
    assert.equal(vpn.labSupernet(), "10.210.0.0/16");
    assert.equal(vpn.vpnGatewayIp(), "10.212.0.1");
    assert.equal(vpn.vpnCidr(), "10.212.0.0/24");
    assert.ok(vpn.vpnAddressPlanSafe());
    process.env.VPN_SUBNET_BASE = "10.210";
    assert.ok(!vpn.vpnAddressPlanSafe(), "VPN base must not swallow lab subnets");
    process.env.VPN_SUBNET_BASE = "10.200";
    assert.ok(!vpn.vpnAddressPlanSafe(), "VPN base must not collide with local display nets");
    delete process.env.VPN_SUBNET_BASE;
    assert.ok(vpn.vpnAddressPlanSafe());
  });

  it("allocates tunnel IPs densely and reports exhaustion", async () => {
    const vpn = await import("../server/labs/vpn.js");
    assert.equal(vpn.allocClientIp([]), "10.212.0.2");
    assert.equal(vpn.allocClientIp(new Set(["10.212.0.2"])), "10.212.0.3");
    assert.equal(vpn.allocClientIp(["10.212.0.2", "10.212.0.4"]), "10.212.0.3");
    const full = [];
    for (let n = 2; n <= 254; n++) full.push(`10.212.0.${n}`);
    assert.equal(vpn.allocClientIp(full), null);
  });

  it("builds exact per-instance firewall specs", async () => {
    const vpn = await import("../server/labs/vpn.js");
    assert.equal(vpn.aclTag("u_x", "10.210.1.10"), "axiom-vpn:u_x:10.210.1.10");
    const specs = vpn.aclRuleSpecs({ userId: "u_x", clientIp: "10.212.0.2", targetIp: "10.210.1.10" });
    assert.equal(specs.length, 3);
    for (const [i, proto] of ["tcp", "udp", "icmp"].entries()) {
      assert.ok(specs[i].includes(proto));
      assert.ok(specs[i].includes("10.212.0.2/32") && specs[i].includes("10.210.1.10/32"));
      assert.ok(specs[i].includes("axiom-vpn:u_x:10.210.1.10"));
      assert.ok(specs[i].includes("ACCEPT"));
    }
    const other = vpn.aclRuleSpecs({ userId: "u_y", clientIp: "10.212.0.3", targetIp: "10.210.1.10" });
    assert.ok(!JSON.stringify(specs).includes("axiom-vpn:u_y"), "rules are scoped per student");
    assert.ok(JSON.stringify(other).includes("axiom-vpn:u_y"));
  });
});

describe("vpn disabled behavior (no docker needed)", () => {
  it("reports disabled status without touching docker", async () => {
    const vpn = await import("../server/labs/vpn.js");
    const st = await vpn.vpnStatus("anyone");
    assert.equal(st.enabled, false);
    assert.equal(st.configured, false);
    assert.equal(st.gateway, false);
  });

  it("refuses pack operations with clear errors", async () => {
    const vpn = await import("../server/labs/vpn.js");
    for (const fn of [() => vpn.ensureVpnClient("u"), () => vpn.clientConfFor("u"), () => vpn.regenerateVpnClient("u")]) {
      await assert.rejects(fn, (e) => e.name === "VpnError" && e.status === 503 && /not enabled/i.test(e.message));
    }
  });

  it("lifecycle hooks no-op cleanly when disabled", async () => {
    const vpn = await import("../server/labs/vpn.js");
    assert.deepEqual((await vpn.syncInstanceVpn({ id: "x", provider: "docker", network_name: "n", target_ip: "10.0.0.1" })).synced, false);
    assert.deepEqual((await vpn.unsyncInstanceVpn({ id: "x", provider: "docker", network_name: "n" })).synced, false);
    assert.deepEqual((await vpn.syncInstanceVpn({ id: "x", provider: "local", network_name: "local-x" })).synced, false);
    assert.deepEqual((await vpn.reconcileVpn()).reconciled, false);
  });

  it("gateway probe fails safe without a daemon", async () => {
    const orch = await import("../server/labs/orchestrator.js");
    if (await orch.dockerAvailable()) return; // daemon hosts skip: probe may succeed
    const vpn = await import("../server/labs/vpn.js");
    assert.equal(await vpn.gatewayAvailable(), false);
  });
});

describe("vpn identity store (sqlite)", () => {
  let vpn, userId;
  before(async () => {
    const db = await import("../server/db.js");
    await db.initDb();
    vpn = await import("../server/labs/vpn.js");
    const { createUser } = await import("../server/auth.js");
    const u = await createUser({ username: "vpntester", email: "vpn@test.local", displayName: "V", password: "password12345" });
    userId = u.id;
  });
  after(() => { delete process.env.VPN_ENABLED; delete process.env.VPN_ENDPOINT_HOST; });

  it("starts with no client and revokes idempotently", async () => {
    assert.equal(await vpn.getVpnClient(userId), null);
    assert.deepEqual(await vpn.revokeVpnClient(userId), { ok: true });
  });

  it("still refuses without endpoint/gateway when enabled", async () => {
    process.env.VPN_ENABLED = "1";
    delete process.env.VPN_ENDPOINT_HOST;
    await assert.rejects(vpn.ensureVpnClient(userId), /endpoint/i);
    process.env.VPN_ENDPOINT_HOST = "vpn.example.local";
    const orch = await import("../server/labs/orchestrator.js");
    if (await orch.dockerAvailable()) return; // live-gateway hosts go further in manual validation
    await assert.rejects(vpn.ensureVpnClient(userId), /gateway is not running/i);
    await assert.rejects(vpn.clientConfFor(userId), /No VPN pack yet|gateway is not running/i);
  });
});

describe("vpn http routes", () => {
  const PORT = 3461;
  const BASE = `http://127.0.0.1:${PORT}`;
  let child, cookie;
  before(async () => {
    const { spawn } = await import("node:child_process");
    child = spawn("node", ["server/index.js"], {
      cwd: REPO, env: { ...process.env, PORT: String(PORT), DATA_DIR: TMP, LAB_PROVIDER: "local" },
      stdio: "ignore",
    });
    const deadline = Date.now() + 20000;
    for (;;) {
      try { const r = await fetch(`${BASE}/login`); if (r.ok) break; } catch {}
      if (Date.now() > deadline) throw new Error("test server did not boot");
      await new Promise((r) => setTimeout(r, 200));
    }
    const db = await import("../server/db.js");
    try { await db.initDb(); } catch {}
    const { createUser } = await import("../server/auth.js");
    try {
      await createUser({ username: "vpnhttp", email: "vh@test.local", displayName: "VH", password: "password12345" });
    } catch {}
    const r = await fetch(`${BASE}/login`, {
      method: "POST", redirect: "manual",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ identifier: "vpnhttp", password: "password12345" }),
    });
    assert.equal(r.status, 302);
    cookie = (r.headers.get("set-cookie") || "").split(";")[0];
  });
  after(() => { try { child.kill(); } catch {} });

  const get = (p, opts = {}) => fetch(`${BASE}${p}`, { redirect: "manual", headers: { Cookie: cookie }, ...opts });

  it("status/pack endpoints answer with clear disabled errors (no route shadowing)", async () => {
    let r = await get("/api/vpn/status", { headers: { Cookie: cookie, Accept: "application/json" } });
    assert.equal(r.status, 200);
    assert.equal((await r.json()).enabled, false);
    r = await get("/api/vpn/pack", { headers: { Cookie: cookie } });
    assert.equal(r.status, 503);
    assert.match((await r.json()).error, /not enabled/i);
    r = await fetch(`${BASE}/api/vpn/status`);
    assert.equal(r.status, 401);
  });

  it("lab page renders the VPN-off panel without keys", async () => {
    const r = await get("/labs/core/m6-6-2-1-whois-vm3");
    assert.equal(r.status, 200);
    const html = await r.text();
    assert.ok(html.includes("From your own Kali (VPN)"));
    assert.ok(html.includes("Student VPN is not enabled"));
    assert.ok(!html.match(/[A-Za-z0-9+/]{43}=/));
  });
});

describe("vpn deploy artifacts", () => {
  it("gateway image is minimal with a valid entrypoint", async () => {
    const dockerfile = fs.readFileSync(path.join(REPO, "vpn-gateway/Dockerfile"), "utf8");
    assert.ok(dockerfile.includes("wireguard-tools") && dockerfile.includes("iptables"));
    assert.ok(!/USER /.test(dockerfile), "gateway must stay root (needs NET_ADMIN for wg/iptables)");
    assert.ok(dockerfile.includes("EXPOSE 51820/udp"));
    const ep = fs.readFileSync(path.join(REPO, "vpn-gateway/entrypoint.sh"), "utf8");
    assert.ok(ep.includes("wg0") && ep.includes("FORWARD") && ep.includes("axiom-vpn:"));
    assert.ok(ep.includes("server_public.key"), "gateway identity persists on a volume");
  });

  it("compose + env + docs wire the gateway", async () => {
    const compose = fs.readFileSync(path.join(REPO, "docker-compose.yml"), "utf8");
    assert.ok(compose.includes("axiom-vpn") && compose.includes("51820") && compose.includes("vpnconf"));
    const env = fs.readFileSync(path.join(REPO, ".env.example"), "utf8");
    for (const k of ["VPN_ENABLED", "VPN_ENDPOINT_HOST", "VPN_ENDPOINT_PORT", "VPN_SUBNET_BASE", "VPN_GATEWAY_CONTAINER"]) {
      assert.ok(env.includes(k), `missing .env.example key: ${k}`);
    }
    const { config } = await import("../server/config.js");
    assert.equal(config.vpnEnabled, false);
    assert.equal(config.vpnGatewayContainer, "axiom-vpn");
  });
});
