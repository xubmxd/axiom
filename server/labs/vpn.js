// Student VPN: per-user WireGuard access to lab targets (HTB/THM-style).
//
// Model: one long-lived `axiom-vpn` gateway container (see vpn-gateway/).
// The orchestrator attaches it to each docker lab network on provision
// (same `docker network connect` pattern as AXIOM_SELF_CONTAINER) and
// detaches on destroy. Each student holds one WireGuard identity (/32 on the
// VPN subnet); the gateway carries per-student iptables ACCEPT rules so a
// student reaches ONLY their own running instances' target IPs.
//
// Trust boundaries are unchanged: the app already drives Docker through the
// host socket; targets never get the socket, the gateway never gets lab
// secrets. WireGuard peers are runtime state — the `vpn_clients` table is
// the source of truth and is re-synced to the gateway on boot.
//
// Everything here degrades to a no-op when VPN is disabled or the gateway
// is absent, so labs provision identically with the feature off. VPN only
// serves the docker provider: local-provider targets are in-process
// loopback servers with virtual display IPs and are unreachable by design.
import crypto from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { all, get, run, nowIso, isPg } from "../db.js";
import { log } from "../log.js";

const execFileAsync = promisify(execFile);

export class VpnError extends Error {
  constructor(message, status = 503) {
    super(message);
    this.name = "VpnError";
    this.status = status;
  }
}

// ---------- pure config (env read at call time so tests can override) ----------
export function vpnEnabled() {
  return (process.env.VPN_ENABLED || "0") === "1";
}

export function vpnBase() {
  return String(process.env.VPN_SUBNET_BASE || "10.212").replace(/\.$/, "");
}

export function dockerBase() {
  return String(process.env.LAB_DOCKER_SUBNET_BASE || "10.210").replace(/\.$/, "");
}

export function localBase() {
  return String(process.env.LAB_LOCAL_SUBNET_BASE || "10.200").replace(/\.$/, "");
}

export function vpnGatewayIp() {
  return `${vpnBase()}.0.1`;
}

export function vpnCidr() {
  return `${vpnBase()}.0.0/24`;
}

// Supernet routed to clients: covers every present and future docker lab
// subnet (third octet is random per instance).
export function labSupernet() {
  const [a, b] = dockerBase().split(".");
  return `${a}.${b}.0.0/16`;
}

export function vpnEndpoint() {
  return {
    host: String(process.env.VPN_ENDPOINT_HOST || "").trim(),
    port: parseInt(process.env.VPN_ENDPOINT_PORT || "51820", 10) || 51820,
  };
}

export function gatewayContainer() {
  return process.env.VPN_GATEWAY_CONTAINER || "axiom-vpn";
}

// Guard against a VPN subnet that would swallow or collide with lab nets.
export function vpnAddressPlanSafe() {
  const two = (b) => b.split(".").slice(0, 2).join(".");
  return two(vpnBase()) !== two(dockerBase()) && two(vpnBase()) !== two(localBase());
}

// First free tunnel IP (.2–.254; .1 is the gateway). Pure for tests.
export function allocClientIp(usedIps) {
  const used = new Set(usedIps || []);
  for (let n = 2; n <= 254; n++) {
    const ip = `${vpnBase()}.0.${n}`;
    if (!used.has(ip)) return ip;
  }
  return null;
}

// ---------- keys + pack (pure; dependency-free X25519, wg-compatible) ----------
const b64urlToB64 = (s) => Buffer.from(String(s).replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("base64");

export function generateKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("x25519");
  return {
    privateKey: b64urlToB64(privateKey.export({ format: "jwk" }).d),
    publicKey: b64urlToB64(publicKey.export({ format: "jwk" }).x),
  };
}

export function isWgKey(s) {
  if (typeof s !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(s)) return false;
  try { return Buffer.from(s, "base64").length === 32; } catch { return false; }
}

export function buildClientConf({ privateKey, clientIp, serverPublicKey, endpointHost, endpointPort, allowedIps }) {
  return [
    "# Axiom student VPN — personal pack. Do not share it.",
    "# Kali: sudo apt install wireguard && sudo wg-quick up ./axiom.conf",
    "# Then query your target directly, e.g. whois <domain> -h <target-ip>",
    "[Interface]",
    `PrivateKey = ${privateKey}`,
    `Address = ${clientIp}/32`,
    "MTU = 1380",
    "",
    "[Peer]",
    `PublicKey = ${serverPublicKey}`,
    `Endpoint = ${endpointHost}:${endpointPort}`,
    `AllowedIPs = ${allowedIps}`,
    "PersistentKeepalive = 25",
    "",
  ].join("\n");
}

// ---------- firewall rules (pure spec builders; applied via docker exec) ----------
// Every managed rule carries `axiom-vpn:<userId>:<targetIp>` so rules can be
// removed precisely per instance or purged per user without touching others.
export function aclTag(userId, targetIp) {
  return `axiom-vpn:${userId}:${targetIp}`;
}

export function aclRuleSpecs({ userId, clientIp, targetIp }) {
  const tag = aclTag(userId, targetIp);
  return ["tcp", "udp", "icmp"].map((proto) => (
    ["-i", "wg0", "-s", `${clientIp}/32`, "-d", `${targetIp}/32`, "-p", proto,
      "-m", "comment", "--comment", tag, "-j", "ACCEPT"]
  ));
}

// ---------- gateway shell-outs ----------
async function gwExec(args, timeout = 15000) {
  const { stdout } = await execFileAsync("docker", ["exec", gatewayContainer(), ...args], { timeout });
  return String(stdout || "").trim();
}

export async function gatewayAvailable() {
  try {
    const { stdout } = await execFileAsync(
      "docker", ["inspect", "-f", "{{.State.Running}}", gatewayContainer()], { timeout: 10000 });
    return String(stdout).trim() === "true";
  } catch { return false; }
}

export async function gatewayPublicKey() {
  const lines = (await gwExec(["cat", "/config/server_public.key"])).split("\n");
  const key = (lines.pop() || "").trim();
  if (!isWgKey(key)) throw new VpnError("VPN gateway has no usable public key yet.", 503);
  return key;
}

export async function ensurePeer(publicKey, clientIp) {
  await gwExec(["wg", "set", "wg0", "peer", publicKey, "allowed-ips", `${clientIp}/32`]);
}

export async function removePeer(publicKey) {
  await gwExec(["wg", "set", "wg0", "peer", publicKey, "remove"]).catch(() => {});
}

export async function listPeers() {
  try {
    const out = await gwExec(["wg", "show", "wg0", "peers"]);
    return out ? out.split("\n").map((s) => s.trim()).filter((s) => isWgKey(s)) : [];
  } catch { return []; }
}

export async function peerHandshakeAt(publicKey) {
  try {
    const out = await gwExec(["wg", "show", "wg0", "latest-handshakes"]);
    for (const line of out.split("\n")) {
      const [pub, ts] = line.trim().split(/\s+/);
      if (pub === publicKey) return parseInt(ts, 10) || 0;
    }
    return 0;
  } catch { return 0; }
}

async function iptables(action, spec) {
  await gwExec(["iptables", action, "FORWARD", ...spec]);
}

export async function addInstanceAcls({ userId, clientIp, targetIp }) {
  for (const spec of aclRuleSpecs({ userId, clientIp, targetIp })) {
    await iptables("-D", spec).catch(() => {}); // exactly-once: clear stale dupes first
    await iptables("-A", spec);
  }
}

export async function removeInstanceAcls({ userId, clientIp, targetIp }) {
  for (const spec of aclRuleSpecs({ userId, clientIp, targetIp })) {
    await iptables("-D", spec).catch(() => {});
  }
}

async function deleteManagedLines(fragment) {
  let lines = [];
  try { lines = (await gwExec(["iptables", "-S", "FORWARD"])).split("\n"); } catch { return 0; }
  let n = 0;
  for (const line of lines) {
    if (!line.includes(fragment)) continue;
    const args = line.trim().split(/\s+/);
    if (args[0] !== "-A") continue;
    args[0] = "-D";
    await gwExec(["iptables", ...args]).catch(() => {});
    n++;
  }
  return n;
}

export async function purgeUserAcls(userId) {
  return deleteManagedLines(`axiom-vpn:${userId}:`);
}

export async function purgeAllManagedAcls() {
  return deleteManagedLines("axiom-vpn:");
}

export async function attachGateway(networkName) {
  if (!networkName) return { attached: false };
  try {
    await execFileAsync("docker", ["network", "connect", networkName, gatewayContainer()], { timeout: 15000 });
    return { attached: true };
  } catch (e) {
    if (/already exists/i.test(String(e?.message || ""))) return { attached: true, reused: true };
    throw e;
  }
}

export async function detachGateway(networkName) {
  if (!networkName) return;
  await execFileAsync(
    "docker", ["network", "disconnect", "-f", networkName, gatewayContainer()], { timeout: 15000 }).catch(() => {});
}

// ---------- client identity (DB is source of truth; gateway peers are runtime) ----------
export async function getVpnClient(userId) {
  if (!userId) return null;
  return get(`SELECT user_id, public_key, client_ip, created_at FROM vpn_clients WHERE user_id=?`, [userId]);
}

async function getVpnClientSecret(userId) {
  if (!userId) return null;
  return get(`SELECT * FROM vpn_clients WHERE user_id=?`, [userId]);
}

function requireVpnUsable() {
  if (!vpnEnabled()) throw new VpnError("Student VPN is not enabled on this server.", 503);
  if (!vpnAddressPlanSafe()) {
    throw new VpnError("VPN address plan collides with lab networks. Contact your administrator.", 503);
  }
  if (!vpnEndpoint().host) {
    throw new VpnError("VPN endpoint is not configured yet. Contact your administrator.", 503);
  }
}

export async function ensureVpnClient(userId) {
  requireVpnUsable();
  if (!await gatewayAvailable()) throw new VpnError("VPN gateway is not running. Try again in a minute.", 503);
  let row = await getVpnClientSecret(userId);
  if (!row?.client_ip || !isWgKey(row?.private_key) || !isWgKey(row?.public_key)) {
    const used = new Set((await all(`SELECT client_ip FROM vpn_clients`)).map((r) => r.client_ip));
    const ip = row?.client_ip && !used.has(row.client_ip) ? row.client_ip : allocClientIp(used);
    if (!ip) throw new VpnError("VPN client pool is exhausted. Contact your administrator.", 503);
    const { privateKey, publicKey } = generateKeypair();
    const now = nowIso();
    if (isPg()) {
      await run(`INSERT INTO vpn_clients(user_id, public_key, private_key, client_ip, created_at) VALUES(?,?,?,?,?)
        ON CONFLICT (user_id) DO UPDATE SET public_key=EXCLUDED.public_key, private_key=EXCLUDED.private_key, client_ip=EXCLUDED.client_ip`,
        [userId, publicKey, privateKey, ip, now]);
    } else {
      await run(`INSERT OR REPLACE INTO vpn_clients(user_id, public_key, private_key, client_ip, created_at) VALUES(?,?,?,?,?)`,
        [userId, publicKey, privateKey, ip, now]);
    }
    row = await getVpnClientSecret(userId);
  }
  await ensurePeer(row.public_key, row.client_ip); // idempotent; restores peer after gateway restarts
  return getVpnClient(userId);
}

export async function regenerateVpnClient(userId) {
  requireVpnUsable();
  if (!await gatewayAvailable()) throw new VpnError("VPN gateway is not running. Try again in a minute.", 503);
  const old = await getVpnClientSecret(userId);
  if (!old) return ensureVpnClient(userId);
  if (old.public_key) await removePeer(old.public_key);
  const { privateKey, publicKey } = generateKeypair();
  await run(`UPDATE vpn_clients SET public_key=?, private_key=? WHERE user_id=?`, [publicKey, privateKey, userId]);
  await ensurePeer(publicKey, old.client_ip);
  log("vpn.regenerate", { user: userId });
  return getVpnClient(userId);
}

export async function revokeVpnClient(userId) {
  const row = await getVpnClientSecret(userId);
  if (row?.public_key && await gatewayAvailable()) await removePeer(row.public_key);
  if (userId) await purgeUserAcls(userId).catch(() => {});
  await run(`DELETE FROM vpn_clients WHERE user_id=?`, [userId]);
  log("vpn.revoke", { user: userId });
  return { ok: true };
}

export async function clientConfFor(userId) {
  requireVpnUsable();
  if (!await gatewayAvailable()) throw new VpnError("VPN gateway is not running. Try again in a minute.", 503);
  const row = await getVpnClientSecret(userId);
  if (!row) throw new VpnError("No VPN pack yet.", 404);
  const ep = vpnEndpoint();
  return buildClientConf({
    privateKey: row.private_key,
    clientIp: row.client_ip,
    serverPublicKey: await gatewayPublicKey(),
    endpointHost: ep.host,
    endpointPort: ep.port,
    allowedIps: labSupernet(),
  });
}

export async function vpnStatus(userId) {
  const ep = vpnEndpoint();
  const base = {
    enabled: vpnEnabled(),
    endpoint: ep.host ? `${ep.host}:${ep.port}` : null,
    supernet: labSupernet(),
    dockerOnly: true,
  };
  if (!base.enabled) return { ...base, gateway: false, configured: false };
  const gateway = await gatewayAvailable();
  const row = await getVpnClient(userId);
  if (!row) return { ...base, gateway, configured: false };
  const hs = gateway ? await peerHandshakeAt(row.public_key) : 0;
  return {
    ...base, gateway, configured: true, clientIp: row.client_ip,
    lastHandshake: hs || null,
    connected: hs > 0 && Date.now() / 1000 - hs < 180,
  };
}

// ---------- lifecycle hooks (called by the orchestrator; never throw) ----------
// Attach the gateway to every docker lab net (cheap; lets a later pack
// download work without reprovisioning). ACLs only for pack holders.
export async function syncInstanceVpn(instance) {
  try {
    if (!vpnEnabled() || instance?.provider !== "docker" || !instance.network_name) {
      return { synced: false, reason: "skipped" };
    }
    if (!await gatewayAvailable()) return { synced: false, reason: "gateway-down" };
    await attachGateway(instance.network_name);
    const client = await getVpnClient(instance.user_id).catch(() => null);
    if (!client?.client_ip || !isWgKey(client.public_key) || !instance.target_ip) {
      return { synced: true, acls: false };
    }
    await ensurePeer(client.public_key, client.client_ip);
    await addInstanceAcls({ userId: instance.user_id, clientIp: client.client_ip, targetIp: instance.target_ip });
    return { synced: true, acls: true };
  } catch (e) {
    log("vpn.sync", { instance: instance?.id, error: String(e?.message || e).slice(0, 200) });
    return { synced: false, reason: "error" };
  }
}

export async function unsyncInstanceVpn(instance) {
  try {
    if (!vpnEnabled() || instance?.provider !== "docker" || !instance?.network_name) {
      return { synced: false, reason: "skipped" };
    }
    if (await gatewayAvailable()) {
      const client = instance.user_id ? await getVpnClient(instance.user_id).catch(() => null) : null;
      if (client?.client_ip && instance.target_ip) {
        await removeInstanceAcls({ userId: instance.user_id, clientIp: client.client_ip, targetIp: instance.target_ip });
      }
    }
    await detachGateway(instance.network_name);
    return { synced: true };
  } catch (e) {
    log("vpn.unsync", { instance: instance?.id, error: String(e?.message || e).slice(0, 200) });
    return { synced: false, reason: "error" };
  }
}

// Boot: re-attach surviving nets, restore peers from DB, rebuild ACLs.
export async function reconcileVpn() {
  try {
    if (!vpnEnabled() || !await gatewayAvailable()) return { reconciled: false };
    const { allActiveInstances } = await import("./service.js");
    const actives = await allActiveInstances().catch(() => []);
    for (const inst of actives) {
      if (inst.provider === "docker" && inst.network_name) {
        await attachGateway(inst.network_name).catch(() => {});
      }
    }
    const clients = await all(`SELECT user_id, public_key, client_ip FROM vpn_clients`);
    for (const c of clients) {
      if (isWgKey(c.public_key) && c.client_ip) await ensurePeer(c.public_key, c.client_ip).catch(() => {});
    }
    const known = new Set(clients.map((c) => c.public_key));
    for (const pub of await listPeers()) {
      if (!known.has(pub)) await removePeer(pub);
    }
    await purgeAllManagedAcls().catch(() => {});
    for (const inst of actives) {
      if (inst.provider !== "docker" || !inst.target_ip) continue;
      const c = clients.find((x) => x.user_id === inst.user_id);
      if (c?.client_ip) {
        await addInstanceAcls({ userId: inst.user_id, clientIp: c.client_ip, targetIp: inst.target_ip }).catch(() => {});
      }
    }
    return { reconciled: true };
  } catch (e) {
    log("vpn.reconcile", { error: String(e?.message || e).slice(0, 200) });
    return { reconciled: false };
  }
}
