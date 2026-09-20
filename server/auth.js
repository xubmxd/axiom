import crypto from "node:crypto";
import { config } from "./config.js";
import { get, run, uid, nowIso } from "./db.js";

const scrypt = crypto.scrypt;
function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16).toString("hex");
    scrypt(password, salt, 64, (err, dk) => {
      if (err) return reject(err);
      resolve(`scrypt$${salt}$${dk.toString("hex")}`);
    });
  });
}
function verifyPassword(password, stored) {
  return new Promise((resolve, reject) => {
    try {
      const [algo, salt, hash] = stored.split("$");
      if (algo !== "scrypt") return resolve(false);
      scrypt(password, salt, 64, (err, dk) => {
        if (err) return reject(err);
        const a = Buffer.from(hash, "hex"), b = dk;
        resolve(a.length === b.length && crypto.timingSafeEqual(a, b));
      });
    } catch { resolve(false); }
  });
}

export { hashPassword, verifyPassword };

export async function createUser({ username, email, displayName, password, role = "user" }) {
  const id = uid("u");
  const colors = ["#5b7cff", "#22c1a3", "#a78bfa", "#f59e0b", "#f472b6", "#38bdf8"];
  const color = colors[parseInt(crypto.randomBytes(1).toString("hex"), 16) % colors.length];
  const now = nowIso();
  await run(
    `INSERT INTO users(id, username, email, display_name, password_hash, role, status, avatar_color, timezone, created_at, updated_at)
     VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
    [id, username.toLowerCase().trim(), email.toLowerCase().trim(), displayName?.trim() || username, await hashPassword(password), role, "active", color, "Asia/Kolkata", now, now]
  );
  await run(`INSERT INTO user_settings(user_id, updated_at) VALUES(?,?)`, [id, now]).catch(() => {});
  return get(`SELECT * FROM users WHERE id=?`, [id]);
}

export async function findLogin(identifier) {
  const v = String(identifier || "").toLowerCase().trim();
  return get(`SELECT * FROM users WHERE username=? OR email=?`, [v, v]);
}

export async function createSession(userId, ip = "") {
  const id = "s_" + crypto.randomBytes(24).toString("hex");
  const now = new Date();
  const exp = new Date(now.getTime() + config.sessionDays * 864e5).toISOString();
  await run(`INSERT INTO sessions(id, user_id, created_at, expires_at, ip) VALUES(?,?,?,?,?)`,
    [id, userId, now.toISOString(), exp, ip]);
  return { id, expiresAt: exp };
}
export async function getSessionUser(sid) {
  if (!sid) return null;
  const s = await get(`SELECT * FROM sessions WHERE id=?`, [sid]);
  if (!s || new Date(s.expires_at) < new Date()) return null;
  const u = await get(`SELECT * FROM users WHERE id=?`, [s.user_id]);
  if (!u || u.status !== "active") return null;
  return u;
}
export async function destroySession(sid) { await run(`DELETE FROM sessions WHERE id=?`, [sid]); }

export function sessionCookie(res, sid, expiresAt) {
  res.cookie("sid", sid, {
    httpOnly: true, sameSite: "lax", secure: process.env.COOKIE_SECURE === "1",
    expires: new Date(expiresAt), path: "/",
  });
}

// ---- Invitations ----
export function newInviteToken() { return crypto.randomBytes(32).toString("hex"); }
export function sha256(s) { return crypto.createHash("sha256").update(s).digest("hex"); }

const attempts = new Map(); // ip -> {count, reset}
export function rateLimit(ip, max = 20, windowMs = 60_000) {
  const now = Date.now();
  const e = attempts.get(ip) || { count: 0, reset: now + windowMs };
  if (now > e.reset) { e.count = 0; e.reset = now + windowMs; }
  e.count++;
  attempts.set(ip, e);
  return e.count <= max;
}
