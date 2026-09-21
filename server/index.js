import express from "express";
import cookieParser from "cookie-parser";
import path from "node:path";
import fs from "node:fs";
import { config } from "./config.js";
import "./wrap.js"; // must load first: patches Express to forward async errors
import { initDb, get, run, nowIso } from "./db.js";
import { log } from "./log.js";
import { findLogin, verifyPassword, createSession, sessionCookie, getSessionUser, destroySession, createUser, rateLimit, sha256 } from "./auth.js";
import { scanAll, startWatcher } from "./scanner.js";
import { pages } from "./routes-pages.js";
import { api } from "./routes-api.js";
import { media } from "./routes-media.js";
import { labPages, labApi } from "./routes-labs.js";

await initDb();

// Cyber Range: seed declarative lab definitions (idempotent), then
// reconcile any instances left active across a restart.
try {
  const { seedFromDefinitions } = await import("./labs/service.js");
  const r = await seedFromDefinitions();
  log("labs.seed", r);
} catch (e) {
  log("labs.seed.error", { error: String(e?.message || e).slice(0, 300) });
}
try {
  const { reconcileOnBoot, warmupLabImages } = await import("./labs/orchestrator.js");
  await reconcileOnBoot();
  // Pre-build missing lab images in the background so the first lab start
  // never waits on a build. Fire-and-forget: warmup never throws and hosts
  // without a daemon simply skip it.
  warmupLabImages().then((r) => log("labs.warmup", r)).catch(() => {});
} catch (e) {
  log("labs.reconcile.error", { error: String(e?.message || e).slice(0, 300) });
}

const app = express();
app.set("trust proxy", 1);
app.use(cookieParser());
app.use(express.urlencoded({ extended: false, limit: "1mb" }));
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.resolve("public"), { maxAge: "1h" }));

app.use(async (req, res, next) => {
  req.user = await getSessionUser(req.cookies?.sid);
  if (req.user) {
    req.tzOffset = Number(req.get("x-tz-offset") || 0) || 0;
    run(`UPDATE users SET last_seen_at=? WHERE id=?`, [nowIso(), req.user.id]).catch(() => {});
  }
  next();
});

// ---- auth actions ----
app.post("/login", async (req, res) => {
  const ip = req.ip || "?";
  if (!rateLimit(ip, 20)) return res.redirect("/login?err=" + encodeURIComponent("Too many attempts — wait a minute."));
  const u = await findLogin(req.body?.identifier);
  if (!u || u.status !== "active" || !await verifyPassword(String(req.body?.password || ""), u.password_hash)) {
    log("auth.fail", { ip });
    return res.redirect("/login?err=" + encodeURIComponent("Invalid credentials."));
  }
  const s = await createSession(u.id, ip);
  sessionCookie(res, s.id, s.expiresAt);
  log("auth.login", { user: u.id });
  const next = String(req.body?.next || "/");
  res.redirect(next.startsWith("/") ? next : "/");
});
app.post("/logout", async (req, res) => {
  if (req.cookies?.sid) await destroySession(req.cookies.sid);
  res.clearCookie("sid", { path: "/" });
  res.redirect("/login");
});
app.post("/invite/:token", async (req, res) => {
  const inv = await get(`SELECT * FROM invitations WHERE token_hash=?`, [sha256(req.params.token)]);
  if (!inv || inv.used_at || new Date(inv.expires_at) < new Date())
    return res.redirect(`/invite/${req.params.token}?err=` + encodeURIComponent("Invitation invalid or expired."));
  const { username, email, display_name, password } = req.body || {};
  if (!username || !email?.includes("@") || String(password || "").length < 10)
    return res.redirect(`/invite/${req.params.token}?err=` + encodeURIComponent("Check fields — password minimum 10 characters."));
  try {
    const u = await createUser({ username, email, display_name, password, role: inv.role });
    await run(`UPDATE invitations SET used_at=?, used_by=? WHERE id=?`, [nowIso(), u.id, inv.id]);
    const s = await createSession(u.id, req.ip);
    sessionCookie(res, s.id, s.expiresAt);
    log("user.register", { user: u.id, via: "invite" });
    res.redirect("/");
  } catch {
    res.redirect(`/invite/${req.params.token}?err=` + encodeURIComponent("Username or email already taken."));
  }
});

app.use("/api", api);
app.use("/api", labApi);
app.use("/media", media);
app.use("/", labPages);
app.use("/", pages);

app.use((req, res) => {
  res.status(404).send("<!doctype html><title>Not found · Axiom</title><h1>Not found</h1><p>The page you requested doesn't exist.</p><a href='/'>Back home</a>");
});

// error handler — never leak stacks
app.use((err, req, res, next) => {
  log("error", { path: req.path, error: String(err?.message || err).slice(0, 300) });
  if (req.path.startsWith("/api/")) return res.status(500).json({ error: "Something went wrong." });
  res.status(500).send("<h1>Something went wrong</h1><p>Please retry. If it persists, contact your administrator.</p><a href='/'>Home</a>");
});

await scanAll(false);
startWatcher(() => scanAll(false));

app.listen(config.port, () => log("boot", { port: config.port, courses: config.coursesRoot, version: config.appVersion }));
