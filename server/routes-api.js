import { Router } from "express";
import { get, run, all, nowIso, uid } from "./db.js";
import { findLogin, verifyPassword, createSession, sessionCookie, createUser, rateLimit, sha256 } from "./auth.js";
import { log } from "./log.js";
import { config } from "./config.js";
import { scanAll, normalizeRootPath, validateRootPath, listCourseRoots, startWatcher } from "./scanner.js";
import { recordHeartbeat, bumpCompletion, dayFor } from "./stats.js";
import { ah } from "./wrap.js";

export const api = Router();

// timezone offset middleware data
api.use((req, res, next) => {
  req.tzOffset = Number(req.get("x-tz-offset") || req.body?.tzOffset || req.query.tzOffset || 0) || 0;
  next();
});

// ---- video progress ----
api.post("/progress/video", ah(async (req, res) => {
  if (!req.user) return res.status(401).json({ error: "auth" });
  const { lessonId, position, duration, watchDelta, completed, tzOffset } = req.body || {};
  const l = await get(`SELECT * FROM lessons WHERE id=? AND is_active=1`, [lessonId]);
  if (!l) return res.status(404).json({ error: "lesson" });
  const now = nowIso();
  const row = await get(`SELECT * FROM video_progress WHERE user_id=? AND lesson_id=?`, [req.user.id, lessonId]);
  const pos = Math.max(0, Math.min(Number(duration) || 0, Number(position) || 0));
  const dur = Math.max(0, Number(duration) || row?.duration_secs || 0);
  const watch = Math.max(0, Math.min(120, Number(watchDelta) || 0)); // server clamps; only counts genuine playback
  let done = row?.completed ? 1 : 0;
  if (completed === true) done = 1;
  else if (completed === false) done = 0;
  else if (dur > 0 && pos / dur >= config.videoCompletionThreshold) done = 1; // ~90% genuine position
  if (!row) {
    await run(`INSERT INTO video_progress(user_id, lesson_id, position_secs, duration_secs, completed, completed_at, watch_secs, updated_at) VALUES(?,?,?,?,?,?,?,?)`,
      [req.user.id, lessonId, pos, dur, done, done ? now : null, watch, now]);
  } else {
    // multi-device safety: don't let stale tab rewind newer progress by >10s unless explicitly completed
    const safePos = pos < (row.position_secs || 0) - 10 && row.updated_at > new Date(Date.now() - 60e3).toISOString() ? row.position_secs : pos;
    // Portable max in JS: SQL max(col,?) is aggregate-only on Postgres (crashes with
    // "function max(numeric, numeric) does not exist"), while GREATEST() doesn't exist on SQLite.
    const safeDur = Math.max(Number(row.duration_secs) || 0, dur);
    await run(`UPDATE video_progress SET position_secs=?, duration_secs=?, completed=?, completed_at=COALESCE(completed_at,?), watch_secs=watch_secs+?, updated_at=? WHERE user_id=? AND lesson_id=?`,
      [safePos, safeDur, done, done ? now : null, watch, now, req.user.id, lessonId]);
  }
  if (dur > 0 && !l.duration_secs) await run(`UPDATE lessons SET duration_secs=? WHERE id=?`, [Math.round(dur), lessonId]).catch(() => {});
  if (done && !row?.completed) {
    await bumpCompletion(req.user.id, tzOffset ?? req.tzOffset);
    await maybeCompleteCourse(req.user.id, l.course_id);
    log("lesson.complete", { user: req.user.id, lesson: lessonId });
  }
  if (watch > 0) await recordHeartbeat({ userId: req.user.id, courseId: l.course_id, contentType: "video", contentId: lessonId, tabId: req.body?.tabId || "", activeSecs: watch, tzOffset: tzOffset ?? req.tzOffset });
  res.json({ ok: true, completed: !!done });
}));

// ---- video progress (bulk: select multiple lessons, mark watched/unwatched) ----
api.post("/progress/video/bulk", ah(async (req, res) => {
  if (!req.user) return res.status(401).json({ error: "auth" });
  const { lessonIds, completed, tzOffset } = req.body || {};
  if (!Array.isArray(lessonIds) || lessonIds.length === 0) return res.status(400).json({ error: "Select at least one lesson." });
  if (lessonIds.length > 200) return res.status(400).json({ error: "Select at most 200 lessons at once." });
  if (completed !== true && completed !== false) return res.status(400).json({ error: "completed must be true or false." });
  const ids = [...new Set(lessonIds.map((s) => String(s)).filter(Boolean))].slice(0, 200);
  if (!ids.length) return res.status(400).json({ error: "Select at least one lesson." });
  const placeholders = ids.map(() => "?").join(",");
  const lessons = await all(`SELECT * FROM lessons WHERE id IN (${placeholders}) AND is_active=1`, ids);
  if (!lessons.length) return res.status(404).json({ error: "No matching lessons." });
  const now = nowIso();
  const done = completed ? 1 : 0;
  let updated = 0, newlyCompleted = 0;
  const courseIds = new Set();
  for (const l of lessons) {
    const row = await get(`SELECT * FROM video_progress WHERE user_id=? AND lesson_id=?`, [req.user.id, l.id]);
    if (!row) {
      await run(`INSERT INTO video_progress(user_id, lesson_id, position_secs, duration_secs, completed, completed_at, watch_secs, updated_at) VALUES(?,?,?,?,?,?,?,?)`,
        [req.user.id, l.id, row?.position_secs || 0, 0, done, done ? now : null, 0, now]);
      if (done) newlyCompleted++;
    } else if ((row.completed ? 1 : 0) !== done) {
      if (done) {
        await run(`UPDATE video_progress SET completed=1, completed_at=COALESCE(completed_at,?), updated_at=? WHERE user_id=? AND lesson_id=?`,
          [now, now, req.user.id, l.id]);
        newlyCompleted++;
      } else {
        await run(`UPDATE video_progress SET completed=0, completed_at=NULL, updated_at=? WHERE user_id=? AND lesson_id=?`,
          [now, req.user.id, l.id]);
      }
    } else {
      continue;
    }
    updated++;
    courseIds.add(l.course_id);
    if (done) log("lesson.complete", { user: req.user.id, lesson: l.id, bulk: true });
  }
  for (let i = 0; i < newlyCompleted; i++) await bumpCompletion(req.user.id, tzOffset ?? req.tzOffset);
  for (const cid of courseIds) await maybeCompleteCourse(req.user.id, cid);
  res.json({ ok: true, updated, completed: !!done });
}));

// ---- reading progress ----
api.post("/progress/reading", ah(async (req, res) => {
  if (!req.user) return res.status(401).json({ error: "auth" });
  const { pageId, scrollPct, scrollPx, activeDelta, completed, tzOffset } = req.body || {};
  const p = await get(`SELECT * FROM reading_pages WHERE id=? AND is_active=1`, [pageId]);
  if (!p) return res.status(404).json({ error: "page" });
  const now = nowIso();
  const pct = Math.max(0, Math.min(1, Number(scrollPct) || 0));
  const px = Math.max(0, Math.min(200000, parseInt(scrollPx) || 0));
  const act = Math.max(0, Math.min(120, Number(activeDelta) || 0));
  const row = await get(`SELECT * FROM reading_progress WHERE user_id=? AND page_id=?`, [req.user.id, pageId]);
  let done = row?.completed ? 1 : 0;
  if (completed === true) done = 1;
  else if (completed === false) done = 0;
  else if (pct >= config.readingCompletionThreshold) done = 1;
  if (!row) {
    await run(`INSERT INTO reading_progress(user_id, page_id, scroll_pct, scroll_px, completed, completed_at, active_secs, last_read_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?)`,
      [req.user.id, pageId, pct, px, done, done ? now : null, act, now, now]);
  } else {
    // Portable max in JS (see video route: max(col,?) crashes on Postgres).
    const safePct = Math.max(Number(row.scroll_pct) || 0, pct);
    await run(`UPDATE reading_progress SET scroll_pct=?, scroll_px=?, completed=?, completed_at=COALESCE(completed_at,?), active_secs=active_secs+?, last_read_at=?, updated_at=? WHERE user_id=? AND page_id=?`,
      [safePct, px, done, done ? now : null, act, now, now, req.user.id, pageId]);
  }
  if (done && !row?.completed) {
    await bumpCompletion(req.user.id, tzOffset ?? req.tzOffset);
    await maybeCompleteCourse(req.user.id, p.course_id);
  }
  if (act > 0) await recordHeartbeat({ userId: req.user.id, courseId: p.course_id, contentType: "reading", contentId: pageId, tabId: req.body?.tabId || "", activeSecs: act, tzOffset: tzOffset ?? req.tzOffset });
  res.json({ ok: true, completed: !!done });
}));

// ---- generic heartbeat (focus-safe, no progress change) ----
api.post("/heartbeat", ah(async (req, res) => {
  if (!req.user) return res.status(401).json({ error: "auth" });
  const { courseId, contentType, contentId, tabId, activeSecs, tzOffset } = req.body || {};
  const r = await recordHeartbeat({ userId: req.user.id, courseId, contentType: contentType || "video", contentId: contentId || "", tabId: tabId || "", activeSecs: activeSecs || 0, tzOffset: tzOffset ?? req.tzOffset });
  res.json({ ok: true, ...r });
}));

async function maybeCompleteCourse(userId, courseId) {
  const c = await get(`SELECT * FROM courses WHERE id=?`, [courseId]);
  if (!c) return;
  const lr = await get(`SELECT COUNT(*) t, SUM(COALESCE(vp.completed,0)) d FROM lessons l LEFT JOIN video_progress vp ON vp.lesson_id=l.id AND vp.user_id=? WHERE l.course_id=? AND l.is_active=1`, [userId, courseId]);
  const pr = await get(`SELECT COUNT(*) t, SUM(COALESCE(rp.completed,0)) d FROM reading_pages p LEFT JOIN reading_progress rp ON rp.page_id=p.id AND rp.user_id=? WHERE p.course_id=? AND p.is_active=1`, [userId, courseId]);
  const total = (lr?.t || 0) + (pr?.t || 0);
  const done = (lr?.d || 0) + (pr?.d || 0);
  const ex = await get(`SELECT * FROM course_completions WHERE user_id=? AND course_id=?`, [userId, courseId]);
  if (total > 0 && done >= total) {
    if (!ex) {
      const t = await get(`SELECT SUM(video_secs+reading_secs) s FROM daily_activity WHERE user_id=?`, [userId]);
      await run(`INSERT INTO course_completions(user_id, course_id, completed_at, learned_secs, items_done, items_total) VALUES(?,?,?,?,?,?)`,
        [userId, courseId, nowIso(), Math.round(t?.s || 0), done, total]);
      log("course.complete", { user: userId, course: courseId });
    }
  } else if (ex) {
    // Self-heal: rescan added items or the user un-marked one — a stale row
    // would otherwise keep counting a merely-started course as completed.
    await run(`DELETE FROM course_completions WHERE user_id=? AND course_id=?`, [userId, courseId]);
  }
}

// ---- settings ----
api.post("/settings/profile", ah(async (req, res) => {
  if (!req.user) return res.status(401).json({ error: "auth" });
  const { display_name, email, timezone } = req.body || {};
  if (!String(display_name || "").trim() || !String(email || "").includes("@")) return res.status(400).json({ error: "Invalid name/email" });
  const tz = String(timezone || "Asia/Kolkata").slice(0, 60);
  try { new Intl.DateTimeFormat("en-US", { timeZone: tz }); }
  catch { return res.status(400).json({ error: "Unknown timezone — use an IANA name like Asia/Kolkata." }); }
  try {
    await run(`UPDATE users SET display_name=?, email=?, timezone=?, updated_at=? WHERE id=?`,
      [String(display_name).slice(0, 80), String(email).toLowerCase().slice(0, 120), tz, nowIso(), req.user.id]);
    res.json({ ok: true });
  } catch { res.status(400).json({ error: "Email or name already in use" }); }
}));
api.post("/settings/password", ah(async (req, res) => {
  if (!req.user) return res.status(401).json({ error: "auth" });
  const full = await get(`SELECT * FROM users WHERE id=?`, [req.user.id]);
  const { verifyPassword, hashPassword } = await import("./auth.js");
  if (!await verifyPassword(String(req.body?.current || ""), full.password_hash)) return res.status(400).json({ error: "Current password incorrect" });
  if (String(req.body?.next || "").length < 10) return res.status(400).json({ error: "New password too short" });
  await run(`UPDATE users SET password_hash=?, updated_at=? WHERE id=?`, [await hashPassword(String(req.body.next)), nowIso(), req.user.id]);
  log("user.password", { user: req.user.id });
  res.json({ ok: true });
}));
api.post("/settings/prefs", ah(async (req, res) => {
  if (!req.user) return res.status(401).json({ error: "auth" });
  const b = req.body || {};
  await run(`UPDATE user_settings SET autoplay=?, playback_speed=?, updated_at=? WHERE user_id=?`,
    [b.autoplay ? 1 : 0, Math.min(2, Math.max(0.5, Number(b.playback_speed) || 1)), nowIso(), req.user.id]);
  res.json({ ok: true });
}));

// ---- profile picture (file-based: DATA_DIR/avatars/<userId>.<ext>) ----
api.post("/settings/avatar", ah(async (req, res) => {
  if (!req.user) return res.status(401).json({ error: "auth" });
  const { parseAvatarUpload, avatarFileName, AVATAR_EXTS } = await import("./avatar.js");
  let parsed;
  try { parsed = parseAvatarUpload(req.body?.dataUrl); }
  catch (e) { return res.status(400).json({ error: e.message || "Invalid image." }); }
  const { default: fs } = await import("node:fs");
  const { default: path } = await import("node:path");
  const dir = path.join(config.dataDir, "avatars");
  fs.mkdirSync(dir, { recursive: true });
  // drop any previous extension variant so exactly one avatar file exists
  for (const ext of AVATAR_EXTS) {
    try { fs.rmSync(path.join(dir, avatarFileName(req.user.id, ext)), { force: true }); } catch {}
  }
  const file = avatarFileName(req.user.id, parsed.ext);
  fs.writeFileSync(path.join(dir, file), parsed.buffer);
  log("user.avatar", { user: req.user.id, ext: parsed.ext });
  res.json({ ok: true, url: `/media/avatar/${req.user.id}.${parsed.ext}?v=${Date.now()}` });
}));
api.delete("/settings/avatar", ah(async (req, res) => {
  if (!req.user) return res.status(401).json({ error: "auth" });
  const { avatarFileName, AVATAR_EXTS } = await import("./avatar.js");
  const { default: fs } = await import("node:fs");
  const { default: path } = await import("node:path");
  const dir = path.join(config.dataDir, "avatars");
  for (const ext of AVATAR_EXTS) {
    try { fs.rmSync(path.join(dir, avatarFileName(req.user.id, ext)), { force: true }); } catch {}
  }
  log("user.avatar.remove", { user: req.user.id });
  res.json({ ok: true });
}));

// ---- admin ----
function needAdminJson(req, res, next) {
  if (!req.user) return res.status(401).json({ error: "auth" });
  if (req.user.role !== "admin") return res.status(403).json({ error: "forbidden" });
  next();
}
api.post("/admin/scan", needAdminJson, ah(async (req, res) => {
  const r = await scanAll(true);
  res.json(r);
}));
api.post("/admin/invites", needAdminJson, ah(async (req, res) => {
  const { newInviteToken } = await import("./auth.js");
  const token = newInviteToken();
  const id = `inv_${token.slice(0, 12)}`;
  const exp = new Date(Date.now() + 7 * 864e5).toISOString();
  await run(`INSERT INTO invitations(id, token_hash, role, created_by, email_hint, expires_at, created_at) VALUES(?,?,?,?,?,?,?)`,
    [id, sha256(token), req.body?.role === "admin" ? "admin" : "user", req.user.id, String(req.body?.email_hint || "").slice(0, 120), exp, nowIso()]);
  log("invite.create", { by: req.user.id, role: req.body?.role || "user" });
  res.json({ ok: true, url: `${config.appUrl}/invite/${token}` });
}));
api.patch("/admin/users/:id", needAdminJson, ah(async (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: "cannot modify self" });
  const status = req.body?.action === "enable" ? "active" : "disabled";
  await run(`UPDATE users SET status=?, updated_at=? WHERE id=?`, [status, nowIso(), req.params.id]);
  if (status === "disabled") await run(`DELETE FROM sessions WHERE user_id=?`, [req.params.id]);
  log("user.status", { by: req.user.id, target: req.params.id, status });
  res.json({ ok: true });
}));

// ---- admin: course libraries (multiple scan roots) ----
async function rearmWatcher() {
  try { await startWatcher(() => scanAll(false)); } catch {}
}
api.get("/admin/roots", needAdminJson, ah(async (req, res) => {
  const roots = await listCourseRoots(true);
  const out = [];
  for (const r of roots) {
    const n = await get(`SELECT COUNT(*) n FROM courses WHERE root_id=?`, [r.id]);
    out.push({ ...r, course_count: n?.n || 0 });
  }
  res.json({ ok: true, roots: out });
}));
api.post("/admin/roots", needAdminJson, ah(async (req, res) => {
  const rawPath = String(req.body?.path || "").trim();
  const label = String(req.body?.label || "").slice(0, 80).trim();
  if (!rawPath) return res.status(400).json({ error: "Path is required." });
  const existing = await listCourseRoots(true);
  const err = validateRootPath(rawPath, existing);
  if (err) return res.status(400).json({ error: err });
  const norm = normalizeRootPath(rawPath);
  if (existing.some((r) => normalizeRootPath(r.path) === norm)) {
    return res.status(400).json({ error: "That directory is already added." });
  }
  const now = nowIso();
  const id = uid("root");
  try {
    await run(`INSERT INTO course_roots(id, path, label, is_active, last_error, created_at, updated_at) VALUES(?,?,?,?,?,?,?)`,
      [id, norm, label || norm.split("/").pop() || norm, 1, "", now, now]);
  } catch {
    return res.status(400).json({ error: "Could not add — path must be unique." });
  }
  const { default: fs } = await import("node:fs");
  const { default: path } = await import("node:path");
  try {
    fs.mkdirSync(norm, { recursive: true });
    for (const sub of ["video", "reading"]) fs.mkdirSync(path.join(norm, sub), { recursive: true });
  } catch {}
  log("roots.add", { by: req.user.id, path: norm });
  await rearmWatcher();
  const row = await get(`SELECT * FROM course_roots WHERE id=?`, [id]);
  res.json({ ok: true, root: row });
}));
api.patch("/admin/roots/:id", needAdminJson, ah(async (req, res) => {
  const row = await get(`SELECT * FROM course_roots WHERE id=?`, [req.params.id]);
  if (!row) return res.status(404).json({ error: "Library not found." });
  const now = nowIso();
  if (req.body?.path !== undefined) {
    const rawPath = String(req.body.path || "").trim();
    if (!rawPath) return res.status(400).json({ error: "Path cannot be empty." });
    const others = (await listCourseRoots(true)).filter((r) => r.id !== row.id);
    const err = validateRootPath(rawPath, others);
    if (err) return res.status(400).json({ error: err });
    const norm = normalizeRootPath(rawPath);
    await run(`UPDATE course_roots SET path=?, updated_at=? WHERE id=?`, [norm, now, row.id]);
    // keep denormalized course paths in sync so media keeps resolving
    try { await run(`UPDATE courses SET root_path=? WHERE root_id=?`, [norm, row.id]); } catch {}
    log("roots.move", { by: req.user.id, id: row.id, path: norm });
  }
  if (req.body?.label !== undefined) {
    await run(`UPDATE course_roots SET label=?, updated_at=? WHERE id=?`,
      [String(req.body.label || "").slice(0, 80), now, row.id]);
  }
  if (req.body?.is_active !== undefined) {
    const active = req.body.is_active ? 1 : 0;
    if (!active) {
      const total = await get(`SELECT COUNT(*) n FROM course_roots WHERE is_active=1`);
      const thisActive = row.is_active ? 1 : 0;
      if (thisActive && (total?.n || 0) <= 1) {
        return res.status(400).json({ error: "At least one library must stay enabled." });
      }
    }
    await run(`UPDATE course_roots SET is_active=?, updated_at=? WHERE id=?`, [active, now, row.id]);
    log("roots.toggle", { by: req.user.id, id: row.id, active });
  }
  await rearmWatcher();
  res.json({ ok: true, root: await get(`SELECT * FROM course_roots WHERE id=?`, [row.id]) });
}));
api.delete("/admin/roots/:id", needAdminJson, ah(async (req, res) => {
  const row = await get(`SELECT * FROM course_roots WHERE id=?`, [req.params.id]);
  if (!row) return res.status(404).json({ error: "Library not found." });
  const total = await get(`SELECT COUNT(*) n FROM course_roots`);
  if ((total?.n || 0) <= 1) {
    return res.status(400).json({ error: "Cannot remove the last library. Disable courses by removing their folders instead." });
  }
  // Deleting a library removes its indexed courses; lesson/page cascades
  // clean up groups, progress and completions via FK ON DELETE CASCADE.
  await run(`DELETE FROM courses WHERE root_id=?`, [row.id]);
  await run(`DELETE FROM course_roots WHERE id=?`, [row.id]);
  log("roots.remove", { by: req.user.id, id: row.id, path: row.path });
  await rearmWatcher();
  res.json({ ok: true });
}));
