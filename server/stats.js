import { config } from "./config.js";
import { all, get, run, nowIso } from "./db.js";

// Daily attribution respects user timezone: client sends tzOffsetMinutes (minutes behind UTC, like getTimezoneOffset()).
// day = UTC timestamp shifted by -offset into local calendar day.
export function dayFor(tzOffsetMinutes, when = new Date()) {
  const off = Number.isFinite(+tzOffsetMinutes) ? +tzOffsetMinutes : 0;
  const local = new Date(when.getTime() - off * 60_000);
  return local.toISOString().slice(0, 10);
}

export async function recordHeartbeat({ userId, courseId, contentType, contentId, tabId, activeSecs, tzOffset }) {
  const now = nowIso();
  const secs = Math.max(0, Math.min(120, Number(activeSecs) || 0));
  // close stale sessions for this tab/content, open or update current
  // Portable recency check: last_heartbeat_at stores ISO UTC strings, so a
  // lexicographic comparison works on both SQLite and Postgres
  // (SQLite-only datetime('now','-5 minutes') crashes on Postgres).
  const cutoff = new Date(Date.now() - 5 * 60e3).toISOString();
  const open = await get(
    `SELECT * FROM learning_sessions WHERE user_id=? AND tab_id=? AND content_id=? AND last_heartbeat_at > ? ORDER BY last_heartbeat_at DESC LIMIT 1`,
    [userId, tabId || "", contentId || "", cutoff]
  ).catch(() => null);
  let sid = open?.id;
  if (open) {
    await run(`UPDATE learning_sessions SET last_heartbeat_at=?, ended_at=?, active_secs=active_secs+? WHERE id=?`, [now, now, secs, open.id]);
  } else {
    sid = `ls_${Date.now().toString(36)}${Math.floor(Math.random() * 1e6)}`;
    await run(`INSERT INTO learning_sessions(id, user_id, course_id, content_type, content_id, tab_id, started_at, ended_at, last_heartbeat_at, active_secs) VALUES(?,?,?,?,?,?,?,?,?,?)`,
      [sid, userId, courseId || null, contentType, contentId || "", tabId || "", now, now, now, secs]);
  }
  // aggregate into daily_activity (pg + sqlite compatible-ish: upsert manually)
  const day = dayFor(tzOffset);
  const row = await get(`SELECT * FROM daily_activity WHERE user_id=? AND day=?`, [userId, day]);
  const col = contentType === "reading" ? "reading_secs" : "video_secs";
  if (!row) {
    await run(`INSERT INTO daily_activity(user_id, day, video_secs, reading_secs, completions, updated_at) VALUES(?,?,?,?,0,?)`,
      [userId, day, col === "video_secs" ? secs : 0, col === "reading_secs" ? secs : 0, now]);
  } else {
    await run(`UPDATE daily_activity SET ${col}=${col}+?, updated_at=? WHERE user_id=? AND day=?`, [secs, now, userId, day]);
  }
  return { sessionId: sid, day };
}

export async function bumpCompletion(userId, tzOffset) {
  const day = dayFor(tzOffset);
  const now = nowIso();
  const row = await get(`SELECT * FROM daily_activity WHERE user_id=? AND day=?`, [userId, day]);
  if (!row) await run(`INSERT INTO daily_activity(user_id, day, video_secs, reading_secs, completions, updated_at) VALUES(?,?,0,0,1,?)`, [userId, day, now]);
  else await run(`UPDATE daily_activity SET completions=completions+1, updated_at=? WHERE user_id=? AND day=?`, [now, userId, day]);
}

export async function yearActivity(userId) {
  const rows = await all(`SELECT * FROM daily_activity WHERE user_id=? ORDER BY day ASC`, [userId]);
  return rows;
}

// Adaptive intensity: percentile of user's own nonzero daily totals (last 365d kept in memory).
// Levels 0..4. Thresholds frozen per-request from history so yesterday's color doesn't thrash:
// use all-time nonzero distribution quantiles with smoothing.
export function intensityLevels(rows) {
  const vals = rows.map((r) => (r.video_secs || 0) + (r.reading_secs || 0)).filter((v) => v > 0).sort((a, b) => a - b);
  if (!vals.length) return { q1: 900, q2: 1800, q3: 3600 };
  const q = (p) => vals[Math.min(vals.length - 1, Math.floor(p * vals.length))];
  // floor tiny differences: minimum 5-min gaps between bands
  let q1 = Math.max(300, q(0.4)), q2 = Math.max(q1 + 300, q(0.65)), q3 = Math.max(q2 + 300, q(0.85));
  return { q1, q2, q3 };
}
export function levelFor(totalSecs, { q1, q2, q3 }) {
  if (!totalSecs) return 0;
  if (totalSecs < 60) return 1; // any genuine activity must be visible (GitHub colors any contribution)
  if (totalSecs < q1) return 1;
  if (totalSecs < q2) return 2;
  if (totalSecs < q3) return 3;
  return 4;
}

export async function streaks(userId, tzOffset) {
  const rows = await all(`SELECT day, video_secs, reading_secs FROM daily_activity WHERE user_id=? ORDER BY day DESC`, [userId]);
  const need = config.streakMinutes * 60;
  const good = new Set(rows.filter((r) => (r.video_secs + r.reading_secs) >= need).map((r) => r.day));
  const today = dayFor(tzOffset);
  let cur = 0;
  let d = new Date(today + "T12:00:00Z");
  if (!good.has(today)) d = new Date(d.getTime() - 864e5); // allow today-in-progress
  while (good.has(d.toISOString().slice(0, 10))) { cur++; d = new Date(d.getTime() - 864e5); }
  // longest
  const days = [...good].sort();
  let longest = 0, run = 0, prev = null;
  for (const day of days) {
    const t = new Date(day + "T12:00:00Z").getTime();
    run = prev !== null && t - prev === 864e5 ? run + 1 : 1;
    longest = Math.max(longest, run);
    prev = t;
  }
  return { current: cur, longest, qualifies: need };
}

export async function totals(userId) {
  const r = await get(`SELECT SUM(video_secs) v, SUM(reading_secs) rd, SUM(completions) c FROM daily_activity WHERE user_id=?`, [userId]);
  const cc = await get(`SELECT COUNT(*) n FROM course_completions WHERE user_id=?`, [userId]);
  return {
    videoSecs: Math.round(r?.v || 0), readingSecs: Math.round(r?.rd || 0),
    completions: r?.c || 0, coursesCompleted: cc?.n || 0,
  };
}
