import { Router } from "express";
import fs from "node:fs";
import path from "node:path";
import { all, get } from "./db.js";
import { config } from "./config.js";
import { layout, esc, fmtDur, fmtClock, fmtDate, initials, avatarHtml, progressBar, graphHtml, emptyState, iconArt, PLAYER_ICONS } from "./views.js";
import { yearActivity, intensityLevels, streaks, totals, dayFor } from "./stats.js";
import { courseDir } from "./scanner.js";

// Rotating workspace line — server-rendered once per page load, stable for
// the session. No backend needed; edit this list freely.
const MOTIVATION = [
  "Small steps every day compound into expertise.",
  "Progress is built one difficult lesson at a time.",
  "Consistency beats intensity when the goal is mastery.",
  "Learn deeply. Build deliberately.",
  "Every concept you master makes the next one easier.",
  "Discipline turns curiosity into skill.",
  "Stay curious. Keep digging.",
  "Mastery is just deliberate practice repeated.",
  "Understand the system, not just the answer.",
  "One lesson closer to knowing how it works.",
];

export const pages = Router();

function needAuth(req, res, next) {
  if (!req.user) return res.redirect("/login?next=" + encodeURIComponent(req.originalUrl));
  next();
}
function needAdmin(req, res, next) {
  if (!req.user) return res.redirect("/login?next=" + encodeURIComponent(req.originalUrl));
  if (req.user.role !== "admin") return res.status(403).send(layout({ title: "Forbidden", user: req.user, body: `<div class="wrap">${emptyState("Not authorized", "This area requires an administrator.")}</div>` }));
  next();
}

// ---------- course progress helpers ----------
// Progress aggregates recursively from ALL lessons + pages, regardless of depth.
export async function courseProgress(userId, course) {
  const lessons = await all(`SELECT l.id, COALESCE(vp.completed,0) done FROM lessons l LEFT JOIN video_progress vp ON vp.lesson_id=l.id AND vp.user_id=? WHERE l.course_id=? AND l.is_active=1`, [userId, course.id]);
  const pages = await all(`SELECT p.id, COALESCE(rp.completed,0) done FROM reading_pages p LEFT JOIN reading_progress rp ON rp.page_id=p.id AND rp.user_id=? WHERE p.course_id=? AND p.is_active=1`, [userId, course.id]);
  const done = lessons.filter((l) => l.done).length + pages.filter((p) => p.done).length;
  const total = lessons.length + pages.length;
  return { done, total, pct: total ? (done / total) * 100 : 0, lessons: lessons.length, pages: pages.length };
}

export function depthLabel(d) {
  return d === 1 ? "Module" : d === 2 ? "Submodule" : `Section`;
}

// Generic recursive course tree. Groups nest arbitrarily; ungrouped items
// (flat courses) live on the root node — never fake groups.
export async function courseTree(courseId, userId) {
  const { natSort } = await import("./scanner.js");
  const groups = await all(`SELECT * FROM content_groups WHERE course_id=? AND is_active=1`, [courseId]);
  const lessons = await all(`SELECT l.*, COALESCE(vp.completed,0) done, vp.position_secs pos FROM lessons l LEFT JOIN video_progress vp ON vp.lesson_id=l.id AND vp.user_id=? WHERE l.course_id=? AND l.is_active=1`, [userId, courseId]);
  const pages = await all(`SELECT p.*, COALESCE(rp.completed,0) done, rp.scroll_pct FROM reading_pages p LEFT JOIN reading_progress rp ON rp.page_id=p.id AND rp.user_id=? WHERE p.course_id=? AND p.is_active=1`, [userId, courseId]);
  const resources = await all(`SELECT * FROM resources WHERE course_id=? AND is_active=1`, [courseId]);
  const nodes = new Map();
  const root = { group: null, children: [], lessons: [], pages: [], resources: [] };
  const sorted = [...groups].sort((a, b) => natSort(a.path_key, b.path_key));
  for (const g of sorted) nodes.set(g.id, { group: g, children: [], lessons: [], pages: [], resources: [] });
  for (const n of nodes.values()) {
    if (n.group.parent_id && nodes.has(n.group.parent_id)) nodes.get(n.group.parent_id).children.push(n);
    else root.children.push(n);
  }
  const put = (list, key, item) => {
    const n = item[key] && nodes.has(item[key]) ? nodes.get(item[key]) : root;
    n[list].push(item);
  };
  for (const l of lessons.sort((a, b) => a.position - b.position)) put("lessons", "group_id", l);
  for (const p of pages.sort((a, b) => a.position - b.position)) put("pages", "group_id", p);
  for (const r of resources.sort((a, b) => natSort(a.file_name, b.file_name))) put("resources", "group_id", r);
  return root;
}

export async function groupChain(groupId) {
  const chain = [];
  let cur = groupId;
  while (cur) {
    const g = await get(`SELECT * FROM content_groups WHERE id=?`, [cur]);
    if (!g) break;
    chain.unshift(g);
    cur = g.parent_id;
  }
  return chain;
}

export function crumbs(course, chain, leaf) {
  return `<nav class="crumbs mono" aria-label="Breadcrumb"><a href="/library">library</a> / <a href="/courses/${course.id}">${esc(course.title)}</a>${chain.map((g) => ` / <span>${esc(g.title)}</span>`).join("")} / <span>${esc(leaf)}</span></nav>`;
}

async function continueItems(userId) {
  // ONE resume point: the single most-recently touched content item across
  // video + reading, completed or not. updated_at is bumped on every
  // position save and every completion toggle, so it is the access clock —
  // no inference from progress, ordering, or insertion order. The item's
  // course is trivially the last-accessed course, and the item is trivially
  // the last-accessed content within it. Returns [] when nothing was ever
  // touched (the caller renders the empty state).
  const v = await get(
    `SELECT l.id content_id, l.title, l.course_id, c.title course, c.kind, vp.position_secs pos, vp.duration_secs dur, vp.completed done, vp.updated_at ts, 'video' t
     FROM video_progress vp JOIN lessons l ON l.id=vp.lesson_id JOIN courses c ON c.id=l.course_id
     WHERE vp.user_id=? AND l.is_active=1 ORDER BY vp.updated_at DESC LIMIT 1`, [userId]);
  const r = await get(
    `SELECT p.id content_id, p.title, p.course_id, c.title course, c.kind, rp.scroll_pct pos, rp.completed done, rp.updated_at ts, 'reading' t
     FROM reading_progress rp JOIN reading_pages p ON p.id=rp.page_id JOIN courses c ON c.id=p.course_id
     WHERE rp.user_id=? AND p.is_active=1 ORDER BY rp.updated_at DESC LIMIT 1`, [userId]);
  return [v, r].filter(Boolean).sort((a, b) => (a.ts < b.ts ? 1 : -1)).slice(0, 1);
}

// ---------- Auth pages ----------
pages.get("/login", (req, res) => {
  if (req.user) return res.redirect("/");
  res.send(layout({ title: "Sign in", user: null, body: `
  <div class="authwrap"><div class="authcard">
    <div class="brand big"><span class="brand-mark">◈</span><span class="brand-name">Axiom</span></div>
    <h1>Welcome back</h1><p class="dim">Sign in to your private learning workspace.</p>
    ${req.query.err ? `<div class="alert" role="alert">${esc(req.query.err)}</div>` : ""}
    <form method="post" action="/login" class="form">
      <label>Username or email<input name="identifier" autocomplete="username" required></label>
      <label>Password<input name="password" type="password" autocomplete="current-password" required></label>
      <input type="hidden" name="next" value="${esc(req.query.next || "/")}">
      <button class="btn primary" type="submit">Sign in</button>
    </form>
    <p class="dim small">Invite-only · ask your administrator for an invitation link.</p>
  </div></div>` }));
});

pages.get("/invite/:token", async (req, res) => {
  const { sha256 } = await import("./auth.js");
  const inv = await get(`SELECT * FROM invitations WHERE token_hash=?`, [sha256(req.params.token)]);
  const bad = !inv || inv.used_at || new Date(inv.expires_at) < new Date();
  res.send(layout({ title: "Accept invitation", user: null, body: `
  <div class="authwrap"><div class="authcard">
    <div class="brand big"><span class="brand-mark">◈</span><span class="brand-name">Axiom</span></div>
    ${bad ? `<h1>Invitation invalid</h1><p class="dim">This link is expired, already used, or never existed. Ask an admin for a fresh one.</p><a class="btn" href="/login">Back to sign in</a>`
    : `<h1>Create your account</h1><p class="dim">You've been invited${inv.email_hint ? ` as <b>${esc(inv.email_hint)}</b>` : ""} · role: <b>${esc(inv.role)}</b></p>
    ${req.query.err ? `<div class="alert">${esc(req.query.err)}</div>` : ""}
    <form method="post" action="/invite/${esc(req.params.token)}" class="form">
      <label>Display name<input name="display_name" required maxlength="80"></label>
      <label>Username<input name="username" required maxlength="40" pattern="[A-Za-z0-9_.-]+"></label>
      <label>Email<input name="email" type="email" required maxlength="120"></label>
      <label>Password<input name="password" type="password" required minlength="10" autocomplete="new-password"></label>
      <button class="btn primary" type="submit">Create account</button>
    </form>`}
  </div></div>` }));
});

// ---------- Dashboard ----------
pages.get("/", needAuth, async (req, res) => {
  const u = req.user;
  const courses = await all(`SELECT * FROM courses ORDER BY title ASC`);
  const prog = [];
  for (const c of courses) prog.push({ c, ...(await courseProgress(u.id, c)) });
  const inProg = prog.filter((p) => p.done > 0 && p.pct < 100).sort((a, b) => b.pct - a.pct);
  const notStarted = prog.filter((p) => p.done === 0);
  const cont = await continueItems(u.id);
  const rows = await yearActivity(u.id);
  const bands = intensityLevels(rows);
  const st = await streaks(u.id, req.tzOffset);
  const tot = await totals(u.id);
  // True last-7-calendar-days slice for the Activity summary (rows are sparse —
  // last-7-records is not the same as this week). Pure presentation slice; no
  // tracking change.
  const todayStr = dayFor(req.tzOffset);
  const weekCut = new Date(new Date(todayStr + "T12:00:00Z").getTime() - 6 * 864e5).toISOString().slice(0, 10);
  const weekRows = rows.filter((r) => r.day >= weekCut && r.day <= todayStr);
  const weekSecs = weekRows.reduce((a, r) => a + (r.video_secs || 0) + (r.reading_secs || 0), 0);
  const weekVideo = weekRows.reduce((a, r) => a + (r.video_secs || 0), 0);
  const weekReading = weekRows.reduce((a, r) => a + (r.reading_secs || 0), 0);
  const weekActive = weekRows.filter((r) => (r.video_secs || 0) + (r.reading_secs || 0) > 0).length;
  // Previous 7 calendar days, for the week-over-week delta (real data only).
  const prevCut = new Date(new Date(weekCut + "T12:00:00Z").getTime() - 7 * 864e5).toISOString().slice(0, 10);
  const prevSecs = rows.filter((r) => r.day >= prevCut && r.day < weekCut)
    .reduce((a, r) => a + (r.video_secs || 0) + (r.reading_secs || 0), 0);
  const delta = prevSecs > 0 ? Math.round((weekSecs - prevSecs) / prevSecs * 100) : null;
  const best = weekRows.reduce((a, r) => ((r.video_secs || 0) + (r.reading_secs || 0) > ((a?.video_secs || 0) + (a?.reading_secs || 0)) ? r : a), null);
  const mostActive = best ? new Date(best.day + "T12:00:00Z").toLocaleDateString(undefined, { weekday: "short" }) : "—";
  const bestSecs = best ? ((best.video_secs || 0) + (best.reading_secs || 0)) : 0;
  // Overall progress across every course (real aggregates, no new queries).
  const allDone = prog.reduce((a, p) => a + p.done, 0);
  const allTotal = prog.reduce((a, p) => a + p.total, 0);
  const allPct = allTotal ? Math.round(allDone / allTotal * 100) : 0;
  // Activity range selector (real re-render, default 12 weeks).
  const weeks = [12, 26, 52].includes(parseInt(req.query.range)) ? parseInt(req.query.range) : 12;
  const msg = MOTIVATION[Math.floor(Math.random() * MOTIVATION.length)];
  const todayLabel = new Date().toLocaleDateString(undefined, { weekday: "short", day: "numeric", month: "short", year: "numeric" });
  const firstName = esc(u.display_name.split(" ")[0] || u.username);
  const contCount = cont.length;
  const progCount = inProg.length;

  const statDelta = delta === null
    ? `<small class="mono dim">this week · ${fmtDur(weekVideo)} video · ${fmtDur(weekReading)} reading</small>`
    : `<small><span class="${delta >= 0 ? "up" : "down"}">↑ ${Math.abs(delta)}%</span><span class="mono dim"> vs last week · ${fmtDur(weekVideo)} vid · ${fmtDur(weekReading)} read</span></small>`;

  // ONE resume point: the single last-accessed item (or the empty state).
  // Completed items are never substituted — the action becomes "Revisit",
  // reopening the same existing lesson route.
  const continueRail = (() => {
    const it = cont[0];
    if (!it) return emptyState("Nothing to resume yet.", "Start a lesson from your Library and it will appear here.", `<a class="btn primary" href="/library">Browse Library →</a>`);
    const done = !!it.done;
    const pct = it.t === "video" && it.dur ? Math.round((it.pos / it.dur) * 100)
      : (it.t === "reading" && it.pos !== undefined && it.pos !== null ? Math.round(Number(it.pos) * 100) : null);
    const meta = it.t === "video" && it.dur ? `${fmtClock(it.pos)} / ${fmtClock(it.dur)} · ${pct}%`
      : (pct !== null ? `${pct}% through this page` : "");
    const action = done ? "Revisit →" : (it.t === "video" ? "▶ Resume" : "Continue reading →");
    return `<div class="resume-featured">
      <div class="resume-top"><span class="mono dim resume-course">${esc(it.course)}</span><span class="pill ${it.t}">${it.t === "video" ? "Video" : "Reading"}</span></div>
      <h3>${esc(it.title)}</h3>
      ${meta ? `<p class="mono dim small resume-meta">${esc(meta)}</p>` : ""}
      ${pct !== null ? progressBar(pct, it.title) : ""}
      <a class="btn primary resume-btn" href="/learn/${it.t}/${it.content_id}">${action}</a>
    </div>`;
  })();

  res.send(layout({ title: "Workspace", user: u, active: "home", body: `
  <div class="wrap ws">
    <section class="ws-head">
      <div class="ws-welcome">
        <p class="eyebrow mono">Welcome back,</p>
        <h1>Good to see you, <span class="hl">${firstName}</span>.</h1>
        <p class="dim ws-msg">${esc(msg)}</p>
      </div>
      <div class="ws-date"><p class="mono dim"><span aria-hidden="true">◷</span> ${esc(todayLabel)}</p><p class="mono dim small">Keep going.</p></div>
    </section>

    <div class="ws-grid" data-cont="${contCount}" data-prog="${progCount}">
      <div class="ws-main">
        <div class="statrow" role="list" aria-label="Learning statistics">
          <div class="stat" role="listitem"><div class="stat-top"><span class="mono dim stat-label">Learning Time</span><span class="stat-glyph" aria-hidden="true">▤</span></div><b>${fmtDur(weekSecs)}${delta !== null ? ` <span class="${delta >= 0 ? "up" : "down"} small">↑ ${Math.abs(delta)}%</span>` : ""}</b>${statDelta}</div>
          <div class="stat" role="listitem"><div class="stat-top"><span class="mono dim stat-label">Current Streak</span><span class="stat-glyph" aria-hidden="true">◉</span></div><b>${st.current} day${st.current === 1 ? "" : "s"}</b><small class="mono dim">Best: ${st.longest} day${st.longest === 1 ? "" : "s"}</small></div>
          <div class="stat" role="listitem"><div class="stat-top"><span class="mono dim stat-label">Completed</span><span class="stat-glyph" aria-hidden="true">◆</span></div><b>${tot.coursesCompleted} course${tot.coursesCompleted === 1 ? "" : "s"}</b><small class="mono dim">Out of ${courses.length}</small></div>
          <div class="stat" role="listitem"><div class="stat-top"><span class="mono dim stat-label">Total Progress</span><span class="stat-glyph" aria-hidden="true">▅</span></div><b>${allPct}%</b>${progressBar(allPct, "Overall progress")}<small class="mono dim">${allDone}/${allTotal} items</small></div>
        </div>

  <section class="card act-card" aria-label="Activity">
          <div class="act-head"><div><h2><span class="h-ic" aria-hidden="true">◐</span> Activity</h2><p class="dim small act-sub">Your learning activity over the last ${weeks} weeks.</p></div>
          <form class="range" action="/" method="get"><select name="range" onchange="this.form.submit()" aria-label="Activity range">${[12, 26, 52].map((w) => `<option value="${w}" ${weeks === w ? "selected" : ""}>Last ${w} weeks</option>`).join("")}</select></form></div>
          <div class="act">
            <div class="act-main">${graphHtml(rows, bands, weeks)}</div>
            <aside class="act-side" aria-label="This week summary">
              <p class="eyebrow mono">This week</p>
              <div class="act-stats">
                <div class="act-stat"><span class="mono dim">learned</span><b>${fmtDur(weekSecs)} ${delta !== null ? `<em class="${delta >= 0 ? "up" : "down"}">↑ ${Math.abs(delta)}%</em>` : ""}</b></div>
                <div class="act-stat"><span class="mono dim">active days</span><b>${weekActive} / 7</b></div>
                <div class="act-stat"><span class="mono dim">most active day</span><b>${mostActive}${bestSecs ? ` <em class="mono dim">${fmtDur(bestSecs)}</em>` : ""}</b></div>
              </div>
              <p class="mono dim small act-quote">“Progress, not perfection.”</p>
            </aside>
          </div>
        </section>

        <section aria-label="In progress"><div class="sech"><h2><span class="h-ic" aria-hidden="true">◑</span> In Progress</h2><a class="link" href="/library?f=progress">View all →</a></div>
        ${inProg.length ? `<div class="coursegrid" data-n="${Math.min(inProg.length, 6)}">${inProg.slice(0, 6).map((p) => courseCard(p)).join("")}</div>` : `<div class="card dim">Nothing in progress. ${notStarted.length ? "Something new is waiting in the library." : ""}</div>`}</section>

        <section class="mantra" aria-hidden="true"><div><p class="mantra-a">A more capable you.</p><p class="mantra-b">One lesson at a time.</p></div><div class="mantra-r mono"><span>Consistency</span><span>creates excellence</span><i></i></div></section>
      </div>

      <div class="ws-rail">
        <section class="card rail-card" aria-label="Continue learning"><div class="sech rail-head"><h2><span class="h-ic" aria-hidden="true">▣</span> Continue Learning</h2><a class="link" href="/library" aria-label="Browse library">→</a></div>
        ${continueRail}</section>

        <section class="card rail-card" aria-label="Quick actions"><div class="sech rail-head"><h2><span class="h-ic" aria-hidden="true">▤</span> Quick Actions</h2></div>
        <div class="qal">
          <a href="/library"><span><b>Browse Library</b><small class="mono dim">${courses.length} courses</small></span><span aria-hidden="true">→</span></a>
          ${cont[0] ? `<a href="/learn/${cont[0].t}/${cont[0].content_id}"><span><b>Resume learning</b><small class="mono dim">${esc(cont[0].title.slice(0, 34))}</small></span><span aria-hidden="true">→</span></a>` : ""}
          ${u.role === "admin" ? `<a href="/admin"><span><b>Open Admin Console</b><small class="mono dim">system &amp; scanner</small></span><span aria-hidden="true">→</span></a>` : `<a href="/profile"><span><b>View Profile</b><small class="mono dim">stats &amp; activity</small></span><span aria-hidden="true">→</span></a>`}
        </div></section>
      </div>
    </div>
  </div>` }));
});

function courseCard({ c, done, total, pct, lessons, pages }) {
  const kind = lessons > 0 && pages > 0 ? "mixed" : c.kind;
  const code = esc(String(c.dir_name || c.kind || "").toUpperCase().replace(/[-_]+/g, " ").slice(0, 18) || kind);
  return `<a class="ccard" href="/courses/${c.id}">
    <div class="ccard-art">${iconArt(c, 56)}</div>
    <div class="ccard-b"><div class="ccard-t"><span class="mono dim small ccard-code">${code}</span><span class="pill ${kind}">${kind}</span></div>
    <h3>${esc(c.title)}</h3>
    ${progressBar(pct, c.title)}<p class="mono dim small ccard-meta"><span>${Math.round(pct)}%</span><span>${done} / ${total} items</span></p></div></a>`;
}

// ---------- Library ----------
pages.get("/library", needAuth, async (req, res) => {
  const u = req.user;
  const q = (req.query.q || "").trim().toLowerCase();
  const f = req.query.f || "all", kind = req.query.kind || "all", sort = req.query.sort || "recent";
  let courses = await all(`SELECT * FROM courses ORDER BY title ASC`);
  const withP = [];
  for (const c of courses) withP.push({ c, ...(await courseProgress(u.id, c)) });
  // search across indexed lessons/pages/modules
  let matchIds = null;
  if (q) {
    const like = `%${q}%`;
    const ls = await all(`SELECT DISTINCT course_id FROM lessons WHERE LOWER(title) LIKE ? AND is_active=1`, [like]);
    const ps = await all(`SELECT DISTINCT course_id FROM reading_pages WHERE LOWER(title) LIKE ? AND is_active=1`, [like]);
    const gs = await all(`SELECT DISTINCT course_id FROM content_groups WHERE LOWER(title) LIKE ? AND is_active=1`, [like]);
    const cs = withP.filter((p) => p.c.title.toLowerCase().includes(q)).map((p) => p.c.id);
    matchIds = new Set([...ls.map((r) => r.course_id), ...ps.map((r) => r.course_id), ...gs.map((r) => r.course_id), ...cs]);
  }
  let list = withP.filter((p) => {
    if (matchIds && !matchIds.has(p.c.id)) return false;
    if (kind === "video" && !(p.lessons > 0)) return false;
    if (kind === "reading" && !(p.pages > 0)) return false;
    if (f === "progress" && !(p.done > 0 && p.pct < 100)) return false;
    if (f === "todo" && p.done !== 0) return false;
    if (f === "done" && !(p.total > 0 && p.pct >= 100)) return false;
    return true;
  });
  if (sort === "name") list.sort((a, b) => a.c.title.localeCompare(b.c.title));
  else if (sort === "progress") list.sort((a, b) => b.pct - a.pct);
  else list.sort((a, b) => (a.c.updated_at < b.c.updated_at ? 1 : -1));

  res.send(layout({ title: "Library", user: u, active: "library", body: `
  <div class="wrap">
    <div class="sech"><div><p class="eyebrow mono">library · ${list.length} courses</p><h1>Course library</h1></div></div>
    <form class="toolbar" method="get" action="/library">
      <input class="search" name="q" placeholder="Search courses, lessons, pages…" value="${esc(req.query.q || "")}">
      <div class="chips">
        ${["all", "progress", "todo", "done"].map((x) => `<button name="f" value="${x}" class="chip ${f === x ? "on" : ""}">${{ all: "All", progress: "In progress", todo: "Not started", done: "Completed" }[x]}</button>`).join("")}
        <span class="sep"></span>
        ${["all", "video", "reading"].map((x) => `<button name="kind" value="${x}" class="chip ${kind === x ? "on" : ""}">${x === "all" ? "Both" : x[0].toUpperCase() + x.slice(1)}</button>`).join("")}
        <input type="hidden" name="sort" value="${esc(sort)}">
      </div>
    </form>
    ${list.length ? `<div class="coursegrid">${list.map(courseCard).join("")}</div>`
      : emptyState(q ? "No courses found" : "Your library is empty", q ? "Try another search or clear the filters." : "Add courses to the configured course directory and they'll appear here.")}
  </div>` }));
});

// ---------- Course detail ----------
pages.get("/courses/:id", needAuth, async (req, res) => {
  const u = req.user;
  const c = await get(`SELECT * FROM courses WHERE id=?`, [req.params.id]);
  if (!c) return res.status(404).send(layout({ title: "Not found", user: u, body: `<div class="wrap">${emptyState("Course unavailable", "This course may have been removed. A rescan will refresh the library.")}</div>` }));
  const p = await courseProgress(u.id, c);
  const tree = await courseTree(c.id, u.id);
  const flatLessons = [];
  const flatPages = [];
  (function walk(n) {
    flatLessons.push(...n.lessons);
    flatPages.push(...n.pages);
    n.children.forEach(walk);
  })(tree);
  const firstLesson = flatLessons.find((l) => !l.done) || flatLessons[0];
  const firstPage = flatPages.find((x) => !x.done) || flatPages[0];
  const firstNext = firstLesson ? { t: "video", id: firstLesson.id } : firstPage ? { t: "reading", id: firstPage.id } : null;
  const kindLabel = p.lessons > 0 && p.pages > 0 ? "Mixed" : p.lessons > 0 ? "Video" : "Reading";
  const countLabel = [p.lessons ? `${p.lessons} lessons` : "", p.pages ? `${p.pages} pages` : ""].filter(Boolean).join(" · ") || "empty";
  const comp = p.total > 0 && p.pct >= 100 ? await get(`SELECT * FROM course_completions WHERE user_id=? AND course_id=?`, [u.id, c.id]) : null;

  res.send(layout({ title: c.title, user: u, active: "library", body: `
  <div class="wrap">
    <nav class="crumbs mono" aria-label="Breadcrumb"><a href="/library">library</a> / <span>${esc(c.title)}</span></nav>
    <section class="chead">
      ${iconArt(c, 88)}
      <div><p class="eyebrow mono">${esc(kindLabel)} course · ${esc(countLabel)}</p>
      <h1>${esc(c.title)}</h1>
      <p class="dim small mono">source: courses/${esc(c.kind)}/${esc(c.dir_name)}</p>
      <div class="crow"><div class="cfill">${progressBar(p.pct, c.title)}<span class="dim small">${Math.round(p.pct)}% · ${p.done}/${p.total}</span></div>
      ${firstNext ? `<a class="btn primary" href="/learn/${firstNext.t}/${firstNext.id}">${p.done === 0 ? "Start" : p.pct >= 100 ? "Review" : "Continue"} →</a>` : ""}</div></div>
    </section>
    ${comp ? `<div class="complete"><div><h3>Course complete</h3><p class="dim small">Finished ${fmtDate(comp.completed_at, u.timezone)} · ${fmtDur(comp.learned_secs)} learned · ${comp.items_done}/${comp.items_total} items</p></div><span class="seal">◆ 100%</span></div>` : ""}
    ${p.total === 0 ? emptyState("No lessons indexed", "The course folder has no recognised video, reading or resource files yet.") : renderDetailTree(tree)}
  </div>` }));
});

function lessonRow(l) {
  return `<li><a href="/learn/video/${l.id}"><span class="n mono">▸</span><span class="t">${esc(l.title)}</span>${l.done ? `<span class="done" aria-label="completed">✓</span>` : (l.pos ? `<span class="pct dim mono">${fmtClock(l.pos)}</span>` : "")}</a></li>`;
}
function pageRow(pg) {
  return `<li><a href="/learn/reading/${pg.id}"><span class="n mono">▸</span><span class="t">${esc(pg.title)}</span>${pg.done ? `<span class="done">✓</span>` : `<span class="pct dim mono">${Math.round((pg.scroll_pct || 0) * 100)}%</span>`}</a></li>`;
}
function resourceRow(r, lessonById) {
  const link = r.lesson_id && lessonById.get(r.lesson_id) ? ` → ${esc(lessonById.get(r.lesson_id).title)}` : "";
  return `<li class="res"><a href="/media/${r.course_id}/resource/${r.id}"><span class="pill res">${esc(r.kind)}</span><span class="t">${esc(r.title)}</span><span class="dim small mono">${esc(link)}</span></a></li>`;
}
// Full recursive detail tree. Depth is display-only (Module/Submodule/Section);
// the model itself is a generic parent/child hierarchy.
function renderDetailTree(node, lessonById = null) {
  if (!lessonById) {
    lessonById = new Map();
    (function idx(n) { n.lessons.forEach((l) => lessonById.set(l.id, l)); n.children.forEach(idx); })(node);
  }
  let html = "";
  for (const child of node.children) {
    const g = child.group;
    const counts = [
      child.lessons.length ? `${child.lessons.length} lessons` : "",
      child.pages.length ? `${child.pages.length} pages` : "",
      child.resources.length ? `${child.resources.length} files` : "",
    ].filter(Boolean).join(" · ");
    html += `<section class="mod tdepth-${Math.min(g.depth, 4)}"><h2><span class="mono dim">${esc(depthLabel(g.depth))}</span> ${esc(g.title)}${counts ? ` <span class="dim small mono">· ${esc(counts)}</span>` : ""}</h2>`;
    if (child.lessons.length) html += `<ol class="llist">${child.lessons.map(lessonRow).join("")}</ol>`;
    if (child.pages.length) html += `<ol class="llist">${child.pages.map(pageRow).join("")}</ol>`;
    if (child.resources.length) html += `<ol class="llist small">${child.resources.map((r) => resourceRow(r, lessonById)).join("")}</ol>`;
    html += renderDetailTree(child, lessonById) + `</section>`;
  }
  // renderRootItems is ROOT-ONLY: a group node's own lessons/pages/resources
  // were already rendered by its parent loop above. Appending them here
  // rendered every grouped item a second time under a duplicate
  // "Lessons"/"Reading"/"Files" heading. Root items are genuinely
  // ungrouped, so only they need the fallback section.
  return html + (node.group ? "" : renderRootItems(node, lessonById));
}
// Compact recursive sidebar: group labels nest, lessons + pages link.
function renderSideTree(node, currentId) {
  let html = "";
  const items = [
    ...node.lessons.map((l) => ({ t: "video", id: l.id, title: l.title, done: l.done })),
    ...node.pages.map((p) => ({ t: "reading", id: p.id, title: p.title, done: p.done })),
  ];
  if (items.length) {
    html += `<ol class="llist small">${items.map((s) => `<li><a href="/learn/${s.t}/${s.id}" class="${s.id === currentId ? "on" : ""}" title="${esc(s.title)}"><span class="n mono">▸</span><span class="t">${esc(s.title)}</span>${s.done ? `<span class="done">✓</span>` : ""}</a></li>`).join("")}</ol>`;
  }
  for (const child of node.children) {
    html += `<details class="tnode" open><summary><span class="mono dim small">${esc(depthLabel(child.group.depth))}</span> ${esc(child.group.title)}</summary>${renderSideTree(child, currentId)}</details>`;
  }
  return html;
}
function renderRootItems(node, lessonById) {  // Ungrouped (flat-course) items render without fake group headers.
  let html = "";
  if (node.lessons.length) html += `<section class="mod"><h2>Lessons</h2><ol class="llist">${node.lessons.map(lessonRow).join("")}</ol></section>`;
  if (node.pages.length) html += `<section class="mod"><h2>Reading</h2><ol class="llist">${node.pages.map(pageRow).join("")}</ol></section>`;
  if (node.resources.length) html += `<section class="mod"><h2>Files</h2><ol class="llist small">${node.resources.map((r) => resourceRow(r, lessonById)).join("")}</ol></section>`;
  return html;
}

// ---------- Learn: video ----------
pages.get("/learn/video/:id", needAuth, async (req, res) => {
  const u = req.user;
  const l = await get(`SELECT l.*, c.title course, c.id course_id FROM lessons l JOIN courses c ON c.id=l.course_id WHERE l.id=? AND l.is_active=1`, [req.params.id]);
  if (!l) return res.status(404).send(layout({ title: "Lesson unavailable", user: u, body: `<div class="wrap">${emptyState("Lesson unavailable", "This lesson may have been moved or removed.")}</div>` }));
  const prog = await get(`SELECT * FROM video_progress WHERE user_id=? AND lesson_id=?`, [u.id, l.id]);
  const sibs = await all(`SELECT id, title, position FROM lessons WHERE course_id=? AND COALESCE(group_id,'')=COALESCE(?,'') AND is_active=1 ORDER BY position ASC`, [l.course_id, l.group_id]);
  const idx = sibs.findIndex((s) => s.id === l.id);
  const prev = sibs[idx - 1], next = sibs[idx + 1];
  const tree = await courseTree(l.course_id, u.id);
  const chain = await groupChain(l.group_id);
  const settings = await get(`SELECT * FROM user_settings WHERE user_id=?`, [u.id]);
  const attached = await all(`SELECT * FROM resources WHERE lesson_id=? AND is_active=1 ORDER BY file_name ASC`, [l.id]);
  const subs = attached.filter((a) => a.kind === "subtitle");
  const files = attached.filter((a) => a.kind !== "subtitle");

  res.send(layout({ title: l.title, user: u, active: "library", extraScript: `<script src="/js/video.js" defer></script>`, body: `
  <div class="learn" data-lesson="${l.id}" data-course="${l.course_id}" data-pos="${prog?.position_secs || 0}" data-autoplay="${settings?.autoplay ?? 1}" data-speed="${+settings?.playback_speed || 1}" data-threshold="${config.videoCompletionThreshold}">
    <aside class="side" id="side"><div class="side-h"><a href="/courses/${l.course_id}">← ${esc(l.course)}</a>
      <button class="iconbtn" id="sideToggle" aria-label="Collapse sidebar">⟨</button></div>
      ${renderSideTree(tree, l.id)}
    </aside>
    <div class="stage">
      ${crumbs({ id: l.course_id, title: l.course }, chain, l.title)}
      <h1 class="ltitle">${esc(l.title)}</h1>
      <div class="player" id="player">
        <video id="vid" src="/media/${l.course_id}/video/${l.id}" preload="metadata" playsinline>${subs.map((s, i) => `<track kind="subtitles" src="/media/${l.course_id}/resource/${s.id}" srclang="en" label="${esc(s.title)}${subs.length > 1 ? ` ${i + 1}` : ""}">`).join("")}</video>
        <div class="pspinner" id="pSpin" aria-hidden="true"></div>
        <button class="pcenter" id="bigPlay" aria-label="Play (k)"><span class="pcircle">${PLAYER_ICONS.play}</span></button>
        <div class="pbadge mono" id="pDone"${prog?.completed ? "" : " hidden"}>Completed</div>
        <div class="perror" id="pError" hidden><p>This video couldn't be loaded.</p></div>
        <div class="pchrome">
          <div class="pbar-wrap"><div class="vidbar" id="seek" role="slider" tabindex="0" aria-label="Seek" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"><i id="seekBuf"></i><i id="seekFill"></i><span class="seektip mono" id="seekTip">0:00</span></div></div>
          <div class="controls">
            <button id="btnPlay" aria-label="Play or pause (k)">${PLAYER_ICONS.play}</button>
            <button id="btnRw" aria-label="Back 5 seconds (Left arrow)">${PLAYER_ICONS.rw}</button>
            <button id="btnFf" aria-label="Forward 5 seconds (Right arrow)">${PLAYER_ICONS.ff}</button>
            <button id="btnPrev" ${prev ? "" : "disabled"} aria-label="Previous lesson">${PLAYER_ICONS.prev}</button>
            <button id="btnNext" ${next ? "" : "disabled"} aria-label="Next lesson">${PLAYER_ICONS.next}</button>
            <span class="time mono"><span id="tCur">0:00</span> / <span id="tDur">0:00</span></span>
            <span class="sp"></span>
            <button id="btnMute" aria-label="Mute (m)" aria-pressed="false">${PLAYER_ICONS.vol}</button>
            <input id="vol" type="range" min="0" max="1" step="0.05" value="1" aria-label="Volume">
            ${subs.length ? `<button id="btnCC" aria-label="Subtitles" aria-pressed="false">${PLAYER_ICONS.cc}</button>` : ""}
            <button id="btnPip" aria-label="Picture in picture (p)">${PLAYER_ICONS.pip}</button>
            <button id="btnMenu" aria-label="Player settings" aria-expanded="false" aria-controls="pMenu">${PLAYER_ICONS.sliders}</button>
            <button id="btnFull" aria-label="Fullscreen (f)">${PLAYER_ICONS.max}</button>
          </div>
          <div class="pmenu" id="pMenu" hidden>
            <p class="mono dim">Speed</p>
            <div class="mrow" id="mSpeed" role="group" aria-label="Playback speed">${[0.5, 0.75, 1, 1.25, 1.5, 1.75, 2].map((s) => `<button data-speed="${s}" aria-pressed="${(+settings?.playback_speed || 1) === s ? "true" : "false"}">${s}×</button>`).join("")}</div>
            <div class="mrow"><button id="mTheater" aria-pressed="false">Theater mode</button></div>
            <p class="mono dim keys">Space play · ←/→ 5s · M mute · F fullscreen · P PiP</p>
          </div>
        </div>
        <div class="nextUp" id="nextUp" hidden><p class="mono">Next lesson in <b id="cd">5</b>…</p><div><button class="btn primary" id="playNow">Play now</button> <button class="btn" id="cancelAuto">Cancel</button></div></div>
      </div>
      <div class="lrow">
        <button class="btn" id="btnFocus">Focus mode</button>
        <button class="btn ${prog?.completed ? "done" : ""}" id="btnDone">${prog?.completed ? "✓ Completed" : "Mark as complete"}</button>
        ${prev ? `<a class="btn" href="/learn/video/${prev.id}">← ${esc(prev.title.slice(0, 28))}</a>` : `<span></span>`}
        ${next ? `<a class="btn primary" id="nextLink" href="/learn/video/${next.id}">${esc(next.title.slice(0, 28))} →</a>` : `<span></span>`}
      </div>
      ${files.length ? `<div class="attach"><p class="mono dim small">ATTACHED FILES</p><div class="lrow">${files.map((f) => `<a class="btn xs" href="/media/${l.course_id}/resource/${f.id}">⧉ ${esc(f.title)} <span class="dim">· ${esc(f.kind)}</span></a>`).join("")}</div></div>` : ""}
      <p class="dim small mono" data-next-id="${next?.id || ""}" data-prev-id="${prev?.id || ""}">space/k play · ←/→ 5s · f fullscreen · m mute · p PiP · resume saves automatically</p>
    </div>
  </div>` }));
});

// ---------- Learn: reading ----------
// Embedded data: images (base64 dumps in imported HTML) are extracted to
// files under DATA_DIR on first render and served as ordinary media URLs.
// Without this the sanitizer would have to either inline megabytes of
// base64 per page view or drop the images entirely.
const EMBEDDED_MIME = {
  png: "image/png", jpg: "image/jpeg", gif: "image/gif", webp: "image/webp",
  avif: "image/avif", bmp: "image/bmp", ico: "image/x-icon", tif: "image/tiff", svg: "image/svg+xml",
};
const readCache = new Map(); // key -> { html, headings }
function embeddedFile(courseId, pageId, file) {
  const base = path.join(config.dataDir, "embedded", courseId, pageId);
  const target = path.normalize(path.join(base, file));
  if (target !== base && !target.startsWith(base + path.sep)) throw new Error("path traversal blocked");
  return target;
}
function sniffEmbedded(buf, fallbackExt) {
  if (buf.length >= 8 && buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47) return "png";
  if (buf.length >= 6 && buf.toString("ascii", 0, 6) === "GIF89a") return "gif";
  if (buf.length >= 6 && buf.toString("ascii", 0, 6) === "GIF87a") return "gif";
  if (buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return "jpg";
  if (buf.length >= 12 && buf.toString("ascii", 0, 4) === "RIFF" && buf.toString("ascii", 8, 12) === "WEBP") return "webp";
  return fallbackExt;
}
pages.get("/learn/reading/:id", needAuth, async (req, res) => {
  const u = req.user;
  const p = await get(`SELECT p.*, c.title course, c.id course_id FROM reading_pages p JOIN courses c ON c.id=p.course_id WHERE p.id=? AND p.is_active=1`, [req.params.id]);
  if (!p) return res.status(404).send(layout({ title: "Page unavailable", user: u, body: `<div class="wrap">${emptyState("Page unavailable", "This page may have been moved or removed.")}</div>` }));
  const { sanitize } = await import("./sanitize.js");
  const { resolveInside } = await import("./scanner.js");
  const course = await get(`SELECT * FROM courses WHERE id=?`, [p.course_id]);
  let srcPath = "";
  try { srcPath = resolveInside(course, p.path_key); } catch { srcPath = ""; }
  let stat = null;
  try { stat = srcPath ? fs.statSync(srcPath) : null; } catch { stat = null; }
  const cacheKey = stat ? `${course.id}:${p.id}:${stat.mtimeMs}:${stat.size}` : "";
  let html = "", headings = [];
  if (cacheKey && readCache.has(cacheKey)) {
    ({ html, headings } = readCache.get(cacheKey));
  } else {
    let raw = "";
    try { raw = srcPath ? fs.readFileSync(srcPath, "utf8") : ""; } catch { raw = ""; }
    if (!raw) return res.status(500).send(layout({ title: "Parse error", user: u, body: `<div class="wrap">${emptyState("Couldn't render this page", "The source HTML could not be read. It may be encoded unusually.")}</div>` }));
    const pageDir = p.path_key.includes("/") ? p.path_key.slice(0, p.path_key.lastIndexOf("/")) : "";
    let imgIdx = 0;
    const onLargeImage = (dataUri, ext) => {
      const idx = imgIdx++;
      try {
        const comma = String(dataUri).indexOf(",");
        let b64 = comma >= 0 ? String(dataUri).slice(comma + 1) : "";
        b64 = b64.replace(/\s+/g, "");
        if (!b64 || b64.length > 200_000_000) return "";
        // Reuse the file from a previous render when the payload size
        // matches — avoids re-decoding a 100MB+ blob on every page view.
        const pad = b64.endsWith("==") ? 2 : b64.endsWith("=") ? 1 : 0;
        const expected = Math.floor((b64.length * 3) / 4) - pad;
        const dir = path.join(config.dataDir, "embedded", course.id, p.id);
        // Probe with the guessed ext first; sniff after decode may correct it.
        let file = `img-${idx}.${ext}`;
        let fp = embeddedFile(course.id, p.id, file);
        try {
          const st = fs.statSync(fp);
          if (st.isFile() && st.size === expected) return `/media/${course.id}/embedded/${p.id}/${file}`;
        } catch {}
        const buf = Buffer.from(b64, "base64");
        if (!buf.length) return "";
        const realExt = EMBEDDED_MIME[sniffEmbedded(buf, ext)] ? sniffEmbedded(buf, ext) : ext;
        file = `img-${idx}.${realExt}`;
        fp = embeddedFile(course.id, p.id, file);
        try {
          const st = fs.statSync(fp);
          if (st.isFile() && st.size === buf.length) return `/media/${course.id}/embedded/${p.id}/${file}`;
        } catch {}
        fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(fp, buf);
        return `/media/${course.id}/embedded/${p.id}/${file}`;
      } catch { return ""; }
    };
    ({ html, headings } = sanitize(raw, { mediaPrefix: `/media/${course.id}/asset`, linkPrefix: `/r/${course.id}`, pageDir, onLargeImage }));
    // Drop orphaned extracts from an older revision of the same page.
    try {
      const dir = path.join(config.dataDir, "embedded", course.id, p.id);
      for (const f of fs.readdirSync(dir)) {
        const m = /^img-(\d+)\.[a-z0-9]+$/i.exec(f);
        if (m && Number(m[1]) >= imgIdx) fs.rmSync(path.join(dir, f), { force: true });
      }
    } catch {}
    if (cacheKey) {
      readCache.set(cacheKey, { html, headings });
      if (readCache.size > 20) readCache.delete(readCache.keys().next().value);
    }
  }
  const prog = await get(`SELECT * FROM reading_progress WHERE user_id=? AND page_id=?`, [u.id, p.id]);
  const sibs = await all(`SELECT id, title, position FROM reading_pages WHERE course_id=? AND is_active=1 ORDER BY position ASC`, [p.course_id]);
  const idx = sibs.findIndex((s) => s.id === p.id);
  const prev = sibs[idx - 1], next = sibs[idx + 1];
  const tree = await courseTree(p.course_id, u.id);
  const chain = await groupChain(p.group_id);

  res.send(layout({ title: p.title, user: u, active: "library", extraScript: `<script src="/js/reader.js" defer></script>`, body: `
  <div class="learn reading" data-page="${p.id}" data-course="${p.course_id}" data-scroll="${prog?.scroll_px || 0}" data-threshold="${config.readingCompletionThreshold}">
    <aside class="side" id="side"><div class="side-h"><a href="/courses/${p.course_id}">← ${esc(p.course)}</a><button class="iconbtn" id="sideToggle" aria-label="Collapse sidebar">⟨</button></div>
      <p class="mono dim small">IN THIS COURSE</p>
      ${renderSideTree(tree, p.id)}
      ${headings.length ? `<p class="mono dim small">ON THIS PAGE</p><ol class="llist small ghost">${headings.slice(0, 12).map((h) => `<li><a href="#${h.id}">${esc(h.text)}</a></li>`).join("")}</ol>` : ""}
    </aside>
    <div class="stage read-stage">
      ${crumbs({ id: p.course_id, title: p.course }, chain, p.title)}
      <div class="readbar"><div class="pbar" id="readProgress"><i style="width:${Math.round((prog?.scroll_pct || 0) * 100)}%"></i></div></div>
      <article class="prose" id="prose"><h1>${esc(p.title)}</h1>${html || "<p class=dim>Empty page.</p>"}</article>
      <div class="lrow">
        <button class="btn" id="btnFocus">Focus mode</button>
        <button class="btn ${prog?.completed ? "done" : ""}" id="btnDone">${prog?.completed ? "✓ Completed" : "Mark as complete"}</button>
        ${prev ? `<a class="btn" href="/learn/reading/${prev.id}">← ${esc(prev.title.slice(0, 30))}</a>` : `<span></span>`}
        ${next ? `<a class="btn primary" href="/learn/reading/${next.id}">${esc(next.title.slice(0, 30))} →</a>` : `<span class="seal">◆ end</span>`}
      </div>
    </div>
  </div>` }));
});

// internal-link redirect: /r/:courseId/<url-encoded relative path>
// NOTE: express 4 wildcards are anonymous — the match lands in req.params[0].
pages.get("/r/:cid/*", needAuth, async (req, res) => {
  const target = req.params[0] || "";
  const row = await get(`SELECT id FROM reading_pages WHERE course_id=? AND path_key=? AND is_active=1`, [req.params.cid, target]);
  if (row) return res.redirect(`/learn/reading/${row.id}`);
  res.status(404).send(layout({ title: "Not found", user: req.user, body: `<div class="wrap">${emptyState("Link target unavailable", "The linked page isn't indexed.")}</div>` }));
});

// ---------- Profile / settings ----------
pages.get("/profile", needAuth, async (req, res) => {
  const u = req.user;
  const tot = await totals(u.id);
  const st = await streaks(u.id, req.tzOffset);
  const rows = await yearActivity(u.id);
  const bands = intensityLevels(rows);
  // Profile activity is scoped to the current month (user timezone).
  const monthStart = dayFor(req.tzOffset).slice(0, 7) + "-01";
  const monthName = new Date(monthStart + "T12:00:00Z").toLocaleDateString(undefined, { month: "long" });
  const monthRows = rows.filter((r) => r.day >= monthStart);
  const monthSecs = monthRows.reduce((a, r) => a + (r.video_secs || 0) + (r.reading_secs || 0), 0);
  const monthVideo = monthRows.reduce((a, r) => a + (r.video_secs || 0), 0);
  const monthReading = monthRows.reduce((a, r) => a + (r.reading_secs || 0), 0);
  const monthActive = monthRows.filter((r) => (r.video_secs || 0) + (r.reading_secs || 0) > 0).length;
  const monthBest = monthRows.reduce((a, r) => ((r.video_secs || 0) + (r.reading_secs || 0) > ((a?.video_secs || 0) + (a?.reading_secs || 0)) ? r : a), null);
  const monthBestDay = monthBest ? new Date(monthBest.day + "T12:00:00Z").toLocaleDateString(undefined, { weekday: "short" }) : "—";
  const monthBestSecs = monthBest ? ((monthBest.video_secs || 0) + (monthBest.reading_secs || 0)) : 0;
  const monthMeta = `${monthName} · ${fmtDur(monthSecs)} learned · ${monthActive} active day${monthActive === 1 ? "" : "s"} · ${fmtDur(monthVideo)} video · ${fmtDur(monthReading)} reading`;
  const profActivity = rows.length ? `<div class="act">
      <div class="act-main">${graphHtml(rows, bands, "month")}</div>
      <aside class="act-side" aria-label="This month summary">
        <p class="eyebrow mono">This month</p>
        <div class="act-stats">
          <div class="act-stat"><span class="mono dim">learned</span><b>${fmtDur(monthSecs)}</b></div>
          <div class="act-stat"><span class="mono dim">active days</span><b>${monthActive}</b></div>
          <div class="act-stat"><span class="mono dim">most active</span><b>${monthBestDay}${monthBestSecs ? ` <em class="mono dim">${fmtDur(monthBestSecs)}</em>` : ""}</b></div>
        </div>
      </aside>
    </div>` : emptyState("No learning activity yet.", "Start a lesson and your history will appear here.", `<a class="btn primary" href="/library">Browse Library</a>`);
  res.send(layout({ title: "Profile", user: u, active: "profile", body: `<div class="wrap narrow">
  <div class="phead">${avatarHtml(u, true)}
  <div><h1>${esc(u.display_name)}</h1><p class="dim mono small">@${esc(u.username)} · ${esc(u.email)} · ${esc(u.role)}</p></div>
  <a class="btn" href="/settings">Settings</a></div>
  <div class="statrow">
    <div class="stat"><div class="stat-top"><span class="mono dim stat-label">Total learned</span><span class="stat-glyph" aria-hidden="true">▤</span></div><b>${fmtDur(tot.videoSecs + tot.readingSecs)}</b><small class="mono dim">${fmtDur(tot.videoSecs)} video · ${fmtDur(tot.readingSecs)} reading</small></div>
    <div class="stat"><div class="stat-top"><span class="mono dim stat-label">Current streak</span><span class="stat-glyph" aria-hidden="true">◉</span></div><b>${st.current}d</b><small class="mono dim">longest ${st.longest}d</small></div>
    <div class="stat"><div class="stat-top"><span class="mono dim stat-label">Courses done</span><span class="stat-glyph" aria-hidden="true">◆</span></div><b>${tot.coursesCompleted}</b></div>
    <div class="stat"><div class="stat-top"><span class="mono dim stat-label">Lessons done</span><span class="stat-glyph" aria-hidden="true">✓</span></div><b>${tot.completions}</b></div>
  </div>
  <section class="card act-card prof-act" aria-label="Activity">
    <div class="act-head"><div><h2><span class="h-ic" aria-hidden="true">◐</span> Activity</h2><p class="dim small act-sub mono">${monthMeta}</p></div></div>
    ${profActivity}
  </section>
  </div>` }));
});

pages.get("/settings", needAuth, async (req, res) => {
  const u = req.user;
  const s = await get(`SELECT * FROM user_settings WHERE user_id=?`, [u.id]);
  res.send(layout({ title: "Settings", user: u, active: "settings", body: `<div class="wrap narrow">
  <h1>Settings</h1>
  <div id="saveMsg"></div>
  <section class="card" aria-labelledby="picH">
    <h3 id="picH">Profile picture</h3>
    <div class="pic-row">
      <div class="pic-prev" id="picPrev" data-initials="${esc(initials(u.display_name))}">${avatarHtml(u, true)}</div>
      <div class="pic-body">
        <p class="dim small pic-sub">Square-cropped in your browser and kept small. Shown in the topbar and on your profile.</p>
        <div class="lrow pic-actions">
          <button class="btn" type="button" id="picChoose">Choose picture</button>
          <input type="file" id="picFile" accept="image/png,image/jpeg,image/webp,image/gif" hidden>
          <button class="btn danger" type="button" id="picRemove">Remove</button>
        </div>
        <p class="mono dim small" id="picMsg" role="status"></p>
      </div>
    </div>
  </section>
  <form class="card form" id="profileForm">
    <h3>Profile</h3>
    <label>Display name<input name="display_name" value="${esc(u.display_name)}" maxlength="80"></label>
    <label>Email<input name="email" type="email" value="${esc(u.email)}"></label>
    <label>Timezone (IANA, e.g. Asia/Kolkata)<input name="timezone" value="${esc(u.timezone)}" maxlength="60" placeholder="Asia/Kolkata"><small class="dim">Formats dates shown to you. Daily activity follows this device's clock.</small></label>
    <button class="btn primary" type="submit">Save profile</button>
  </form>
  <form class="card form" id="passForm"><h3>Password</h3>
    <label>Current password<input name="current" type="password" autocomplete="current-password"></label>
    <label>New password (min 10 chars)<input name="next" type="password" minlength="10" autocomplete="new-password"></label>
    <button class="btn primary" type="submit">Change password</button></form>
  <form class="card form" id="prefForm"><h3>Learning preferences</h3>
    <label class="check"><input type="checkbox" name="autoplay" ${s?.autoplay ? "checked" : ""}> Autoplay countdown after videos</label>
    <label>Default playback speed<select name="playback_speed">${[0.5, 0.75, 1, 1.25, 1.5, 1.75, 2].map((v) => `<option ${(+s?.playback_speed || 1) === v ? "selected" : ""}>${v}</option>`).join("")}</select></label>
    <button class="btn primary" type="submit">Save preferences</button></form>
  <section class="card sess" aria-labelledby="sessH">
    <h3 id="sessH">Session security</h3>
    <p class="dim small sess-sub">You are currently signed in. Ending the session signs you out of Axiom on this browser.</p>
    <form method="post" action="/logout" id="signoutForm">
      <button class="btn danger" type="submit" id="signoutBtn">Sign out</button>
    </form>
    <p class="mono dim small sess-note">ends this session · you'll sign in again next visit</p>
    <dialog class="confirm" id="signoutDialog" aria-labelledby="soT">
      <h3 id="soT">Sign out?</h3>
      <p class="dim small">You'll be signed out of Axiom and returned to the sign-in page.</p>
      <div class="confirm-row">
        <button class="btn" type="button" id="soCancel">Cancel</button>
        <button class="btn danger" type="button" id="soConfirm">Sign out</button>
      </div>
    </dialog>
  </section>
  <script>document.getElementById('profileForm').onsubmit=saveJSON('/api/settings/profile','saveMsg');document.getElementById('passForm').onsubmit=saveJSON('/api/settings/password','saveMsg');document.getElementById('prefForm').onsubmit=saveJSON('/api/settings/prefs','saveMsg');</script>
  <script>
  // Profile picture: validated client-side, cropped to a 256px square JPEG
  // in-browser so uploads stay small, then stored via the avatar endpoint.
  (function(){const file=document.getElementById('picFile'),choose=document.getElementById('picChoose'),remove=document.getElementById('picRemove'),msg=document.getElementById('picMsg'),prev=document.getElementById('picPrev');if(!file||!choose||!prev)return;
  const say=(t)=>{if(msg)msg.textContent=t;};
  const paint=(url)=>{const init=prev.dataset.initials||'?';
    prev.innerHTML=url?'<img class="avatar-img big" src="'+url+'" alt="">':'<div class="avatar big" aria-hidden="true">'+init+'</div>';
    const cur=document.querySelector('.acct summary > :first-child');
    if(cur)cur.outerHTML=url?'<img class="avatar-img" src="'+url+'" alt="">':'<span class="avatar" aria-hidden="true">'+init+'</span>';};
  choose.addEventListener('click',()=>file.click());
  file.addEventListener('change',()=>{const f=file.files[0];file.value='';if(!f)return;
    if(!/^image\\/(png|jpeg|jpg|webp|gif)$/.test(f.type)){say('Choose a PNG, JPG, WEBP or GIF file.');return;}
    if(f.size>8*1024*1024){say('That file is too large (max 8MB).');return;}
    say('Preparing…');const img=new Image(),obj=URL.createObjectURL(f);
    img.onload=()=>{URL.revokeObjectURL(obj);
      try{const S=256,c=document.createElement('canvas');c.width=c.height=S;const ctx=c.getContext('2d');
      const side=Math.min(img.naturalWidth,img.naturalHeight);
      ctx.drawImage(img,(img.naturalWidth-side)/2,(img.naturalHeight-side)/2,side,side,0,0,S,S);
      const dataUrl=c.toDataURL('image/jpeg',.85);say('Uploading…');
      fetch('/api/settings/avatar',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({dataUrl})})
        .then(async(r)=>{const j=await r.json().catch(()=>({}));if(!r.ok)throw new Error(j.error||'Upload failed.');return j;})
        .then((j)=>{paint(j.url);say('Profile picture updated.');toast('Profile picture updated');})
        .catch((e)=>say(e.message||'Upload failed.'));}catch(e){say('Could not process that image.');}};
    img.onerror=()=>{URL.revokeObjectURL(obj);say('Could not read that image.');};
    img.src=obj;});
  remove.addEventListener('click',()=>{fetch('/api/settings/avatar',{method:'DELETE'})
    .then(async(r)=>{if(!r.ok)throw new Error('Remove failed.');paint(null);say('Profile picture removed.');toast('Profile picture removed');})
    .catch((e)=>say(e.message||'Remove failed.'));});})();
  </script>
  <script>
  // Confirm-then-submit over the existing POST /logout endpoint: without JS
  // the form signs out directly (unchanged behavior); with JS a native dialog
  // confirms first (Escape dismisses, focus is managed by the dialog).
  (function(){const f=document.getElementById('signoutForm'),d=document.getElementById('signoutDialog');if(!f||!d)return;
  f.addEventListener('submit',(e)=>{if(d.dataset.ok==='1'||typeof d.showModal!=='function')return;e.preventDefault();d.showModal();document.getElementById('soCancel').focus();});
  document.getElementById('soCancel').addEventListener('click',()=>d.close());
  document.getElementById('soConfirm').addEventListener('click',()=>{d.dataset.ok='1';f.requestSubmit();});
  d.addEventListener('close',()=>{if(d.dataset.ok!=='1')document.getElementById('signoutBtn').focus({preventScroll:true});});})();
  </script>
  </div>` }));
});

// ---------- Admin ----------
pages.get("/admin", needAdmin, async (req, res) => {
  const users = await all(`SELECT id, username, email, display_name, role, status, created_at, last_seen_at FROM users ORDER BY created_at ASC`);
  const courses = await all(`SELECT * FROM courses ORDER BY title ASC`);
  const scan = await get(`SELECT * FROM scan_state WHERE id=1`);
  const invs = await all(`SELECT id, role, email_hint, expires_at, used_at, created_at FROM invitations ORDER BY created_at DESC LIMIT 20`);
  const tu = await get(`SELECT COUNT(*) n FROM users`);
  const tc = await get(`SELECT COUNT(*) n FROM courses`);
  const tl = await get(`SELECT (SELECT COUNT(*) FROM lessons WHERE is_active=1)+(SELECT COUNT(*) FROM reading_pages WHERE is_active=1) n`);
  const tt = await get(`SELECT SUM(video_secs+reading_secs) s FROM daily_activity`);
  const recent = await all(`SELECT d.day, d.video_secs, d.reading_secs, u.display_name FROM daily_activity d JOIN users u ON u.id=d.user_id ORDER BY d.day DESC LIMIT 10`);
  let storage = "n/a";
  try {
    const { execSync } = await import("node:child_process");
    storage = execSync(`du -sh "${config.coursesRoot}" 2>/dev/null | cut -f1`).toString().trim() || "n/a";
  } catch {}
  const rows = courses.map((c) => `<tr><td>${esc(c.title)}</td><td><span class="pill ${c.kind}">${c.kind}</span></td><td class="mono">${c.lesson_count || c.page_count || 0}</td><td class="mono dim">${c.last_scanned_at ? fmtDate(c.last_scanned_at) : "—"}</td></tr>`).join("");
  res.send(layout({ title: "Admin", user: req.user, active: "admin", body: `<div class="wrap wide">
  <p class="eyebrow mono">admin console</p><h1>System overview</h1>
  <div class="statrow">
    <div class="stat"><span class="mono dim">users</span><b>${tu.n}</b></div>
    <div class="stat"><span class="mono dim">courses</span><b>${tc.n}</b></div>
    <div class="stat"><span class="mono dim">items</span><b>${tl.n || 0}</b></div>
    <div class="stat"><span class="mono dim">learned</span><b>${fmtDur(tt.s || 0)}</b></div>
    <div class="stat"><span class="mono dim">storage</span><b>${esc(storage)}</b></div>
  </div>
  <div class="admin-grid">
  <section class="card"><div class="sech"><h2>Scanner</h2><span class="pill ${scan.last_status === "ok" ? "reading" : "video"}">${esc(scan.last_status)}</span></div>
    <p class="dim small mono">last ok: ${scan.last_ok_at ? fmtDate(scan.last_ok_at) : "never"} · root: ${esc(config.coursesRoot)}</p>
    ${scan.last_error ? `<div class="alert">${esc(scan.last_error)}</div>` : ""}
    <div class="lrow"><button class="btn primary" id="rescan">Rescan courses</button><span class="dim small" id="scanMsg"></span></div>
    <h3>Courses</h3><div class="tablewrap"><table><thead><tr><th>Title</th><th>Type</th><th>Items</th><th>Scanned</th></tr></thead><tbody>${rows}</tbody></table></div></section>
  <section class="card"><div class="sech"><h2>Users</h2><span class="dim small mono">${users.length}</span></div>
    <div class="tablewrap"><table><thead><tr><th>User</th><th>Role</th><th>Status</th><th></th></tr></thead><tbody>
    ${users.map((x) => `<tr><td><b>${esc(x.display_name)}</b><br><span class="dim small mono">@${esc(x.username)}</span></td><td>${esc(x.role)}</td><td>${esc(x.status)}</td>
    <td>${x.id !== req.user.id ? `<button class="btn xs" data-act="${x.status === "active" ? "disable" : "enable"}" data-id="${x.id}">${x.status === "active" ? "Disable" : "Enable"}</button>` : `<span class="dim small">you</span>`}</td></tr>`).join("")}
    </tbody></table></div>
    <h3>Invitations</h3>
    <form id="invForm" class="lrow"><input name="email_hint" placeholder="email hint (optional)"><select name="role"><option>user</option><option>admin</option></select><button class="btn primary">Generate invitation</button></form>
    <div id="invOut"></div>
    <ul class="llist small">${invs.map((i) => `<li><span class="mono small">${esc(i.id.slice(0, 12))}… · ${esc(i.role)} · ${i.used_at ? "used" : "open"} · exp ${esc(i.expires_at.slice(0, 10))}</span></li>`).join("")}</ul></section>
  </div>
  <section class="card"><h2>Recent activity</h2><div class="tablewrap"><table><thead><tr><th>Day</th><th>User</th><th>Learned</th></tr></thead><tbody>
  ${recent.map((r) => `<tr><td class="mono">${r.day}</td><td>${esc(r.display_name)}</td><td class="mono">${fmtDur(r.video_secs + r.reading_secs)}</td></tr>`).join("") || `<tr><td colspan=3 class=dim>No activity yet.</td></tr>`}
  </tbody></table></div></section>
  </div>
  <script>
  document.getElementById('rescan').onclick=async(e)=>{e.target.disabled=true;document.getElementById('scanMsg').textContent='Scanning…';const r=await fetch('/api/admin/scan',{method:'POST'});const j=await r.json();document.getElementById('scanMsg').textContent=j.ok?('Done · '+j.courses+' courses'):(j.error||'Failed');e.target.disabled=false;toast(j.ok?'Scan completed':'Scan failed');if(j.ok)setTimeout(()=>location.reload(),800);};
  document.querySelectorAll('[data-act]').forEach(b=>b.onclick=async()=>{await fetch('/api/admin/users/'+b.dataset.id,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:b.dataset.act})});location.reload();});
  document.getElementById('invForm').onsubmit=async(e)=>{e.preventDefault();const fd=new FormData(e.target);const r=await fetch('/api/admin/invites',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email_hint:fd.get('email_hint'),role:fd.get('role')})});const j=await r.json();document.getElementById('invOut').innerHTML=j.url?'<p class=mono>Share link (single-use, expires):<br><input value=\\''+j.url+'\\' readonly onclick=this.select() style=width:100%></p>':(j.error||'Failed');toast('Invitation created');};
  </script>` }));
});
