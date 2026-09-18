import { Router } from "express";
import fs from "node:fs";
import path from "node:path";
import { all, get } from "./db.js";
import { config } from "./config.js";
import { layout, esc, fmtDur, fmtClock, fmtDate, initials, progressBar, graphHtml, emptyState, iconArt } from "./views.js";
import { yearActivity, intensityLevels, streaks, totals } from "./stats.js";
import { courseDir } from "./scanner.js";

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
  // most recently touched unfinished content across courses
  const vids = await all(
    `SELECT l.id content_id, l.title, l.course_id, c.title course, c.kind, vp.position_secs pos, vp.duration_secs dur, vp.updated_at ts, 'video' t
     FROM video_progress vp JOIN lessons l ON l.id=vp.lesson_id JOIN courses c ON c.id=l.course_id
     WHERE vp.user_id=? AND COALESCE(vp.completed,0)=0 AND l.is_active=1 ORDER BY vp.updated_at DESC LIMIT 6`, [userId]);
  const rds = await all(
    `SELECT p.id content_id, p.title, p.course_id, c.title course, c.kind, rp.scroll_pct pos, rp.updated_at ts, 'reading' t
     FROM reading_progress rp JOIN reading_pages p ON p.id=rp.page_id JOIN courses c ON c.id=p.course_id
     WHERE rp.user_id=? AND COALESCE(rp.completed,0)=0 AND p.is_active=1 ORDER BY rp.updated_at DESC LIMIT 6`, [userId]);
  const items = [...vids.map((v) => ({ ...v })), ...rds.map((r) => ({ ...r }))].sort((a, b) => (a.ts < b.ts ? 1 : -1)).slice(0, 4);
  // if nothing in progress, suggest untouched first items of courses with 0 progress
  if (!items.length) {
    const { natSort } = await import("./scanner.js");
    const courses = await all(`SELECT * FROM courses ORDER BY updated_at DESC LIMIT 4`);
    for (const c of courses) {
      const ls = await all(`SELECT id, title, path_key FROM lessons WHERE course_id=? AND is_active=1`, [c.id]);
      ls.sort((a, b) => natSort(a.path_key, b.path_key));
      if (ls.length) {
        items.push({ t: "video", content_id: ls[0].id, title: ls[0].title, course: c.title, course_id: c.id, kind: c.kind, fresh: true });
        continue;
      }
      const ps = await all(`SELECT id, title, path_key FROM reading_pages WHERE course_id=? AND is_active=1`, [c.id]);
      ps.sort((a, b) => natSort(a.path_key, b.path_key));
      if (ps.length) items.push({ t: "reading", content_id: ps[0].id, title: ps[0].title, course: c.title, course_id: c.id, kind: c.kind, fresh: true });
    }
  }
  return items;
}

// ---------- Auth pages ----------
pages.get("/login", (req, res) => {
  if (req.user) return res.redirect("/");
  res.send(layout({ title: "Sign in", user: null, body: `
  <div class="authwrap"><div class="authcard">
    <div class="brand big"><span class="brand-mark">◈</span><span class="brand-name">Lumen</span></div>
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
    <div class="brand big"><span class="brand-mark">◈</span><span class="brand-name">Lumen</span></div>
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
  const done = prog.filter((p) => p.pct >= 100 && p.total > 0);
  const cont = await continueItems(u.id);
  const rows = await yearActivity(u.id);
  const bands = intensityLevels(rows);
  const st = await streaks(u.id, req.tzOffset);
  const tot = await totals(u.id);
  const recent = rows.slice(-7).reduce((a, r) => a + r.video_secs + r.reading_secs, 0);

  res.send(layout({ title: "Workspace", user: u, active: "home", body: `
  <div class="wrap">
    <section class="hero"><div>
      <p class="eyebrow mono">workspace · ${esc(new Date().toLocaleDateString(undefined, { weekday: "long", month: "long", day: "numeric" }))}</p>
      <h1>Good to see you, ${esc(u.display_name.split(" ")[0])}.</h1>
      <p class="dim">${recent > 0 ? `You've learned <b>${fmtDur(recent)}</b> in the last 7 days.` : "Pick up where you left off — progress saves itself."}</p>
    </div></section>
    <div class="statrow">
      <div class="stat"><span class="mono dim">streak</span><b>${st.current} day${st.current === 1 ? "" : "s"}</b><small>longest ${st.longest}</small></div>
      <div class="stat"><span class="mono dim">learned</span><b>${fmtDur(tot.videoSecs + tot.readingSecs)}</b><small>${fmtDur(tot.videoSecs)} video · ${fmtDur(tot.readingSecs)} reading</small></div>
      <div class="stat"><span class="mono dim">completed</span><b>${tot.coursesCompleted} course${tot.coursesCompleted === 1 ? "" : "s"}</b><small>${done.length} at 100%</small></div>
    </div>

    <section><div class="sech"><h2>Continue learning</h2><a class="link" href="/library">Browse library →</a></div>
    ${cont.length ? `<div class="contgrid">${cont.map((it) => `
      <a class="contcard" href="/learn/${it.t}/${it.content_id}">
        <div class="cont-top"><span class="pill ${it.t}">${it.t === "video" ? "Video" : "Reading"}</span><span class="dim small mono">${esc(it.course)}</span></div>
        <h3>${esc(it.title)}</h3>
        ${it.t === "video" && it.dur ? `<p class="dim small mono">${fmtClock(it.pos)} / ${fmtClock(it.dur)}${it.dur ? ` · ${Math.round((it.pos / it.dur) * 100)}%` : ""}</p>${progressBar((it.pos / it.dur) * 100)}` : ""}
        ${it.t === "reading" && it.pos !== undefined && !it.fresh ? `<p class="dim small mono">${Math.round(it.pos * 100)}% through this page</p>${progressBar(it.pos * 100)}` : ""}
        ${it.fresh ? `<p class="dim small">Not started yet — begin here.</p>` : ""}
        <span class="resume">${it.t === "video" ? "Resume →" : "Continue reading →"}</span>
      </a>`).join("")}</div>`
    : emptyState("Start your first lesson", "Add courses to the courses/ directory and they'll appear here.", `<a class="btn primary" href="/library">Open library</a>`)}</section>

    <section><div class="sech"><h2>Activity</h2><span class="dim small mono">${fmtDur(rows.reduce((a, r) => a + r.video_secs + r.reading_secs, 0))} total</span></div>
    <div class="card">${graphHtml(rows, bands)}</div></section>

    <section><div class="sech"><h2>In progress</h2><a class="link" href="/library?f=progress">View all →</a></div>
    ${inProg.length ? `<div class="coursegrid">${inProg.slice(0, 6).map((p) => courseCard(p)).join("")}</div>` : `<div class="card dim">Nothing in progress. ${notStarted.length ? "Something new is waiting in the library." : ""}</div>`}</section>
  </div>` }));
});

function courseCard({ c, done, total, pct, lessons, pages }) {
  const kind = lessons > 0 && pages > 0 ? "mixed" : c.kind;
  return `<a class="ccard" href="/courses/${c.id}">
    ${iconArt(c)}
    <div class="ccard-b"><div class="ccard-t"><h3>${esc(c.title)}</h3><span class="pill ${kind}">${kind}</span></div>
    <p class="dim small mono">${total} item${total === 1 ? "" : "s"}${c.total_seconds ? ` · ${fmtDur(c.total_seconds)}` : ""}</p>
    ${progressBar(pct, c.title)}<p class="dim small">${Math.round(pct)}% · ${done}/${total}</p></div></a>`;
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
    const cs = withP.filter((p) => p.c.title.toLowerCase().includes(q)).map((p) => p.c.id);
    matchIds = new Set([...ls.map((r) => r.course_id), ...ps.map((r) => r.course_id), ...cs]);
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
  return html + renderRootItems(node, lessonById);
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
  <div class="learn" data-lesson="${l.id}" data-course="${l.course_id}" data-pos="${prog?.position_secs || 0}" data-autoplay="${settings?.autoplay ?? 1}" data-threshold="${config.videoCompletionThreshold}">
    <aside class="side" id="side"><div class="side-h"><a href="/courses/${l.course_id}">← ${esc(l.course)}</a>
      <button class="iconbtn" id="sideToggle" aria-label="Collapse sidebar">⟨</button></div>
      ${renderSideTree(tree, l.id)}
    </aside>
    <div class="stage">
      ${crumbs({ id: l.course_id, title: l.course }, chain, l.title)}
      <h1 class="ltitle">${esc(l.title)}</h1>
      <div class="player" id="player">
        <video id="vid" src="/media/${l.course_id}/video/${l.id}" preload="metadata" playsinline>${subs.map((s, i) => `<track kind="subtitles" src="/media/${l.course_id}/resource/${s.id}" srclang="en" label="${esc(s.title)}${subs.length > 1 ? ` ${i + 1}` : ""}">`).join("")}</video>
        <div class="pcenter" id="bigPlay" aria-hidden="true">▶</div>
        <div class="pbar-wrap"><div class="pbar vidbar" id="seek"><i id="seekFill"></i><em id="seekDot"></em></div></div>
        <div class="controls">
          <button id="btnPlay" aria-label="Play or pause (k)">▶</button>
          <button id="btnPrev" ${prev ? "" : "disabled"} aria-label="Previous lesson">⏮</button>
          <button id="btnNext" ${next ? "" : "disabled"} aria-label="Next lesson">⏭</button>
          <span class="time mono"><span id="tCur">0:00</span> / <span id="tDur">0:00</span></span>
          <span class="sp"></span>
          <select id="selSpeed" aria-label="Playback speed">${[0.5, 0.75, 1, 1.25, 1.5, 1.75, 2].map((s) => `<option value="${s}" ${(+settings?.playback_speed || 1) === s ? "selected" : ""}>${s}×</option>`).join("")}</select>
          <button id="btnMute" aria-label="Mute (m)">♪</button>
          <input id="vol" type="range" min="0" max="1" step="0.05" value="1" aria-label="Volume">
          <button id="btnPip" aria-label="Picture in picture">⧉</button>
          <button id="btnFull" aria-label="Fullscreen (f)">⛶</button>
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
      <p class="dim small mono" data-next-id="${next?.id || ""}" data-prev-id="${prev?.id || ""}">space/k play · ←/→ seek · f fullscreen · m mute · resume saves automatically</p>
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
  res.send(layout({ title: "Profile", user: u, body: `<div class="wrap narrow">
  <div class="phead"><div class="avatar big">${esc(initials(u.display_name))}</div>
  <div><h1>${esc(u.display_name)}</h1><p class="dim mono small">@${esc(u.username)} · ${esc(u.email)} · ${esc(u.role)}</p></div>
  <a class="btn" href="/settings">Settings</a></div>
  <div class="statrow">
    <div class="stat"><span class="mono dim">total learned</span><b>${fmtDur(tot.videoSecs + tot.readingSecs)}</b></div>
    <div class="stat"><span class="mono dim">current streak</span><b>${st.current}d</b><small>longest ${st.longest}d</small></div>
    <div class="stat"><span class="mono dim">courses done</span><b>${tot.coursesCompleted}</b></div>
    <div class="stat"><span class="mono dim">lessons done</span><b>${tot.completions}</b></div>
  </div>
  <h2>Activity</h2><div class="card">${graphHtml(rows, bands)}</div>
  </div>` }));
});

pages.get("/settings", needAuth, async (req, res) => {
  const u = req.user;
  const s = await get(`SELECT * FROM user_settings WHERE user_id=?`, [u.id]);
  res.send(layout({ title: "Settings", user: u, body: `<div class="wrap narrow">
  <h1>Settings</h1>
  <div id="saveMsg"></div>
  <form class="card form" id="profileForm">
    <h3>Profile</h3>
    <label>Display name<input name="display_name" value="${esc(u.display_name)}" maxlength="80"></label>
    <label>Email<input name="email" type="email" value="${esc(u.email)}"></label>
    <label>Timezone (IANA, e.g. Europe/Berlin)<input name="timezone" value="${esc(u.timezone)}"></label>
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
  <form class="card" method="post" action="/logout"><h3>Session</h3><button class="btn" type="submit">Sign out everywhere</button></form>
  <script>document.getElementById('profileForm').onsubmit=saveJSON('/api/settings/profile','saveMsg');document.getElementById('passForm').onsubmit=saveJSON('/api/settings/password','saveMsg');document.getElementById('prefForm').onsubmit=saveJSON('/api/settings/prefs','saveMsg');</script>
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
