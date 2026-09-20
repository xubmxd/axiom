// HTML view layer — server-rendered MPA with shared design system.
import fs from "node:fs";
import path from "node:path";
import { config } from "./config.js";
import { levelFor } from "./stats.js";

export function esc(s) {
  return String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
export function fmtDur(totalSecs) {
  totalSecs = Math.max(0, Math.round(totalSecs || 0));
  const h = Math.floor(totalSecs / 3600), m = Math.floor((totalSecs % 3600) / 60), s = totalSecs % 60;
  if (h > 0) return `${h}h ${String(m).padStart(2, "0")}m`;
  if (m > 0) return `${m}m ${String(s).padStart(2, "0")}s`;
  return `${s}s`;
}
export function fmtClock(s) {
  s = Math.max(0, Math.floor(s || 0));
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  return h > 0 ? `${h}:${String(m).padStart(2, "0")}:${String(sec).padStart(2, "0")}` : `${m}:${String(sec).padStart(2, "0")}`;
}
export function fmtDate(iso, tz = "UTC") {
  try {
    return new Date(iso).toLocaleDateString(undefined, { timeZone: tz, month: "short", day: "numeric", year: "numeric" });
  } catch { return iso?.slice(0, 10) || ""; }
}
export function fmtRel(iso) {
  const t = new Date(iso).getTime();
  if (!t) return "";
  const s = Math.max(0, (Date.now() - t) / 1000);
  if (s < 60) return "just now";
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  if (d === 1) return "Yesterday";
  if (d < 7) return `${d}d ago`;
  return new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}
export function initials(name) {
  return String(name || "?").trim().split(/\s+/).slice(0, 2).map((w) => w[0]?.toUpperCase()).join("") || "?";
}

// Profile picture if the user uploaded one (DATA_DIR/avatars/<id>.<ext>),
// otherwise the existing initials fallback. Decorative: surrounding labels
// carry the accessible name.
const AVATAR_LOOKUP_EXTS = ["jpg", "png", "webp", "gif"];
function avatarUrl(user) {
  if (!user?.id || !/^[A-Za-z0-9_-]{1,64}$/.test(user.id)) return null;
  for (const ext of AVATAR_LOOKUP_EXTS) {
    try {
      const st = fs.statSync(path.join(config.dataDir, "avatars", `${user.id}.${ext}`));
      if (st.isFile()) return `/media/avatar/${user.id}.${ext}?v=${Math.floor(st.mtimeMs)}`;
    } catch {}
  }
  return null;
}
export function avatarHtml(user, big = false) {
  const url = avatarUrl(user);
  if (url) return `<img class="avatar-img${big ? " big" : ""}" src="${url}" alt="" loading="lazy">`;
  return big
    ? `<div class="avatar big" aria-hidden="true">${esc(initials(user?.display_name))}</div>`
    : `<span class="avatar" aria-hidden="true">${esc(initials(user?.display_name))}</span>`;
}

function iconArt(course, size = 56) {
  if (course.has_icon) return `<img class="art" src="/media/${course.id}/icon" alt="" width="${size}" height="${size}" loading="lazy">`;
  const hue = [...course.id].reduce((a, c) => a + c.charCodeAt(0), 0) % 360;
  return `<div class="art art-fallback" style="--h:${hue};width:${size}px;height:${size}px" aria-hidden="true"><span>${esc(initials(course.title))}</span></div>`;
}

const ICONS = {
  home: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 10.5 12 3l9 7.5"/><path d="M5 9.5V21h5v-6h4v6h5V9.5"/></svg>`,
  library: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20V4H6.5A2.5 2.5 0 0 0 4 6.5v13Z"/><path d="M4 19.5A2.5 2.5 0 0 0 6.5 22H20v-5"/></svg>`,
  profile: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 3.6-6.5 8-6.5s8 2.5 8 6.5"/></svg>`,
  settings: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .34 1.87l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.7 1.7 0 0 0-1.87-.34 1.7 1.7 0 0 0-1 1.55V21a2 2 0 1 1-4 0v-.09a1.7 1.7 0 0 0-1-1.55 1.7 1.7 0 0 0-1.87.34l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.7 1.7 0 0 0 4.6 15a1.7 1.7 0 0 0-1.55-1H3a2 2 0 1 1 0-4h.09A1.7 1.7 0 0 0 4.6 9a1.7 1.7 0 0 0-.34-1.87l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.7 1.7 0 0 0 9 4.6a1.7 1.7 0 0 0 1-1.55V3a2 2 0 1 1 4 0v.09a1.7 1.7 0 0 0 1 1.55 1.7 1.7 0 0 0 1.87-.34l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.7 1.7 0 0 0-.34 1.87v.05a1.7 1.7 0 0 0 1.55 1H21a2 2 0 1 1 0 4h-.09a1.7 1.7 0 0 0-1.51 1Z"/></svg>`,
  admin: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 2 4 5.5v5.6c0 5 3.4 8.6 8 10.4 4.6-1.8 8-5.4 8-10.4V5.5L12 2Z"/><path d="m9 12 2 2 4-4.5"/></svg>`,
};

export function layout({ title, user, active = "", body, extraHead = "", extraScript = "" }) {
  const isAdmin = user?.role === "admin";
  // Sidebar lists ONLY routes that actually exist — never decorative items.
  const wsNav = [
    { id: "home", href: "/", icon: ICONS.home, label: "Workspace" },
    { id: "library", href: "/library", icon: ICONS.library, label: "Library" },
  ];
  const acctNav = [
    { id: "profile", href: "/profile", icon: ICONS.profile, label: "Profile" },
    { id: "settings", href: "/settings", icon: ICONS.settings, label: "Settings" },
    ...(isAdmin ? [{ id: "admin", href: "/admin", icon: ICONS.admin, label: "Admin" }] : []),
  ];
  const allNav = [...wsNav, ...acctNav];
  // Native title tooltips: visible on hover/focus in the collapsed icon rail,
  // no focus trap, navigation stays fully usable without hover.
  const navItem = (n) => `<li><a href="${n.href}" title="${n.label}" class="${active === n.id ? "on" : ""}"${active === n.id ? ` aria-current="page"` : ""}><span class="ni" aria-hidden="true">${n.icon}</span><span class="nl">${n.label}</span></a></li>`;
  return `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} · Axiom</title>
<meta name="description" content="Axiom — your calm, self-hosted learning workspace.">
<meta property="og:title" content="${esc(title)} · Axiom">
<link rel="icon" href="/img/favicon.svg" type="image/svg+xml">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600;700;800&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/css/app.css">${extraHead}</head>
<body data-user-tz="${esc(user?.timezone || "UTC")}">
<a class="skip" href="#main">Skip to content</a>
<div class="app">
${user ? `<aside class="appnav" id="appnav" aria-label="Primary">
<div class="appnav-h">
<a class="brand" href="/" aria-label="Axiom home" title="Axiom — Workspace"><span class="brand-mark" aria-hidden="true">◈</span><span class="brand-name">Axiom</span></a>
<button class="iconbtn appnav-collapse" id="appnavToggle" aria-label="Collapse sidebar" aria-expanded="true" aria-controls="appnav">⟨</button>
</div>
<p class="brand-path mono" aria-hidden="true">learn &gt; practice &gt; progress</p>
<nav aria-label="Workspace"><p class="nav-group mono">Workspace</p><ul>
${wsNav.map(navItem).join("")}
</ul></nav>
<nav aria-label="Account"><p class="nav-group mono">Account</p><ul>
${acctNav.map(navItem).join("")}
</ul></nav>
<div class="appnav-foot"><p class="side-quote">“Disciplined learning<br>builds freedom.”<span>— Axiom</span></p><p class="mono dim side-ver">axiom · self-hosted · v1.0</p></div>
</aside>` : ""}
<div class="appmain">
<header class="topbar"><div class="topbar-in">
${user ? `<div class="topbar-left"><button class="iconbtn only-mobile" id="navToggle" aria-label="Menu" aria-expanded="false">☰</button></div>
<form class="tsearch" action="/library" method="get" role="search">
<span class="ts-ic" aria-hidden="true"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.8-3.8"/></svg></span>
<input name="q" placeholder="Search courses, topics, or notes…" aria-label="Search courses, lessons, pages" autocomplete="off">
<kbd title="Focus search">Ctrl K</kbd>
</form>
<div class="top-actions">
<details class="acct">
<summary aria-label="Account menu">${avatarHtml(user)}<span class="acct-name">${esc(user.display_name.split(" ")[0] || user.username)}</span><span class="acct-chev" aria-hidden="true">▾</span></summary>
<div class="acct-menu">
<p class="mono dim acct-head">${esc(user.username)} · ${esc(user.role)}</p>
<a href="/profile">Profile</a>
<a href="/settings">Settings</a>
<form method="post" action="/logout"><button type="submit">Sign out</button></form>
</div>
</details>
</div>` : `<a class="brand" href="/" aria-label="Axiom home"><span class="brand-mark" aria-hidden="true">◈</span><span class="brand-name">Axiom</span></a>`}
</div>
${user ? `<nav class="mobilenav" id="mobileNav" aria-label="Mobile">${allNav.map((n) => `<a href="${n.href}">${n.label}</a>`).join("")}<form method="post" action="/logout"><button>Sign out</button></form></nav>` : ""}
</header>
<main id="main" class="main">${body}</main>
<footer class="foot"><span class="mono dim">axiom · v1.0 · self-hosted</span><span class="mono sys"><i aria-hidden="true"></i>All systems online</span></footer>
</div>
</div>
<div id="toasts" aria-live="polite"></div>
<script src="/js/app.js" defer></script><script type="module" src="/js/tip.js"></script>${extraScript}</body></html>`;
}

export function progressBar(pct, label = "") {
  const p = Math.max(0, Math.min(100, Math.round(pct)));
  return `<div class="pbar" role="progressbar" aria-valuenow="${p}" aria-valuemin="0" aria-valuemax="100" aria-label="${esc(label || "progress")}"><i style="width:${p}%"></i></div>`;
}

export function graphHtml(rows, bands, range = 52) {
  // Heatmap window: last N weeks, or "month" for days from the 1st of the
  // current month through today. Weekday + month labels are part of the same
  // grid so columns stay aligned at any size.
  const today = new Date();
  let totalDays, rangeLabel, monthMode = false;
  if (range === "month") {
    const first = Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), 1);
    totalDays = Math.max(7, Math.round((today.getTime() - first) / 864e5) + 1);
    rangeLabel = "this month";
    monthMode = true;
  } else {
    const weeks = parseInt(range) || 52;
    totalDays = Math.max(7, weeks * 7);
    rangeLabel = `last ${weeks} weeks`;
  }
  const byDay = new Map(rows.map((r) => [r.day, (r.video_secs || 0) + (r.reading_secs || 0)]));
  const comp = new Map(rows.map((r) => [r.day, r.completions || 0]));
  const vids = new Map(rows.map((r) => [r.day, r.video_secs || 0]));
  const reads = new Map(rows.map((r) => [r.day, r.reading_secs || 0]));
  const days = [];
  for (let i = totalDays - 1; i >= 0; i--) {
    const d = new Date(today.getTime() - i * 864e5);
    days.push(d.toISOString().slice(0, 10));
  }
  // align to weeks starting Sunday
  const startPad = new Date(days[0] + "T12:00:00Z").getUTCDay();
  const cells = [];
  for (let i = 0; i < startPad; i++) cells.push(null);
  for (const d of days) cells.push(d);
  while (cells.length % 7) cells.push(null);
  const cols = Math.ceil(cells.length / 7);
  const WD = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  // Month labels: only when at least 5 week-columns apart. Short month names
  // are ~40px wide, so anything closer ("Sep Oct") collides into one blob —
  // especially at small cell sizes where 3 columns ≈ 40px is borderline.
  let months = "";
  let prevM = "";
  let prevC = -99;
  for (let c = 0; c < cols; c++) {
    const first = cells.slice(c * 7, c * 7 + 7).find(Boolean);
    const m = first ? new Date(first + "T12:00:00Z").toLocaleDateString(undefined, { month: "short" }) : "";
    if (m && m !== prevM && c - prevC >= 5) { months += `<span style="grid-column:${c + 2}">${esc(m)}</span>`; prevM = m; prevC = c; }
  }
  let html = `<div class="graph${monthMode ? " graph-month" : ""}${!monthMode && cols <= 15 ? " graph-short" : ""}${!monthMode && cols > 30 ? " graph-long" : ""}" role="img" aria-label="Learning activity graph, ${rangeLabel}"><div class="graph-months" aria-hidden="true">${months}</div><div class="graph-grid">`;
  WD.forEach((w, i) => { html += `<span class="gday" style="grid-row:${i + 1}">${w}</span>`; });
  for (const d of cells) {
    if (!d) { html += `<span class="cell empty"></span>`; continue; }
    const tot = byDay.get(d) || 0;
    const lv = levelFor(tot, bands);
    const dt = new Date(d + "T12:00:00Z").toLocaleDateString(undefined, { month: "long", day: "numeric", year: "numeric" });
    const tipLines = [`${fmtDur(tot)} learned`, `${fmtDur(vids.get(d) || 0)} video · ${fmtDur(reads.get(d) || 0)} reading`];
    if (comp.get(d)) tipLines.push(`${comp.get(d)} completed`);
    const tip = `${dt}\n${tipLines.join("\n")}`;
    html += `<span class="cell lv${lv}" data-tip="${esc(tip)}" tabindex="0"></span>`;
  }
  html += `</div><div class="graph-legend mono"><span>Less</span><span class="cell lv0"></span><span class="cell lv1"></span><span class="cell lv2"></span><span class="cell lv3"></span><span class="cell lv4"></span><span>More</span></div></div>`;
  return html;
}

export function emptyState(title, hint, cta = "") {
  return `<div class="empty"><div class="empty-mark" aria-hidden="true">◇</div><h3>${esc(title)}</h3><p>${esc(hint)}</p>${cta}</div>`;
}

export { iconArt };
