// HTML view layer — server-rendered MPA with shared design system.
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

function iconArt(course, size = 56) {
  if (course.has_icon) return `<img class="art" src="/media/${course.id}/icon" alt="" width="${size}" height="${size}" loading="lazy">`;
  const hue = [...course.id].reduce((a, c) => a + c.charCodeAt(0), 0) % 360;
  return `<div class="art art-fallback" style="--h:${hue};width:${size}px;height:${size}px" aria-hidden="true"><span>${esc(initials(course.title))}</span></div>`;
}

export function layout({ title, user, active = "", body, extraHead = "", extraScript = "" }) {
  const isAdmin = user?.role === "admin";
  // Sidebar lists ONLY routes that actually exist — never decorative items.
  const nav = [
    { id: "home", href: "/", icon: "◈", label: "Workspace" },
    { id: "library", href: "/library", icon: "▤", label: "Library" },
    { id: "profile", href: "/profile", icon: "◉", label: "Profile" },
    { id: "settings", href: "/settings", icon: "⚙", label: "Settings" },
    ...(isAdmin ? [{ id: "admin", href: "/admin", icon: "✦", label: "Admin" }] : []),
  ];
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
<a class="brand" href="/" aria-label="Axiom home"><span class="brand-mark" aria-hidden="true">◈</span><span class="brand-name">Axiom</span><span class="brand-sub">learn</span></a>
<button class="iconbtn" id="appnavToggle" aria-label="Collapse sidebar" aria-expanded="true" aria-controls="appnav">⟨</button>
</div>
<nav aria-label="Sections"><ul>
${nav.map((n) => `<li><a href="${n.href}" class="${active === n.id ? "on" : ""}"${active === n.id ? ` aria-current="page"` : ""}><span class="ni" aria-hidden="true">${n.icon}</span>${n.label}</a></li>`).join("")}
</ul></nav>
<div class="appnav-foot mono dim" aria-hidden="true">axiom · self-hosted · v1.0</div>
</aside>` : ""}
<div class="appmain">
<header class="topbar"><div class="topbar-in">
${user ? `<div class="topbar-left"><button class="iconbtn only-mobile" id="navToggle" aria-label="Menu" aria-expanded="false">☰</button><button class="iconbtn appnav-expand" id="appnavExpand" aria-label="Expand sidebar" aria-controls="appnav">⟩</button></div>
<form class="tsearch" action="/library" method="get" role="search">
<span class="ts-ic" aria-hidden="true">⌕</span>
<input name="q" placeholder="Search courses, lessons, pages…" aria-label="Search courses, lessons, pages" autocomplete="off">
<kbd title="Focus search">Ctrl K</kbd>
</form>
<div class="top-actions">
<details class="acct">
<summary aria-label="Account menu"><span class="avatar" aria-hidden="true">${esc(initials(user.display_name))}</span></summary>
<div class="acct-menu">
<a href="/profile">Profile</a>
<a href="/settings">Settings</a>
<form method="post" action="/logout"><button type="submit">Sign out</button></form>
</div>
</details>
</div>` : `<a class="brand" href="/" aria-label="Axiom home"><span class="brand-mark" aria-hidden="true">◈</span><span class="brand-name">Axiom</span><span class="brand-sub">learn</span></a>`}
</div>
${user ? `<nav class="mobilenav" id="mobileNav" aria-label="Mobile">${nav.map((n) => `<a href="${n.href}">${n.label}</a>`).join("")}<form method="post" action="/logout"><button>Sign out</button></form></nav>` : ""}
</header>
<main id="main" class="main">${body}</main>
<footer class="foot"><span class="mono dim">axiom · self-hosted · v1.0</span></footer>
</div>
</div>
<div id="toasts" aria-live="polite"></div>
<script src="/js/app.js" defer></script>${extraScript}</body></html>`;
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
  let html = `<div class="graph${monthMode ? " graph-month" : ""}" role="img" aria-label="Learning activity graph, ${rangeLabel}"><div class="graph-months" aria-hidden="true">${months}</div><div class="graph-grid">`;
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
  html += `</div><div class="graph-legend"><span>Less</span><span class="cell lv0"></span><span class="cell lv1"></span><span class="cell lv2"></span><span class="cell lv3"></span><span class="cell lv4"></span><span>More</span></div></div>`;
  return html;
}

export function emptyState(title, hint, cta = "") {
  return `<div class="empty"><div class="empty-mark" aria-hidden="true">◇</div><h3>${esc(title)}</h3><p>${esc(hint)}</p>${cta}</div>`;
}

export { iconArt };
