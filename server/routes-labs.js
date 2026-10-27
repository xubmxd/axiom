// Cyber Range routes: lab catalog + lab workspace pages, and the lab API.
//
// Pages (mounted at /):  GET /labs, GET /labs/:slug
// API  (mounted at /api): /api/labs… (see below), /api/admin/lab-instances…
//
// Auth: all lab routes require an Axiom session (existing system — no new
// login). Users may only control their own instances; admin-only ops are
// explicitly gated. The browser is never trusted: every state change and
// every submission is validated server-side, and runtime secrets
// (host endpoints, container refs, expected hashes) never leave the server
// except host-loopback connection details scoped to the instance owner.
import { Router } from "express";
import fs from "node:fs";
import { get } from "./db.js";
import { layout, esc, emptyState, labCourseArt } from "./views.js";
import { ah } from "./wrap.js";
import { log } from "./log.js";
import * as svc from "./labs/service.js";
import { selectProvider, provisionInstance, destroyInstance, runTerminalCommand, nmapTopology, isScannerConsoleLab } from "./labs/orchestrator.js";
import { labDomain } from "./labs/whois-data.js";
import { SMB_SLUG } from "./labs/smb-range.js";
import { SMTP_SLUG } from "./labs/smtp-target.js";
import { SNMP_SLUG } from "./labs/snmp-target.js";
import { vpnStatus, ensureVpnClient, clientConfFor, regenerateVpnClient, revokeVpnClient } from "./labs/vpn.js";

export const labPages = Router();
export const labApi = Router();

// ---------- helpers ----------
function needAuthPage(req, res, next) {
  if (!req.user) return res.redirect("/login?next=" + encodeURIComponent(req.originalUrl));
  next();
}
function needAuthJson(req, res, next) {
  if (!req.user) return res.status(401).json({ error: "Sign in required." });
  next();
}
function needAdminJson(req, res, next) {
  if (!req.user) return res.status(401).json({ error: "Sign in required." });
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin only." });
  next();
}

async function resolveLab(param) {
  return (await svc.getLab("id", param)) || (await svc.getLab("slug", param));
}

function labTags(lab) {
  try { const t = JSON.parse(lab.tags || "[]"); return Array.isArray(t) ? t.slice(0, 6) : []; } catch { return []; }
}

function readInstructions(lab) {
  try {
    const def = JSON.parse(fs.readFileSync(lab.definition_path, "utf8"));
    return def.instructions || { objective: [], commands: [], learn: [] };
  } catch { return { objective: [], commands: [], learn: [] }; }
}

function readDefExtra(lab) {  try {
    const def = JSON.parse(fs.readFileSync(lab.definition_path, "utf8"));
    const course = def.course && typeof def.course === "object" ? def.course : {};
    const module = def.module && typeof def.module === "object" ? def.module : {};
    return {
      courseSlug: course.slug || def.courseSlug || "",
      courseTitle: course.title || def.courseTitle || "",
      moduleName: module.title || def.moduleName || "",
      sectionName: def.sectionTitle || def.sectionName || "",
      machineName: def.machineName || "",
    };
  } catch { return { courseSlug: "", courseTitle: "", moduleName: "", sectionName: "", machineName: "" }; }
}

// Per-lab external-research content for OSINT exercises. Definitions may
// carry a `research` block (intro/links/workflow/fallback/tools); labs
// without one fall back to the Google-Hacking wording so existing labs
// render byte-identically. Only https links are honored.
function readDefResearch(lab) {
  const fallback = {
    intro: "This exercise uses the live public web — the same surface the original investigation used. Each link opens in a new browser tab; nothing is embedded here. Perform the searches yourself, then return to Axiom to submit what you find.",
    links: [
      { label: "Open Google Search ↗", short: "Open Google ↗", url: "https://www.google.com", primary: true },
      { label: "Open MegaCorp One ↗", short: "Open MegaCorp One ↗", url: "https://www.megacorpone.com" },
      { label: "Open MegaCorp One GitHub ↗", short: "Open MegaCorp One GitHub ↗", url: "https://github.com/megacorpone/megacorpone.com" },
    ],
    workflow: "Constrain Google to the target domain with <code class=\"mono\">site:megacorpone.com</code>, refine with the role title and <code class=\"mono\">intext:</code>, and follow the trail to the company's public contact page. For the third objective, pivot to social-media and general web search for people connected to MegaCorp One.",
    tools: "Google · Public web · Social-media search",
    note: "No target IP, port, or container exists for this exercise. If the live site is unreachable, the GitHub link above is the documented public-mirror fallback.",
    fallbackNote: "If the live company site is unreachable, use the public mirror/source above (MegaCorp One GitHub) — it is the same public material, clearly identified as a fallback, not a substitute dataset.",
  };
  try {
    const def = JSON.parse(fs.readFileSync(lab.definition_path, "utf8"));
    const r = def.research && typeof def.research === "object" ? def.research : null;
    if (!r) return fallback;
    const links = (Array.isArray(r.links) ? r.links : [])
      .filter((l) => l && typeof l.url === "string" && /^https:\/\/[^"'\s<>]+$/.test(l.url) && typeof l.label === "string" && l.label.trim())
      .slice(0, 4)
      .map((l) => ({ label: l.label.trim().slice(0, 60), short: String(l.short || l.label).trim().slice(0, 60), url: l.url, primary: !!l.primary }));
    if (!links.length) return fallback;
    const text = (v, d) => (typeof v === "string" && v.trim() ? v.trim().slice(0, 1200) : d);
    return {
      intro: text(r.intro, fallback.intro),
      links,
      workflow: text(r.workflow, fallback.workflow),
      tools: text(r.tools, fallback.tools),
      note: text(r.note, fallback.note),
      fallbackNote: text(r.fallback, fallback.fallbackNote),
    };
  } catch { return fallback; }
}

function researchLinksHtml(links, style) {
  return links.map((l, i) =>
    `<a class="btn${l.primary || (style === "conn" && i === 0) ? " primary" : ""}" href="${esc(l.url)}" target="_blank" rel="noopener">${esc(style === "conn" ? (l.short || l.label) : l.label)}</a>`
  ).join("");
}

// Owner-scoped instance view. hostEndpoint is loopback-only connection info
// for the owner (powers the Connection tab + smoke tests); container refs
// and internal errors never leave the server.
function pubInstance(inst) {
  if (!inst) return null;
  return {
    id: inst.id, status: inst.status,
    targetIp: inst.target_ip || null, targetPort: inst.target_port || 43,
    networkCidr: inst.network_cidr || null,
    hostEndpoint: inst.host_endpoint || null,
    provider: inst.provider,
    startedAt: inst.started_at || null,
    resetCount: inst.reset_count || 0,
    error: inst.status === "failed" ? "Provisioning failed. Try starting the lab again." : null,
  };
}

function statusPill(status) {
  const map = { running: "reading", provisioning: "mixed", resetting: "mixed", stopping: "mixed", failed: "video", stopped: "" };
  const label = { running: "Running", provisioning: "Provisioning", resetting: "Resetting", stopping: "Stopping", failed: "Failed", stopped: "Stopped" }[status] || status;
  return `<span class="pill ${map[status] ?? ""}">${label}</span>`;
}

// Public target listing: deployment internals (service ports, target
// metadata, image references) never reach the browser. Names, hostnames,
// types, and OS are presentation data.
function pubTargets(rows) {
  return (rows || []).map((t) => ({
    id: t.id, name: t.name, hostname: t.hostname,
    targetType: t.target_type, os: t.os, networkRole: t.network_role,
  }));
}

// Student VPN pack panel (Connection tab). Server-rendered state, live
// actions via lab.js. Never embeds keys — the pack downloads as a file.
function vpnPanel(vpn, domain, targetIp, username, kaliCmd) {
  if (!vpn?.enabled) {
    return `<h3>From your own Kali (VPN)</h3>
      <p class="dim small">Student VPN is not enabled on this server. Use the lab terminal above — it reaches the same target over the isolated lab network.</p>`;
  }
  const file = `axiom-${String(username || "student").toLowerCase().replace(/[^a-z0-9_-]/g, "_").slice(0, 32) || "student"}.conf`;
  const kali = kaliCmd || `whois ${domain} -h ${targetIp}`;
  const copyBtn = (v) => `<button class="iconbtn xs" data-copy="${esc(v)}" aria-label="Copy command">⧉</button>`;
  return `<h3>From your own Kali (VPN)</h3>
    <div data-vpn>
      <p class="dim small">Join the student VPN from your own Kali VM, then query the target IP directly — the same isolated target, your own terminal. The VPN reaches only YOUR running targets.</p>
      <p class="mono small" data-vpn-line>${vpn.configured ? `Pack ready · your VPN IP ${esc(vpn.clientIp || "")}${vpn.gateway ? "" : " · gateway offline — retry in a minute"}` : "No pack yet — downloading creates your personal one."}</p>
      <div class="lrow">
        <button class="btn xs" data-vpn-download>Download VPN pack</button>
        ${vpn.configured ? `<button class="btn xs" data-vpn-regenerate>Regenerate</button><button class="btn xs" data-vpn-status>Refresh status</button>` : ""}
      </div>
      <div class="cmdlist">
        <div class="cmdrow"><code class="mono">sudo apt install wireguard -y</code>${copyBtn("sudo apt install wireguard -y")}</div>
        <div class="cmdrow"><code class="mono">sudo wg-quick up ./${esc(file)}</code>${copyBtn(`sudo wg-quick up ./${file}`)}</div>
        <div class="cmdrow"><code class="mono">${esc(kali)}</code>${copyBtn(kali)}</div>
        <div class="cmdrow"><code class="mono">sudo wg-quick down ./${esc(file)}</code>${copyBtn(`sudo wg-quick down ./${file}`)}</div>
      </div>
    </div>`;
}

// ---------- pages ----------
// Catalog: training paths only. Labs live under their course — this page
// never lists individual labs, no matter how many exist.
labPages.get("/labs", needAuthPage, ah(async (req, res) => {
  const u = req.user;
  const courses = await svc.listLabCourses();
  const enriched = [];
  for (const course of courses) {
    const [modules, progress] = await Promise.all([
      svc.courseStructure(u.id, course.id),
      svc.courseProgress(u.id, course.id),
    ]);
    if (!progress.total) continue; // unpopulated paths stay hidden
    enriched.push({ course, moduleCount: modules.length, progress });
  }
  res.send(layout({
    title: "Cyber Range", user: u, active: "labs",
    body: `<div class="wrap range-landing">
      <header class="range-hero">
        <p class="eyebrow" style="font-size:12px">cyber range</p>
        <h1>Practical cybersecurity training environments.</h1>
        <p class="range-lede">Choose a training path. Isolated hands-on labs — start a target, interrogate it like a real engagement, submit what you find.</p>
        <p class="range-meta mono">isolated networks · real targets · flag validation</p>
      </header>
      <div class="range-grid">
        <section class="range-paths" aria-label="Training paths">
          <div class="sech"><h2>Training paths</h2><span class="mono dim small">${enriched.length} available</span></div>
          ${enriched.length ? `<div class="courselist">${enriched.map(({ course, moduleCount, progress }) => `
            <a class="ccard coursecard" href="/labs/${esc(course.slug)}">
              <div class="ccard-art">${labCourseArt(course, 56)}</div>
              <div class="ccard-b">
                <div class="ccard-t"><span class="mono ccard-code">training path</span><span class="mono dim small">${progress.completed}/${progress.total} completed</span></div>
                <h3>${esc(course.title)}</h3>
                ${course.subtitle ? `<p class="dim small lab-desc">${esc(course.subtitle)}</p>` : ""}
                <div class="pbar" role="progressbar" aria-valuenow="${progress.pct}" aria-valuemin="0" aria-valuemax="100" aria-label="${esc(course.title)} progress"><i style="width:${progress.pct}%"></i></div>
                <p class="mono ccard-meta"><span>${moduleCount} module${moduleCount === 1 ? "" : "s"} · ${progress.total} lab${progress.total === 1 ? "" : "s"}</span><span class="link">View labs →</span></p>
              </div></a>`).join("")}</div>`
            : emptyState("No training paths yet", "Labs appear here once definitions are registered.", u.role === "admin" ? `<a class="btn primary" href="/admin">Open Admin</a>` : "")}
        </section>
        <aside class="range-how" aria-label="How the range works">
          <p class="eyebrow" style="font-size:12px">How it works</p>
          <div class="range-step"><span class="mono">01</span><div><h3>Start a target</h3><p>Launch an isolated lab network, scoped to your account and separate from every other student.</p></div></div>
          <div class="range-step"><span class="mono">02</span><div><h3>Interrogate it</h3><p>Use the built-in terminal to enumerate, exploit, and capture evidence. No host shell, no shared state.</p></div></div>
          <div class="range-step"><span class="mono">03</span><div><h3>Submit the flag</h3><p>Prove the finding. A correct flag completes the lab and feeds your range progress.</p></div></div>
        </aside>
      </div>
    </div>`,
  }));
}));

// Course range page: modules → sections → labs, all data-driven.
labPages.get("/labs/:courseSlug", needAuthPage, ah(async (req, res) => {
  const u = req.user;
  const course = await svc.getLabCourse(req.params.courseSlug);
  if (!course) {
    // Legacy single-segment lab URL: redirect to the canonical course URL.
    const lab = await resolveLab(req.params.courseSlug);
    if (lab && lab.status === "active") {
      const owner = lab.course_id ? await get(`SELECT slug FROM lab_courses WHERE id=?`, [lab.course_id]) : null;
      if (owner?.slug) return res.redirect(302, `/labs/${owner.slug}/${lab.slug}`);
      return res.status(404).send(layout({ title: "Lab unavailable", user: u, active: "labs", body: `<div class="wrap">${emptyState("Lab unavailable", "This lab is not assigned to a training path yet.")}</div>` }));
    }
    return res.status(404).send(layout({ title: "Not found", user: u, active: "labs", body: `<div class="wrap">${emptyState("Training path not found", "This Cyber Range course does not exist.")}</div>` }));
  }
  const [modules, progress] = await Promise.all([
    svc.courseStructure(u.id, course.id),
    svc.courseProgress(u.id, course.id),
  ]);
  const defCache = new Map();
  const machineOf = (lab) => {
    if (!defCache.has(lab.id)) defCache.set(lab.id, readDefExtra(lab));
    return defCache.get(lab.id).machineName || "";
  };
  const labRow = ({ lab, state, progress: lp, running }) => {
    const pill = state === "completed" ? `<span class="pill reading">✓ Completed</span>`
      : state === "running" ? `<span class="pill reading">● Running</span>`
      : state === "in-progress" ? `<span class="pill mixed">In progress</span>`
      : `<span class="pill">Not started</span>`;
    const machine = machineOf(lab);
    return `<a class="labrow" href="/labs/${esc(course.slug)}/${esc(lab.slug)}">
      <span class="labrow-t"><b>Lab ${esc(String(lab.lab_number))}${machine ? ` — ${esc(machine)}` : ""}</b>
      <span class="dim small">${esc(lab.difficulty)} · ${lp.done}/${lp.total} steps</span></span>${pill}</a>`;
  };
  res.send(layout({
    title: course.title, user: u, active: "labs",
    body: `<div class="wrap">
      <nav class="crumbs mono" aria-label="Breadcrumb"><a href="/labs">cyber range</a> / <span>${esc(course.title)}</span></nav>
      <p class="eyebrow mono">training path</p>
      <h1>${esc(course.title)}</h1>
      ${course.subtitle ? `<p class="dim">${esc(course.subtitle)}</p>` : ""}
      <section class="card course-progress" aria-label="Overall progress">
        <div class="sech"><h2>Overall progress</h2><span class="mono dim small">${progress.completed} / ${progress.total} labs completed · ${progress.pct}%</span></div>
        <div class="pbar" role="progressbar" aria-valuenow="${progress.pct}" aria-valuemin="0" aria-valuemax="100" aria-label="Overall course progress"><i style="width:${progress.pct}%"></i></div>
        <p class="mono dim small">${progress.completed} completed · ${progress.inProgress} in progress · ${progress.notStarted} not started</p>
      </section>
      ${modules.length ? modules.map((m) => `
        <section class="rmod" aria-label="Module ${m.number}">
          <header class="rmod-head">
            <div><p class="eyebrow mono">Module ${esc(String(m.number))}</p><h2>${esc(m.title || `Module ${m.number}`)}</h2></div>
            <span class="mono dim small">${m.completed} / ${m.total} completed</span>
          </header>
          <div class="pbar thin" role="progressbar" aria-valuenow="${m.pct}" aria-valuemin="0" aria-valuemax="100" aria-label="Module ${esc(String(m.number))} progress"><i style="width:${m.pct}%"></i></div>
          <div class="rmod-body">
          ${m.sections.map((s) => {
            const sDone = s.labs.filter((l) => l.progress.complete).length;
            return `
            <div class="rex">
              <div class="rex-head"><h3>${s.section ? `<span class="mono dim">${esc(s.section)}</span> ` : ""}${esc(s.title)}</h3><span class="mono dim small">${s.labs.length} exercise${s.labs.length === 1 ? "" : "s"} · ${sDone}/${s.labs.length} done</span></div>
              <div class="labrows">${s.labs.map(labRow).join("")}</div>
            </div>`; }).join("")}
          </div>
        </section>`).join("")
        : emptyState("No practical labs have been added yet.", "Check back soon — new exercises appear here automatically.")}
    </div>`,
  }));
}));

// Lab workspace: instructions/hints/connection/notes/more tabs + persistent
// status rail (lifecycle, target info, submissions, progress, terminal).
// Canonical path carries the course; the engine itself stays course-agnostic.
labPages.get("/labs/:courseSlug/:labSlug", needAuthPage, ah(async (req, res) => {
  const u = req.user;
  const course = await svc.getLabCourse(req.params.courseSlug);
  const lab = course ? await get(`SELECT * FROM labs WHERE course_id=? AND slug=?`, [course.id, req.params.labSlug]) : null;
  if (!course || !lab || lab.status !== "active") {
    return res.status(404).send(layout({ title: "Lab unavailable", user: u, active: "labs", body: `<div class="wrap">${emptyState("Lab unavailable", "This lab may have been moved or removed.")}</div>` }));
  }
  const [targets, objectives, progress, instance, notes, hints, modProg, vpn] = await Promise.all([
    svc.labTargets(lab.id), svc.labObjectives(lab.id), svc.labProgress(u.id, lab.id),
    svc.activeInstance(u.id, lab.id), svc.getNotes(u.id, lab.id), svc.hintsFor(u.id, lab.id),
    svc.moduleProgress(u.id, course.id, lab.module_number),
    vpnStatus(u.id).catch(() => ({ enabled: false, gateway: false, configured: false })),
  ]);
  const extra = readDefExtra(lab);
  const instr = readInstructions(lab);
  const inst = pubInstance(instance);
  const primary = targets[0] || {};
  // Each lab queries its own domain (VM #1: megacorpone.com,
  // VM #2: offensive-security.com). Falls back to VM #1's domain.
  const domain = labDomain(lab.slug);
  // OSINT exercises (e.g. 6.2.2 Google Hacking) have no network target:
  // research happens on the live public web via the Research tab links.
  const isOsint = lab.environment_type === "osint";
  const research = isOsint ? readDefResearch(lab) : null;
  // Theory/knowledge exercises (7.1.x) have no network target and no tool
  // output: the Connection tab says so plainly instead of showing a fake
  // target, and no terminal card is rendered (there is nothing to run).
  const isTheory = lab.environment_type === "theory";
  // Scanner labs (7.2.x) run the Axiom vulnerability scanner from the web
  // console: no attacker shell, no terminal card. 7.2.1 is theory-style and
  // 7.2.2 is the console without a range; the rest own a target range.
  const isScanner = lab.environment_type === "scanner";
  const scannerTargets = isScanner ? targets.filter((t) => t.target_type === "scanner-target") : [];
  const scannerBase = isScanner && inst?.networkCidr ? String(inst.networkCidr).split(".").slice(0, 3).join(".") : "";
  const scannerBoxes = scannerTargets.map((t) => {
    let suffix = 0;
    try { suffix = parseInt(JSON.parse(t.metadata_json || "{}").ipSuffix, 10) || 0; } catch {}
    return { name: t.name, ip: suffix && scannerBase ? `${scannerBase}.${suffix}` : "" };
  });
  let scannerSshPassword = "";
  if (isScanner && inst && lab.slug === "m7-7-2-5-auth-scan") {
    try {
      const row = await svc.getRuntimeFlag(inst.id, "ssh-password");
      scannerSshPassword = row?.flag_value || "";
    } catch { scannerSshPassword = ""; }
  }
  // DNS labs (6.3.1) render target-connection UI for the lab DNS service
  // instead of the WHOIS layout. WHOIS rendering below is unchanged.
  const isDns = ((targets[0] || {}).target_type || "") === "dns-server";
  // Nmap range labs (6.3.3) render a multi-target connection table.
  // Services and flags are NEVER listed: discovering them is the exercise.
  const isNmap = targets.some((t) => (t.target_type || "") === "attacker");
  const nmapTopo = isNmap && inst?.networkCidr ? await nmapTopology(lab.id, inst.networkCidr).catch(() => null) : null;
  // Scan labs (6.3.2) render target-connection UI for the scan target.
  // Open ports are NEVER listed: discovering them is the exercise.
  const isScan = ((targets[0] || {}).target_type || "") === "scan-target";
  const targetIp = inst?.targetIp || "<TARGET-IP>";
  const withIp = (s) => esc(String(s).replaceAll("<TARGET-IP>", targetIp).replaceAll("<target-ip>", targetIp));

  const objSteps = progress.objectives.map((o) => `
    <li class="check-item${o.completed ? " done" : ""}" data-objective="${esc(o.key)}">
      <span class="check-box" aria-hidden="true">${o.completed ? "✓" : "○"}</span>
      <span>${esc(o.title)}</span>
    </li>`).join("");

  res.send(layout({
    title: lab.title, user: u, active: "labs",
    extraScript: `<script src="/js/lab.js" defer></script>`,
    body: `
  <div class="wrap labwrap" data-lab="${esc(lab.id)}" data-slug="${esc(lab.slug)}" data-env="${esc(lab.environment_type)}"
       data-status="${esc(inst?.status || "stopped")}" data-started-at="${esc(inst?.startedAt || "")}"
       data-target-ip="${esc(inst?.targetIp || "")}">
    <nav class="crumbs mono" aria-label="Breadcrumb"><a href="/labs">cyber range</a> / <a href="/labs/${esc(course.slug)}">${esc(course.title)}</a> / <a href="/labs/${esc(course.slug)}">Module ${esc(String(lab.module_number))}</a> / <span>${esc(lab.section_number)} ${esc(extra.sectionName || lab.section_name)}</span> / <span>Lab ${esc(String(lab.lab_number))}</span></nav>
    <section class="labhead">
      <div>
        <h1>${esc(lab.title)}</h1>
        <p class="dim lab-sub">Lab ${esc(String(lab.lab_number))} — ${esc(extra.machineName || primary.name || "Target")} · ${esc(primary.os || "Linux")}${primary.target_type ? ` (${esc(primary.target_type)})` : ""}</p>
        <p class="dim lab-desc">${esc(lab.description)}</p>
        <div class="lab-tags" aria-label="Lab topics">${labTags(lab).map((t) => `<span class="chip xs">${esc(t)}</span>`).join("")}<span class="chip xs diff">${esc(lab.difficulty)}</span></div>
      </div>
    </section>

    <div class="labgrid">
      <div class="labmain">
        <div class="tabs" role="tablist" aria-label="Lab workspace">
          ${(isOsint ? ["instructions", "hints", "research", "connection", "notes", "more"] : isScanner ? ["instructions", "hints", "scanner", "connection", "notes", "more"] : ["instructions", "hints", "connection", "notes", "more"]).map((t, i) => `<button role="tab" id="tab-${t}" aria-controls="panel-${t}" aria-selected="${i === 0 ? "true" : "false"}" tabindex="${i === 0 ? "0" : "-1"}" data-tab="${t}">${t[0].toUpperCase() + t.slice(1)}${t === "hints" ? ` (${hints.length})` : ""}</button>`).join("")}
        </div>

        <section class="card tabpanel" role="tabpanel" id="panel-instructions" aria-labelledby="tab-instructions" tabindex="0">
          <h2>Lab Instructions</h2>
          <h3>Objective</h3>
          <ol class="objlist">${(instr.objective || []).map((s) => `<li>${withIp(s)}</li>`).join("") || "<li>Follow the objectives in the progress panel.</li>"}</ol>
          ${(instr.commands?.length) ? `<h3>Helpful Commands</h3><div class="cmdlist">${instr.commands.map((c) => `<div class="cmdrow"><code class="mono">${withIp(c)}</code><button class="iconbtn xs" data-copy="${withIp(c)}" aria-label="Copy command">⧉</button></div>`).join("")}</div>` : ""}
          ${(instr.learn?.length) ? `<h3>What You'll Learn</h3><ul class="learnlist">${instr.learn.map((s) => `<li>${esc(s)}</li>`).join("")}</ul>` : ""}
          <h3>Questions</h3>
          <ol class="objlist">${progress.objectives.map((o) => `<li><b>${esc(o.title)}</b>${o.description ? `<br><span>${esc(o.description)}</span>` : ""}</li>`).join("")}</ol>
        </section>

        <section class="card tabpanel" role="tabpanel" id="panel-hints" aria-labelledby="tab-hints" tabindex="0" hidden>
          <h2>Hints</h2>
          ${hints.length ? `<ol class="hintlist">${hints.map((h) => `<li><div class="sech"><b>${esc(h.title)}</b>${h.revealed ? "" : `<button class="btn xs" data-reveal-hint="${esc(h.id)}">Reveal</button>`}</div>${h.revealed ? `<p>${esc(h.body)}</p>` : `<p class="dim small">Hidden until revealed. Using hints never blocks completion.</p>`}</li>`).join("")}</ol>`
            : `<p class="dim">No hints configured for this lab. Work the objective — the target has everything you need.</p>`}
        </section>

        ${isOsint ? `
        <section class="card tabpanel" role="tabpanel" id="panel-research" aria-labelledby="tab-research" tabindex="0" hidden>
          <h2>External Research</h2>
          <p class="dim small">${esc(research.intro)}</p>
          <div class="lrow">
            ${researchLinksHtml(research.links, "research")}
          </div>
          <h3>Suggested workflow</h3>
          <p class="dim small">${research.workflow}</p>
          <h3>Fallback</h3>
          <p class="dim small">${esc(research.fallbackNote)}</p>
        </section>` : ""}

        ${isScanner ? `
        <section class="card tabpanel" role="tabpanel" id="panel-scanner" aria-labelledby="tab-scanner" tabindex="0" hidden>
          <h2>Vulnerability Scanner</h2>
          <p class="dim small">The Axiom scanner (a purpose-built lab scanner, not Nessus). Configure scans below; results, findings, and sitemap pages appear here as scans complete.</p>
          <div data-scanner="${esc(lab.id)}">
            <h3>Scan templates</h3>
            <div data-scanner-templates><p class="dim small">Start the lab to load templates.</p></div>
            <h3>New scan</h3>
            <form data-scanner-new class="form">
              <label>Scan name<input name="name" value="Basic Network Scan" autocomplete="off" spellcheck="false"></label>
              <label>Template<select name="template"><option value="basic">Basic Network Scan</option><option value="discovery">Discovery Scan</option></select></label>
              <fieldset><legend>Targets</legend><div data-scanner-targets><p class="dim small">Start the lab to list targets.</p></div></fieldset>
              <label>Ports (e.g. 80, 8080, 9999, 1-1000)<input name="ports" value="80" autocomplete="off" spellcheck="false"></label>
              <label>SSH username (authenticated scans)<input name="authUser" value="scanner" autocomplete="off" spellcheck="false"></label>
              <label>SSH password (authenticated scans)<input name="authPassword" type="password" autocomplete="off" spellcheck="false" placeholder="from the Connection tab"></label>
              <label>Assessment<select name="assessment"><option value="default">Default</option><option value="custom">Custom</option></select></label>
              <label class="check"><input type="checkbox" name="webapp"> Scan web applications (Custom assessment)</label>
              <label>Plugin filter (name or family)<input name="pluginFilter" autocomplete="off" spellcheck="false" placeholder="optional"></label>
              <button class="btn primary" type="submit">Launch scan</button>
              <p class="mono small" data-scanner-msg role="status"></p>
            </form>
            <h3>Scans</h3>
            <div data-scanner-list><p class="dim small">No scans yet.</p></div>
            <h3>Findings</h3>
            <div data-scanner-findings><p class="dim small">Run a scan to see findings.</p></div>
            <h3>Web application sitemap</h3>
            <div data-scanner-sitemap><p class="dim small">Web-application scans list discovered pages here.</p></div>
            <h3>Settings</h3>
            <div data-scanner-settings><p class="dim small">Start the lab to load settings.</p></div>
          </div>
        </section>` : ""}

        <section class="card tabpanel" role="tabpanel" id="panel-connection" aria-labelledby="tab-connection" tabindex="0" hidden>
          <h2>Connection</h2>
          ${isTheory ? `
          <div class="conn-grid" data-conn>
            <div><p class="mono dim small">ENVIRONMENT</p><p><b>Knowledge exercise</b></p></div>
            <div><p class="mono dim small">TARGET</p><p>None — this exercise needs no VM</p></div>
            <div><p class="mono dim small">NETWORK</p><p>None — there is nothing to scan</p></div>
            <div><p class="mono dim small">ACCESS</p><p>Instructions tab (read, reason, submit)</p></div>
          </div>
          <p class="dim small">Answer from the scenarios and the course material. If the environment ever misbehaves, use Reset Lab in the status panel — it re-activates this workspace.</p>
          ` : isScanner ? `
          <div class="conn-grid" data-conn>
            <div><p class="mono dim small">ENVIRONMENT</p><p><b>Axiom scanner range</b></p></div>
            <div><p class="mono dim small">NETWORK</p><p class="mono">${esc(inst?.networkCidr || "—")} <span class="dim">isolated lab network</span></p></div>
            <div><p class="mono dim small">ACCESS</p><p>Scanner tab (web console — no shell)</p></div>
          </div>
          <h3>Range targets</h3>
          <dl class="kv">
            ${scannerBoxes.map((b) => `<div><dt>${esc(b.name)}</dt><dd class="mono">${esc(b.ip || "—")} <span class="dim">services undisclosed — scan to discover</span></dd></div>`).join("") || `<div><dt>Targets</dt><dd class="dim">Start the lab to reveal the range.</dd></div>`}
          </dl>
          ${lab.slug === "m7-7-2-5-auth-scan" ? `
          <h3>Authenticated scan credentials (VM #1)</h3>
          <dl class="kv">
            <div><dt>SSH username</dt><dd class="mono">scanner</dd></div>
            <div><dt>SSH password</dt><dd class="mono">${esc(scannerSshPassword || (inst ? "provisioning…" : "start the lab first"))} ${scannerSshPassword ? `<button class="iconbtn xs" data-copy="${esc(scannerSshPassword)}" aria-label="Copy SSH password">⧉</button>` : ""}</dd></div>
          </dl>
          <p class="dim small">Enter these credentials in the scan configuration. The password is unique to your session and changes on reset.</p>` : ""}
          <p class="dim small">Scanning happens in the Scanner tab against the targets above. Service banners, findings, and page contents are never listed here — enumerate them with scans.</p>
          ` : isNmap ? `
          <div class="conn-grid" data-conn>
            <div><p class="mono dim small">RANGE</p><p class="mono">${esc(inst?.networkCidr || "—")} <span class="dim">isolated lab network</span></p></div>
            <div><p class="mono dim small">ATTACKER</p><p class="mono">${esc(nmapTopo?.attacker?.ip || inst?.targetIp || "—")}</p></div>
            <div><p class="mono dim small">ACCESS</p><p>Attacker terminal below${vpn?.enabled ? " · Kali via VPN" : ""}</p></div>
          </div>
          <h3>Range targets</h3>
          <dl class="kv">
            ${(nmapTopo?.boxes || []).map((b) => `<div><dt>${esc(b.name)}</dt><dd class="mono">${esc(b.ip)} <span class="dim">services undisclosed — scan to discover</span></dd></div>`).join("") || `<div><dt>Targets</dt><dd class="dim">Start the lab to reveal the range.</dd></div>`}
          </dl>
          <h3>From the attacker terminal</h3>
          <div class="cmdrow"><code class="mono">nmap -sS --open ${esc(inst?.networkCidr || "<SUBNET>")}</code>${inst?.networkCidr ? `<button class="iconbtn xs" data-copy="nmap -sS --open ${esc(inst.networkCidr)}" aria-label="Copy command">⧉</button>` : ""}</div>
          ${lab.slug === SMB_SLUG ? `
          <div class="cmdrow"><code class="mono">nmap -p 445 --open ${esc(inst?.networkCidr || "<SUBNET>")}</code>${inst?.networkCidr ? `<button class="iconbtn xs" data-copy="nmap -p 445 --open ${esc(inst.networkCidr)}" aria-label="Copy command">⧉</button>` : ""}</div>
          <div class="cmdrow"><code class="mono">smbclient -L //${esc(nmapTopo?.boxes?.find((b) => /dc01/i.test(b.name))?.ip || targetIp)} -N</code></div>
          <div class="cmdrow"><code class="mono">net view \\\\dc01</code></div>
          <div class="cmdrow"><code class="mono">enum4linux ${esc(nmapTopo?.boxes?.[0]?.ip || targetIp)}</code></div>` : ""}
          ${lab.slug === SMTP_SLUG ? `
          <div class="cmdrow"><code class="mono">nmap -sV -p 25 -T4 --open ${esc(inst?.networkCidr || "<SUBNET>")}</code>${inst?.networkCidr ? `<button class="iconbtn xs" data-copy="nmap -sV -p 25 -T4 --open ${esc(inst.networkCidr)}" aria-label="Copy command">⧉</button>` : ""}</div>
          <div class="cmdrow"><code class="mono">nc -nv ${esc(nmapTopo?.boxes?.[0]?.ip || targetIp)} 25</code></div>` : ""}
          ${lab.slug === SNMP_SLUG ? `
          <div class="cmdrow"><code class="mono">onesixtyone -c communities.txt ${esc(inst?.networkCidr || "<SUBNET>")}</code>${inst?.networkCidr ? `<button class="iconbtn xs" data-copy="onesixtyone -c communities.txt ${esc(inst.networkCidr)}" aria-label="Copy command">⧉</button>` : ""}</div>
          <div class="cmdrow"><code class="mono">snmpwalk -c public -v1 ${esc(nmapTopo?.boxes?.[0]?.ip || targetIp)} 1.3.6.1.2.1.25.4.2.1.2</code></div>` : ""}
          <p class="dim small">Scan the actual assigned subnet shown above. Services, ports, and flags are never listed here — enumerate the range with Nmap. The attacker shell supports pipes, redirection, output files, and NSE scripts. From your own Kali over VPN the same scans work against this subnet.</p>
          ${vpnPanel(vpn, domain, nmapTopo?.attacker?.ip || targetIp, u.username, `nmap -sS --open ${inst?.networkCidr || "<SUBNET>"}`)}
          ` : isOsint ? `
          <div class="conn-grid" data-conn>
            <div><p class="mono dim small">ENVIRONMENT</p><p><b>External Reconnaissance</b></p></div>
            <div><p class="mono dim small">TARGET</p><p>None — this exercise needs no VM</p></div>
            <div><p class="mono dim small">PRIMARY TOOLS</p><p>${esc(research.tools)}</p></div>
            <div><p class="mono dim small">ACCESS</p><p>Research tab links (new browser tabs)</p></div>
          </div>
          <h3>Research links</h3>
          <div class="lrow">
            ${researchLinksHtml(research.links, "conn")}
          </div>
          <p class="dim small">${esc(research.note)}</p>
          ` : isDns ? `
          <div class="conn-grid" data-conn>
            <div><p class="mono dim small">TARGET</p><p><b>${esc(primary.name || "DNS Server")}</b> <span class="dim">· ${esc(primary.os || "Linux")}${primary.target_type ? ` (${esc(primary.target_type)})` : ""}</span></p></div>
            <div><p class="mono dim small">TARGET IP</p><p class="mono conn-ip">${esc(targetIp)} ${inst?.targetIp ? `<button class="iconbtn xs" data-copy="${esc(inst.targetIp)}" aria-label="Copy target IP">⧉</button>` : ""}</p></div>
            <div><p class="mono dim small">PORTS</p><p class="mono">53/udp + 53/tcp (dns)</p></div>
            <div><p class="mono dim small">NETWORK</p><p class="mono">${esc(inst?.networkCidr || "—")} <span class="dim">isolated lab network</span></p></div>
            <div><p class="mono dim small">ACCESS</p><p>Lab terminal (always)${vpn?.enabled ? " · Kali via VPN" : ""}</p></div>
          </div>
          <h3>From the lab terminal</h3>
          <div class="cmdrow"><code class="mono">dig @${esc(targetIp)} megacorpone.com MX</code>${inst?.targetIp ? `<button class="iconbtn xs" data-copy="dig @${esc(inst.targetIp)} megacorpone.com MX" aria-label="Copy command">⧉</button>` : ""}</div>
          <div class="cmdrow"><code class="mono">dnsenum --dnsserver ${esc(targetIp)} megacorpone.com</code>${inst?.targetIp ? `<button class="iconbtn xs" data-copy="dnsenum --dnsserver ${esc(inst.targetIp)} megacorpone.com" aria-label="Copy command">⧉</button>` : ""}</div>
          ${(() => { const hep = String(inst?.hostEndpoint || "").split(":"); const h = hep[0] || "127.0.0.1"; const up = hep[1] || "53";
            return inst?.hostEndpoint
              ? `<h3>From this machine's shell</h3><div class="cmdrow"><code class="mono">dig @${esc(h)} -p ${esc(up)} megacorpone.com MX</code><button class="iconbtn xs" data-copy="dig @${esc(h)} -p ${esc(up)} megacorpone.com MX" aria-label="Copy command">⧉</button></div><p class="dim small">Loopback mapping of your isolated target — unique to your session. Append <code class="mono">+tcp</code> to query over TCP.</p>`
              : `<p class="dim small">Start the lab to get connection details.</p>`; })()}
          ${vpnPanel(vpn, domain, targetIp, u.username, `dig @${targetIp} megacorpone.com MX`)}
          ` : isScan ? `
          <div class="conn-grid" data-conn>
            <div><p class="mono dim small">TARGET</p><p><b>${esc(primary.name || "Scan Target")}</b> <span class="dim">· ${esc(primary.os || "Linux")}${primary.target_type ? ` (${esc(primary.target_type)})` : ""}</span></p></div>
            <div><p class="mono dim small">TARGET IP</p><p class="mono conn-ip">${esc(targetIp)} <span class="dim">ends in .151</span> ${inst?.targetIp ? `<button class="iconbtn xs" data-copy="${esc(inst.targetIp)}" aria-label="Copy target IP">⧉</button>` : ""}</p></div>
            <div><p class="mono dim small">SERVICES</p><p class="mono">TCP + UDP <span class="dim">(discover open ports by scanning)</span></p></div>
            <div><p class="mono dim small">NETWORK</p><p class="mono">${esc(inst?.networkCidr || "—")} <span class="dim">isolated lab network</span></p></div>
            <div><p class="mono dim small">ACCESS</p><p>Lab terminal (always)${vpn?.enabled ? " · Kali via VPN" : ""}</p></div>
          </div>
          <h3>From the lab terminal</h3>
          <div class="cmdrow"><code class="mono">nc -vz ${esc(targetIp)} 1-1000</code>${inst?.targetIp ? `<button class="iconbtn xs" data-copy="nc -vz ${esc(inst.targetIp)} 1-1000" aria-label="Copy command">⧉</button>` : ""}</div>
          <div class="cmdrow"><code class="mono">nc -vz -u ${esc(targetIp)} 100-200</code>${inst?.targetIp ? `<button class="iconbtn xs" data-copy="nc -vz -u ${esc(inst.targetIp)} 100-200" aria-label="Copy command">⧉</button>` : ""}</div>
          <p class="dim small">Open ports are not listed anywhere — scan the target to discover them. From your own Kali over VPN the same commands work against the target IP directly.</p>
          ${vpnPanel(vpn, domain, targetIp, u.username, `nc -vz ${targetIp} 1-10000`)}
          ` : `
          <div class="conn-grid" data-conn>
            <div><p class="mono dim small">TARGET</p><p><b>${esc(primary.name || "VM #1")}</b> <span class="dim">· ${esc(primary.os || "Linux")}</span></p></div>
            <div><p class="mono dim small">TARGET IP</p><p class="mono conn-ip">${esc(targetIp)} ${inst?.targetIp ? `<button class="iconbtn xs" data-copy="${esc(inst.targetIp)}" aria-label="Copy target IP">⧉</button>` : ""}</p></div>
            <div><p class="mono dim small">PORTS</p><p class="mono">43/tcp (whois)</p></div>
            <div><p class="mono dim small">NETWORK</p><p class="mono">${esc(inst?.networkCidr || "—")} <span class="dim">isolated lab network</span></p></div>
            <div><p class="mono dim small">ACCESS</p><p>Lab terminal (always)${inst ? " · direct WHOIS from the Docker host" : ""}${vpn?.enabled ? " · Kali via VPN" : ""}</p></div>
          </div>
          <h3>From the lab terminal</h3>
          <div class="cmdrow"><code class="mono">whois ${esc(domain)} -h ${esc(targetIp)}</code>${inst?.targetIp ? `<button class="iconbtn xs" data-copy="whois ${esc(domain)} -h ${esc(inst.targetIp)}" aria-label="Copy command">⧉</button>` : ""}</div>
          ${inst?.hostEndpoint ? `<h3>From this machine's shell</h3><div class="cmdrow"><code class="mono">whois ${esc(domain)} -h ${esc(inst.hostEndpoint.replace(":", " -p "))}</code><button class="iconbtn xs" data-copy="whois ${esc(domain)} -h ${esc(inst.hostEndpoint.replace(":", " -p "))}" aria-label="Copy command">⧉</button></div><p class="dim small">Loopback mapping of your isolated target — unique to your session.</p>` : `<p class="dim small">Start the lab to get connection details.</p>`}
          ${vpnPanel(vpn, domain, targetIp, u.username)}
          `}
        </section>

        <section class="card tabpanel" role="tabpanel" id="panel-notes" aria-labelledby="tab-notes" tabindex="0" hidden>
          <h2>Notes</h2>
          <p class="dim small">Private to you. Saved with this lab — switching tabs never loses text.</p>
          <textarea id="labNotes" rows="10" aria-label="Lab notes" placeholder="Enumeration findings, commands that worked, ideas…">${esc(notes?.body || "")}</textarea>
          <div class="lrow"><button class="btn primary" id="saveNotes">Save Notes</button><span class="dim small" id="notesMsg" role="status"></span></div>
        </section>

        <section class="card tabpanel" role="tabpanel" id="panel-more" aria-labelledby="tab-more" tabindex="0" hidden>
          <h2>More</h2>
          <h3>Environment</h3>
          <div class="conn-grid">
            <div><p class="mono dim small">PATH</p><p><a class="link" href="/labs/${esc(course.slug)}">${esc(course.title)}</a> <span class="dim">· Module ${esc(String(lab.module_number))}</span></p></div>
            <div><p class="mono dim small">PROVIDER</p><p class="mono">${esc(inst?.provider || "—")}</p></div>
            <div><p class="mono dim small">RESETS</p><p class="mono">${esc(String(inst?.resetCount ?? 0))}</p></div>
            <div><p class="mono dim small">TYPE</p><p class="mono">${esc(lab.environment_type)}</p></div>
          </div>
          <h3>Report a problem</h3>
          <p class="dim small">If the target misbehaves, reset the lab first (it rebuilds the environment). Still broken? Contact your Axiom administrator.</p>
        </section>

        ${isTheory || isScanner ? "" : `
        <section class="card terminal-card" aria-label="Integrated terminal">
          <div class="sech"><h2><span class="h-ic" aria-hidden="true">▸</span> ${isNmap ? "Attacker Terminal" : "Lab Terminal"}</h2><span class="mono dim small">scoped · no host shell</span></div>
          <div class="term-out" id="termOut" role="log" aria-label="Terminal output" tabindex="0"><div class="dim">${isOsint ? "Type <b>help</b> to see available commands. Research for this exercise is browser-based — see the Research tab." : isNmap ? "Type <b>help</b> for the attacker shell. Scan the assigned subnet from the Connection tab." : "Type <b>help</b> to see available commands. Runs inside your isolated lab environment."}</div></div>
          <form class="term-in" id="termForm"><span class="mono term-ps" aria-hidden="true">${isNmap ? "kali ❯" : "lab ❯"}</span><input id="termInput" autocomplete="off" spellcheck="false" aria-label="Terminal input" placeholder="${isOsint ? "help — research is browser-based" : isDns ? `dig @${esc(targetIp)} megacorpone.com MX` : isScan ? `nc -vz ${esc(targetIp)} 1-1000` : isNmap && lab.slug === SNMP_SLUG ? `onesixtyone -c communities.txt ${esc(inst?.networkCidr || "<SUBNET>")}` : isNmap && lab.slug === SMTP_SLUG ? `nmap -sV -p 25 --open ${esc(inst?.networkCidr || "<SUBNET>")}` : isNmap && lab.slug === SMB_SLUG ? `nmap -p 445 --open ${esc(inst?.networkCidr || "<SUBNET>")}` : isNmap ? `nmap -sS --open ${esc(inst?.networkCidr || "<SUBNET>")}` : `whois ${esc(domain)} -h ${esc(targetIp)}`}" ${inst ? "" : "disabled"}><button class="btn primary xs" type="submit" ${inst ? "" : "disabled"}>Run</button></form>
        </section>`}
      </div>

      <aside class="labrail" aria-label="Lab status and progress">
        <section class="card" aria-label="Lab status">
          <div class="sech"><h2>Lab Status</h2><span data-status-pill>${statusPill(inst?.status || "stopped")}</span></div>
          <p class="mono lab-elapsed${inst?.startedAt ? " running" : " stopped"}" data-elapsed>${inst?.startedAt ? "…" : "Not running"}</p>
          <h3 class="rail-h">${isOsint ? "Environment" : isNmap ? "Range" : isScanner ? "Range" : isTheory ? "Exercise" : "Target Information"}</h3>
          <dl class="kv">
            ${isScanner ? `
            <div><dt>Subnet</dt><dd class="mono">${esc(inst?.networkCidr || "—")}</dd></div>
            <div><dt>Targets</dt><dd>${esc(String(scannerTargets.length))} lab hosts <span class="dim">(scan to discover)</span></dd></div>
            ` : isTheory ? `
            <div><dt>Environment</dt><dd>Knowledge exercise</dd></div>
            <div><dt>Type</dt><dd>Concepts <span class="dim">(no target)</span></dd></div>
            <div><dt>Target IP</dt><dd class="mono">— <span class="dim">none for this exercise</span></dd></div>
            ` : isOsint ? `
            <div><dt>Environment</dt><dd>External reconnaissance</dd></div>
            <div><dt>Type</dt><dd>${esc(primary.os || "Public Web")}${primary.target_type ? ` (${esc(primary.target_type)})` : ""}</dd></div>
            <div><dt>Tools</dt><dd>Google · Public web · Social media</dd></div>
            <div><dt>Target IP</dt><dd class="mono">— <span class="dim">none for this exercise</span></dd></div>
            ` : isNmap ? `
            <div><dt>Subnet</dt><dd class="mono">${esc(inst?.networkCidr || "—")}</dd></div>
            <div><dt>Attacker</dt><dd class="mono" data-target-ip>${esc(nmapTopo?.attacker?.ip || inst?.targetIp || "—")}</dd></div>
            <div><dt>Targets</dt><dd>${esc(String(nmapTopo?.boxes?.length ?? targets.filter((t) => t.target_type === "nmap-target").length))} lab hosts <span class="dim">(scan to discover)</span></dd></div>
            ` : `
            <div><dt>Target IP</dt><dd class="mono" data-target-ip>${esc(inst?.targetIp || "—")} ${inst?.targetIp ? `<button class="iconbtn xs" data-copy="${esc(inst.targetIp)}" aria-label="Copy target IP">⧉</button>` : ""}</dd></div>
            <div><dt>Type</dt><dd>${esc(primary.os || "Linux")}${primary.target_type ? ` (${esc(primary.target_type)})` : ""}</dd></div>
            <div><dt>Network</dt><dd>Isolated Lab Network${inst?.networkCidr ? ` <span class="mono dim">${esc(inst.networkCidr)}</span>` : ""}</dd></div>
            `}
            <div><dt>Difficulty</dt><dd>${esc(lab.difficulty)}</dd></div>
          </dl>
          <div class="lrow lab-actions" data-actions>
            ${!inst ? `<button class="btn primary" data-lab-action="start">Start Lab</button>`
              : inst.status === "running" ? `<button class="btn" data-lab-action="reset">Reset Lab</button><button class="btn danger" data-lab-action="stop">Stop Lab</button>`
              : inst.status === "failed" ? `<button class="btn primary" data-lab-action="start">Retry Start</button><button class="btn danger" data-lab-action="stop">Dismiss</button>`
              : `<button class="btn" disabled aria-disabled="true">${esc(inst.status)}…</button>`}
          </div>
          <p class="dim small" data-action-msg role="status"></p>
        </section>

        <section class="card" aria-label="Submit answer">
          <h2>Submit Answer</h2>
          <form id="submitForm" class="form lab-submit">
            ${progress.objectives.map((o) => `
              <label>${esc(o.title)}${o.description ? `<span class="dim small">${esc(o.description)}</span>` : ""}<input name="${esc(o.key)}" autocomplete="off" spellcheck="false" placeholder="your answer" ${inst ? "" : "disabled"}></label>
              <p class="mono small submit-fb" data-fb="${esc(o.key)}" role="status"></p>`).join("")}
            <button class="btn primary" type="submit" ${inst ? "" : "disabled"}>Submit Answer</button>
          </form>
        </section>

        <section class="card" aria-label="Lab progress">
          <h2>Lab Progress</h2>
          <p class="mono dim small" data-progress-count>${progress.done} / ${progress.total} completed · ${progress.pct}%</p>
          <ol class="checklist" data-checklist>
            <li class="check-item${progress.started ? " done" : ""}"><span class="check-box" aria-hidden="true">${progress.started ? "✓" : "○"}</span><span>${isOsint ? "Start the exercise" : "Start the lab"}</span></li>
            ${objSteps}
          </ol>
          <h3 class="rail-h">Module Progress</h3>
          <p class="mono dim small">Module ${esc(String(lab.module_number))} · ${modProg.completed} / ${modProg.total} labs completed</p>
        </section>
      </aside>
    </div>
  </div>`,
  }));
}));

// ---------- API ----------
labApi.use(needAuthJson);

labApi.get("/labs/courses", ah(async (req, res) => {
  const courses = await svc.listLabCourses();
  const out = [];
  for (const course of courses) {
    const [modules, progress] = await Promise.all([
      svc.courseStructure(req.user.id, course.id),
      svc.courseProgress(req.user.id, course.id),
    ]);
    if (!progress.total) continue;
    out.push({ id: course.id, slug: course.slug, title: course.title, subtitle: course.subtitle, moduleCount: modules.length, progress });
  }
  res.json({ courses: out });
}));

labApi.get("/labs/courses/:courseSlug", ah(async (req, res) => {
  const course = await svc.getLabCourse(req.params.courseSlug);
  if (!course) return res.status(404).json({ error: "Training path not found." });
  const [modules, progress] = await Promise.all([
    svc.courseStructure(req.user.id, course.id),
    svc.courseProgress(req.user.id, course.id),
  ]);
  res.json({
    course: { id: course.id, slug: course.slug, title: course.title, subtitle: course.subtitle },
    modules: modules.map((m) => ({
      number: m.number, title: m.title, total: m.total, completed: m.completed, pct: m.pct,
      sections: m.sections.map((s) => ({
        section: s.section, title: s.title,
        labs: s.labs.map(({ lab, state, running, progress: lp }) => ({
          id: lab.id, slug: lab.slug, title: lab.title, labNumber: lab.lab_number,
          difficulty: lab.difficulty, state, running, progress: lp,
          url: `/labs/${course.slug}/${lab.slug}`,
        })),
      })),
    })),
    progress,
  });
}));

labApi.get("/labs", ah(async (req, res) => {
  const labs = await svc.listLabs();
  const courseById = new Map((await svc.listLabCourses()).map((c) => [c.id, c]));
  const out = [];
  for (const lab of labs) {
    const progress = await svc.labProgress(req.user.id, lab.id);
    const inst = await svc.activeInstance(req.user.id, lab.id);
    const course = lab.course_id ? courseById.get(lab.course_id) : null;
    out.push({
      id: lab.id, slug: lab.slug, title: lab.title, description: lab.description,
      courseSlug: course?.slug || null, courseTitle: course?.title || null,
      moduleNumber: lab.module_number, sectionNumber: lab.section_number, labNumber: lab.lab_number,
      difficulty: lab.difficulty, environmentType: lab.environment_type,
      tags: labTags(lab), status: inst ? inst.status : "stopped", progress,
      url: course ? `/labs/${course.slug}/${lab.slug}` : null,
    });
  }
  res.json({ labs: out });
}));

labApi.get("/labs/:id", ah(async (req, res) => {
  const lab = await resolveLab(req.params.id);
  if (!lab) return res.status(404).json({ error: "Lab not found." });
  const course = lab.course_id ? await get(`SELECT id, slug, title FROM lab_courses WHERE id=?`, [lab.course_id]) : null;
  const [targets, objectives, progress, instance, modProg] = await Promise.all([
    svc.labTargets(lab.id), svc.labObjectives(lab.id), svc.labProgress(req.user.id, lab.id),
    svc.activeInstance(req.user.id, lab.id),
    lab.course_id ? svc.moduleProgress(req.user.id, lab.course_id, lab.module_number) : { total: 0, completed: 0 },
  ]);
  res.json({ lab: { ...lab, tags: labTags(lab), courseSlug: course?.slug || null, url: course ? `/labs/${course.slug}/${lab.slug}` : null }, targets: pubTargets(targets), objectives, progress, instance: pubInstance(instance), moduleProgress: modProg });
}));

labApi.get("/labs/:id/status", ah(async (req, res) => {
  const lab = await resolveLab(req.params.id);
  if (!lab) return res.status(404).json({ error: "Lab not found." });
  const [instance, progress] = await Promise.all([
    svc.activeInstance(req.user.id, lab.id), svc.labProgress(req.user.id, lab.id),
  ]);
  res.json({ instance: pubInstance(instance), progress });
}));

function ownOrAdmin(req, inst) {
  return inst && (inst.user_id === req.user.id || req.user.role === "admin");
}

// Serialize lifecycle ops per user+lab. Docker calls take tens of seconds
// and concurrent start/stop/reset on one instance interleaved into
// Illegal-transition 500s ("fails once, works on retry"). Queued ops run
// one at a time instead; single-process scope is sufficient for Axiom.
const labLocks = new Map();
export async function withLabLock(key, fn) {
  const prev = labLocks.get(key) || Promise.resolve();
  let release;
  const cur = new Promise((r) => (release = r));
  labLocks.set(key, cur);
  try { await prev; } catch {}
  try { return await fn(); }
  finally { release(); if (labLocks.get(key) === cur) labLocks.delete(key); }
}

labApi.post("/labs/:id/start", ah(async (req, res) => {
  const lab = await resolveLab(req.params.id);
  if (!lab || lab.status !== "active") return res.status(404).json({ error: "Lab not found." });
  return withLabLock(`${req.user.id}:${lab.id}`, async () => {
  const existing = await svc.activeInstance(req.user.id, lab.id);
  if (existing) return res.json({ ok: true, reused: true, instance: pubInstance(existing), progress: await svc.labProgress(req.user.id, lab.id) });
  // External-research, theory, and console-only scanner exercises need no
  // target VM: activating the workspace only records a logical session
  // (progress, submissions, notes, hints).
  let provider = "external-research";
  if (lab.environment_type !== "osint" && lab.environment_type !== "theory" && !await isScannerConsoleLab(lab)) {
    try { provider = await selectProvider(); }
    catch (e) { log("lab.start.noprovider", { lab: lab.id, error: String(e?.message || e).slice(0, 200) }); return res.status(500).json({ error: "Lab infrastructure unavailable. Contact your administrator." }); }
  }
  let inst = await svc.createInstance({ userId: req.user.id, labId: lab.id, provider });
  log("lab.start", { user: req.user.id, lab: lab.id, provider });
  try {
    const details = await provisionInstance({ lab, instance: inst });
    inst = await svc.setInstanceStatus(inst, "running", {
      providerReference: details.providerReference, networkName: details.networkName,
      networkCidr: details.networkCidr, targetIp: details.targetIp, targetPort: details.targetPort,
      hostEndpoint: details.hostEndpoint, startedAt: new Date().toISOString(),
    });
  } catch (e) {
    log("lab.start.fail", { user: req.user.id, lab: lab.id, error: String(e?.message || e).slice(0, 300) });
    await svc.clearRuntimeFlags(inst.id).catch(() => {});
    inst = await svc.setInstanceStatus(inst, "failed", { error: "provisioning failed" }).catch(() => inst);
    return res.status(500).json({ error: "Could not start the lab target. Please retry.", instance: pubInstance(inst) });
  }
  res.json({ ok: true, instance: pubInstance(inst), progress: await svc.labProgress(req.user.id, lab.id) });
  });
}));

labApi.post("/labs/:id/stop", ah(async (req, res) => {
  const lab = await resolveLab(req.params.id);
  if (!lab) return res.status(404).json({ error: "Lab not found." });
  const t0 = Date.now();
  const stage = (s) => log("lab.stop.stage", { user: req.user.id, lab: lab.id, stage: s, ms: Date.now() - t0 });
  stage("begin");
  return withLabLock(`${req.user.id}:${lab.id}`, async () => {
  stage("locked");
  const inst = await svc.activeInstance(req.user.id, lab.id) || await svc.latestInstance(req.user.id, lab.id);
  if (!inst || !ownOrAdmin(req, inst)) return res.status(404).json({ error: "No lab session to stop." });
  if (inst.status === "stopped") {
    return res.json({ ok: true, instance: pubInstance(inst) });
  }
  let cur = inst;
  if (cur.status !== "stopping") {
    try { cur = await svc.setInstanceStatus(cur, "stopping"); }
    catch { cur = await svc.getInstance(cur.id) || cur; } // raced transition: work with fresh state
  }
  await destroyInstance(cur);
  stage("destroyed");
  try { cur = await svc.setInstanceStatus(cur, "stopped"); } catch { /* force below covers it */ }
  cur = await svc.forceInstanceState(cur.id, { status: "stopped", provider_reference: "", network_name: "", target_ip: "", host_endpoint: "", stopped_at: new Date().toISOString() });
  await svc.clearRuntimeFlags(cur.id).catch(() => {});
  await svc.clearScannerState(cur.id).catch(() => {});
  log("lab.stop", { user: req.user.id, lab: lab.id, ms: Date.now() - t0 });
  res.json({ ok: true, instance: pubInstance(cur), progress: await svc.labProgress(req.user.id, lab.id) });
  });
}));

labApi.post("/labs/:id/reset", ah(async (req, res) => {
  const lab = await resolveLab(req.params.id);
  if (!lab) return res.status(404).json({ error: "Lab not found." });
  return withLabLock(`${req.user.id}:${lab.id}`, async () => {
  const inst = await svc.activeInstance(req.user.id, lab.id);
  if (!inst || !ownOrAdmin(req, inst)) {
    const latest = await svc.latestInstance(req.user.id, lab.id);
    if (latest && ownOrAdmin(req, latest)) {
      return res.status(409).json({ error: "Lab is stopped. Start it before resetting." });
    }
    return res.status(404).json({ error: "Start the lab before resetting it." });
  }
  if (inst.status !== "running") return res.status(409).json({ error: `Cannot reset while ${inst.status}.` });
  let cur = await svc.setInstanceStatus(inst, "resetting");
  await destroyInstance(cur);
  // A reset rebuilds the environment from scratch: drop the old runtime
  // secrets so provisioning mints fresh ones (new flag for flag labs).
  await svc.clearRuntimeFlags(cur.id).catch(() => {});
  await svc.clearScannerState(cur.id).catch(() => {});
  log("lab.reset", { user: req.user.id, lab: lab.id });
  try {
    const details = await provisionInstance({ lab, instance: cur });
    cur = await svc.setInstanceStatus(cur, "running", {
      providerReference: details.providerReference, networkName: details.networkName,
      networkCidr: details.networkCidr, targetIp: details.targetIp, targetPort: details.targetPort,
      hostEndpoint: details.hostEndpoint, startedAt: new Date().toISOString(), resetCount: cur.reset_count + 1,
    });
  } catch (e) {
    log("lab.reset.fail", { user: req.user.id, lab: lab.id, error: String(e?.message || e).slice(0, 300) });
    cur = await svc.setInstanceStatus(cur, "failed", { error: "reset failed" }).catch(() => cur);
    return res.status(500).json({ error: "Reset failed. The previous environment was destroyed — try starting again.", instance: pubInstance(cur) });
  }
  res.json({ ok: true, instance: pubInstance(cur), progress: await svc.labProgress(req.user.id, lab.id) });
  });
}));

labApi.post("/labs/:id/submit", ah(async (req, res) => {
  const lab = await resolveLab(req.params.id);
  if (!lab) return res.status(404).json({ error: "Lab not found." });
  const instance = await svc.activeInstance(req.user.id, lab.id);
  if (!instance) return res.status(409).json({ error: "Start the lab before submitting answers." });
  const body = req.body || {};
  let answers = {};
  if (body.answers && typeof body.answers === "object") answers = body.answers;
  else if (body.objective) answers[body.objective] = body.answer;
  const keys = Object.keys(answers);
  if (!keys.length) return res.status(400).json({ error: "Nothing to submit." });
  const results = {};
  for (const key of keys.slice(0, 10)) {
    const r = await svc.submitAnswer({ userId: req.user.id, lab, objectiveKey: key, answer: answers[key], instanceId: instance.id });
    if (!r.ok) { results[key] = { correct: false, error: r.error }; continue; }
    results[key] = { correct: r.correct, completed: r.completed };
    log("lab.submit", { user: req.user.id, lab: lab.id, objective: key, correct: r.correct });
  }
  res.json({ ok: true, results, progress: await svc.labProgress(req.user.id, lab.id) });
}));

labApi.get("/labs/:id/hints", ah(async (req, res) => {
  const lab = await resolveLab(req.params.id);
  if (!lab) return res.status(404).json({ error: "Lab not found." });
  res.json({ hints: await svc.hintsFor(req.user.id, lab.id) });
}));

labApi.post("/labs/:id/hints/:hintId/reveal", ah(async (req, res) => {
  const lab = await resolveLab(req.params.id);
  if (!lab) return res.status(404).json({ error: "Lab not found." });
  const hint = await svc.revealHint(req.user.id, lab.id, req.params.hintId);
  if (!hint) return res.status(404).json({ error: "Hint not found." });
  res.json({ ok: true, hint: { id: hint.id, title: hint.title, body: hint.body } });
}));

labApi.get("/labs/:id/notes", ah(async (req, res) => {
  const lab = await resolveLab(req.params.id);
  if (!lab) return res.status(404).json({ error: "Lab not found." });
  const notes = await svc.getNotes(req.user.id, lab.id);
  res.json({ body: notes?.body || "", updatedAt: notes?.updated_at || null });
}));

labApi.put("/labs/:id/notes", ah(async (req, res) => {
  const lab = await resolveLab(req.params.id);
  if (!lab) return res.status(404).json({ error: "Lab not found." });
  const inst = await svc.activeInstance(req.user.id, lab.id) || await svc.latestInstance(req.user.id, lab.id);
  const saved = await svc.saveNotes(req.user.id, lab.id, inst?.id || "", req.body?.body);
  res.json({ ok: true, updatedAt: saved.updated_at });
}));

labApi.post("/labs/:id/terminal", ah(async (req, res) => {  const lab = await resolveLab(req.params.id);
  if (!lab) return res.status(404).json({ error: "Lab not found." });
  const inst = await svc.activeInstance(req.user.id, lab.id);
  if (!inst || !ownOrAdmin(req, inst)) return res.status(409).json({ error: "Start the lab to use the terminal." });
  if (inst.status !== "running") return res.status(409).json({ error: `Terminal unavailable while ${inst.status}.` });
  const r = await runTerminalCommand(inst, req.body?.command, lab);
  res.json({ ok: true, ...r });
}));

// ---------- Axiom vulnerability scanner (Module 7.2) ----------
// Owner-scoped JSON API over the scanner engine. Findings expose genuine
// evidence (that IS the exercise); validation metadata (expected hashes,
// runtime secrets, answer fields) is never serialized here.
async function needScannerInstance(req, lab) {
  const inst = await svc.activeInstance(req.user.id, lab.id);
  if (!inst || inst.user_id !== req.user.id) return { error: "Start the lab before using the scanner." };
  if (inst.status !== "running") return { error: `Scanner unavailable while ${inst.status}.` };
  return { inst };
}

function pubScanJob(j) {
  if (!j) return null;
  return {
    id: j.id, name: j.name, template: j.template,
    targets: JSON.parse(j.targets_json || "[]"), ports: JSON.parse(j.ports_json || "[]"),
    authUser: j.auth_user || null, assessment: JSON.parse(j.assessment_json || "{}"),
    pluginFilter: j.plugin_filter || "", status: j.status, progress: j.progress,
    error: j.error || null, createdAt: j.created_at, updatedAt: j.updated_at,
  };
}

function pubFinding(f) {
  return {
    id: f.id, jobId: f.job_id, pluginId: f.plugin_id, pluginName: f.plugin_name,
    family: f.family, severity: f.severity, targetIp: f.target_ip, port: f.port,
    protocol: f.protocol, title: f.title, description: f.description,
    evidence: f.evidence, details: JSON.parse(f.details_json || "{}"),
    remediation: f.remediation, createdAt: f.created_at,
  };
}

function pubSitemapPage(p) {
  // Metadata only — page content travels exclusively through the page-view
  // endpoint for URLs this scan actually discovered.
  return {
    id: p.id, jobId: p.job_id, targetIp: p.target_ip, port: p.port,
    url: p.url, path: p.path, status: p.status, title: p.title,
    links: JSON.parse(p.links_json || "[]"),
  };
}

labApi.get("/labs/:id/scanner/config", ah(async (req, res) => {
  const lab = await resolveLab(req.params.id);
  if (!lab) return res.status(404).json({ error: "Lab not found." });
  const { inst, error } = await needScannerInstance(req, lab);
  if (error) return res.status(409).json({ error });
  const { TEMPLATE_CATEGORIES, SCAN_TEMPLATES, ADVANCED_SETTINGS } = await import("./labs/scanner-plugins.js");
  let targets = [];
  try {
    const all = await svc.labTargets(lab.id);
    const base = String(inst.network_cidr || "").split(".").slice(0, 3).join(".");
    targets = all.filter((t) => t.target_type === "scanner-target").map((t) => {
      let suffix = 0;
      try { suffix = parseInt(JSON.parse(t.metadata_json || "{}").ipSuffix, 10) || 0; } catch {}
      return { name: t.name, ip: suffix ? `${base}.${suffix}` : "" };
    });
  } catch { targets = []; }
  res.json({
    ok: true,
    categories: TEMPLATE_CATEGORIES,
    templates: SCAN_TEMPLATES,
    advanced: ADVANCED_SETTINGS,
    targets,
    sshUser: "scanner",
  });
}));

labApi.get("/labs/:id/scanner/scans", ah(async (req, res) => {
  const lab = await resolveLab(req.params.id);
  if (!lab) return res.status(404).json({ error: "Lab not found." });
  const { inst, error } = await needScannerInstance(req, lab);
  if (error) return res.status(409).json({ error });
  const jobs = await svc.listScanJobs(inst.id);
  res.json({ ok: true, scans: jobs.map(pubScanJob) });
}));

labApi.post("/labs/:id/scanner/scans", ah(async (req, res) => {
  const lab = await resolveLab(req.params.id);
  if (!lab) return res.status(404).json({ error: "Lab not found." });
  const { inst, error } = await needScannerInstance(req, lab);
  if (error) return res.status(409).json({ error });
  try {
    const { launchScan } = await import("./labs/scanner-jobs.js");
    const job = await launchScan({ lab, instance: inst, userId: req.user.id, config: req.body || {} });
    log("lab.scan.launch", { user: req.user.id, lab: lab.id, job: job.id });
    res.json({ ok: true, scan: pubScanJob(job) });
  } catch (e) {
    res.status(400).json({ error: String(e?.message || e).slice(0, 300) });
  }
}));

labApi.get("/labs/:id/scanner/scans/:jobId", ah(async (req, res) => {
  const lab = await resolveLab(req.params.id);
  if (!lab) return res.status(404).json({ error: "Lab not found." });
  const { inst, error } = await needScannerInstance(req, lab);
  if (error) return res.status(409).json({ error });
  const job = await svc.getScanJob(req.params.jobId);
  if (!job || job.instance_id !== inst.id) return res.status(404).json({ error: "Scan not found." });
  const findings = await svc.listScanFindings(job.id);
  const sitemap = await svc.listSitemapPages(job.id);
  res.json({ ok: true, scan: pubScanJob(job), findings: findings.map(pubFinding), sitemap: sitemap.map(pubSitemapPage) });
}));

labApi.get("/labs/:id/scanner/findings/:findingId", ah(async (req, res) => {
  const lab = await resolveLab(req.params.id);
  if (!lab) return res.status(404).json({ error: "Lab not found." });
  const { inst, error } = await needScannerInstance(req, lab);
  if (error) return res.status(409).json({ error });
  const f = await svc.getScanFinding(req.params.findingId);
  if (!f) return res.status(404).json({ error: "Finding not found." });
  const job = await svc.getScanJob(f.job_id);
  if (!job || job.instance_id !== inst.id) return res.status(404).json({ error: "Finding not found." });
  res.json({ ok: true, finding: pubFinding(f) });
}));

labApi.get("/labs/:id/scanner/page", ah(async (req, res) => {
  const lab = await resolveLab(req.params.id);
  if (!lab) return res.status(404).json({ error: "Lab not found." });
  const { inst, error } = await needScannerInstance(req, lab);
  if (error) return res.status(409).json({ error });
  try {
    const { fetchSitemapPage } = await import("./labs/scanner-jobs.js");
    const page = await fetchSitemapPage({ instance: inst, jobId: String(req.query.jobId || ""), url: String(req.query.url || "") });
    res.json({ ok: true, page });
  } catch (e) {
    res.status(404).json({ error: String(e?.message || e).slice(0, 200) });
  }
}));

// ---------- student VPN (personal WireGuard packs for Kali access) ----------
function vpnErr(res, e) {
  if (e?.name === "VpnError") return res.status(e.status || 503).json({ error: e.message });
  throw e;
}

labApi.get("/vpn/status", ah(async (req, res) => {
  res.json(await vpnStatus(req.user.id));
}));

labApi.get("/vpn/pack", ah(async (req, res) => {
  try {
    await ensureVpnClient(req.user.id);
    const conf = await clientConfFor(req.user.id);
    const safe = String(req.user.username || "student").toLowerCase().replace(/[^a-z0-9_-]/g, "_").slice(0, 32) || "student";
    log("vpn.pack", { user: req.user.id });
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="axiom-${safe}.conf"`);
    res.send(conf);
  } catch (e) { vpnErr(res, e); }
}));

labApi.post("/vpn/regenerate", ah(async (req, res) => {
  try {
    const client = await regenerateVpnClient(req.user.id);
    res.json({ ok: true, clientIp: client.client_ip });
  } catch (e) { vpnErr(res, e); }
}));

// ---------- admin ----------
labApi.get("/admin/lab-instances", needAdminJson, ah(async (req, res) => {
  const rows = await svc.allActiveInstances();
  res.json({ instances: rows.map((r) => ({ ...pubInstance(r), user: r.username, labSlug: r.lab_slug, labTitle: r.lab_title, courseSlug: r.lab_course_slug || null })) });
}));

labApi.post("/admin/lab-instances/:id/stop", needAdminJson, ah(async (req, res) => {
  const inst = await svc.getInstance(req.params.id);
  if (!inst) return res.status(404).json({ error: "Instance not found." });
  await destroyInstance(inst);
  const cur = await svc.forceInstanceState(inst.id, { status: "stopped", provider_reference: "", network_name: "", target_ip: "", host_endpoint: "", stopped_at: new Date().toISOString() });
  await svc.clearRuntimeFlags(inst.id).catch(() => {});
  await svc.clearScannerState(inst.id).catch(() => {});
  log("lab.admin.stop", { by: req.user.id, instance: inst.id });
  res.json({ ok: true, instance: pubInstance(cur) });
}));

labApi.post("/admin/vpn/:userId/revoke", needAdminJson, ah(async (req, res) => {
  await revokeVpnClient(req.params.userId);
  log("vpn.admin.revoke", { by: req.user.id, user: req.params.userId });
  res.json({ ok: true });
}));

export async function labById(id) {
  return get(`SELECT * FROM labs WHERE id=?`, [id]);
}
