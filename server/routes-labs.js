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
import { layout, esc, emptyState } from "./views.js";
import { ah } from "./wrap.js";
import { log } from "./log.js";
import * as svc from "./labs/service.js";
import { selectProvider, provisionInstance, destroyInstance, runTerminalCommand } from "./labs/orchestrator.js";
import { LAB_DOMAIN } from "./labs/whois-data.js";

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

function readDefExtra(lab) {
  try {
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
    body: `<div class="wrap narrow">
      <p class="eyebrow mono">cyber range</p>
      <h1>Practical cybersecurity training environments.</h1>
      <p class="dim" style="max-width:70ch">Choose a training path. Isolated hands-on labs — start a target, interrogate it like a real engagement, submit what you find.</p>
      ${enriched.length ? `<div class="courselist">${enriched.map(({ course, moduleCount, progress }) => `
        <a class="ccard coursecard" href="/labs/${esc(course.slug)}">
          <div class="ccard-art"><div class="art art-fallback lab-art" aria-hidden="true"><span>◈</span></div></div>
          <div class="ccard-b">
            <div class="ccard-t"><span class="mono dim small ccard-code">training path</span><span class="mono dim small">${progress.completed}/${progress.total} completed</span></div>
            <h3>${esc(course.title)}</h3>
            ${course.subtitle ? `<p class="dim small lab-desc">${esc(course.subtitle)}</p>` : ""}
            <div class="pbar" role="progressbar" aria-valuenow="${progress.pct}" aria-valuemin="0" aria-valuemax="100" aria-label="${esc(course.title)} progress"><i style="width:${progress.pct}%"></i></div>
            <p class="mono dim small ccard-meta"><span>${moduleCount} module${moduleCount === 1 ? "" : "s"} · ${progress.total} lab${progress.total === 1 ? "" : "s"}</span><span class="link">View Labs →</span></p>
          </div></a>`).join("")}</div>`
        : emptyState("No training paths yet", "Labs appear here once definitions are registered.", u.role === "admin" ? `<a class="btn primary" href="/admin">Open Admin</a>` : "")}
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
  const [targets, objectives, progress, instance, notes, hints, modProg] = await Promise.all([
    svc.labTargets(lab.id), svc.labObjectives(lab.id), svc.labProgress(u.id, lab.id),
    svc.activeInstance(u.id, lab.id), svc.getNotes(u.id, lab.id), svc.hintsFor(u.id, lab.id),
    svc.moduleProgress(u.id, course.id, lab.module_number),
  ]);
  const extra = readDefExtra(lab);
  const instr = readInstructions(lab);
  const inst = pubInstance(instance);
  const primary = targets[0] || {};
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
  <div class="wrap labwrap" data-lab="${esc(lab.id)}" data-slug="${esc(lab.slug)}"
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
          ${["instructions", "hints", "connection", "notes", "more"].map((t, i) => `<button role="tab" id="tab-${t}" aria-controls="panel-${t}" aria-selected="${i === 0 ? "true" : "false"}" tabindex="${i === 0 ? "0" : "-1"}" data-tab="${t}">${t[0].toUpperCase() + t.slice(1)}${t === "hints" ? ` (${hints.length})` : ""}</button>`).join("")}
        </div>

        <section class="card tabpanel" role="tabpanel" id="panel-instructions" aria-labelledby="tab-instructions" tabindex="0">
          <h2>Lab Instructions</h2>
          <h3>Objective</h3>
          <ol class="objlist">${(instr.objective || []).map((s) => `<li>${withIp(s)}</li>`).join("") || "<li>Follow the objectives in the progress panel.</li>"}</ol>
          ${(instr.commands?.length) ? `<h3>Helpful Commands</h3><div class="cmdlist">${instr.commands.map((c) => `<div class="cmdrow"><code class="mono">${withIp(c)}</code><button class="iconbtn xs" data-copy="${withIp(c)}" aria-label="Copy command">⧉</button></div>`).join("")}</div>` : ""}
          ${(instr.learn?.length) ? `<h3>What You'll Learn</h3><ul class="learnlist">${instr.learn.map((s) => `<li>${esc(s)}</li>`).join("")}</ul>` : ""}
        </section>

        <section class="card tabpanel" role="tabpanel" id="panel-hints" aria-labelledby="tab-hints" tabindex="0" hidden>
          <h2>Hints</h2>
          ${hints.length ? `<ol class="hintlist">${hints.map((h) => `<li><div class="sech"><b>${esc(h.title)}</b>${h.revealed ? "" : `<button class="btn xs" data-reveal-hint="${esc(h.id)}">Reveal</button>`}</div>${h.revealed ? `<p>${esc(h.body)}</p>` : `<p class="dim small">Hidden until revealed. Using hints never blocks completion.</p>`}</li>`).join("")}</ol>`
            : `<p class="dim">No hints configured for this lab. Work the objective — the target has everything you need.</p>`}
        </section>

        <section class="card tabpanel" role="tabpanel" id="panel-connection" aria-labelledby="tab-connection" tabindex="0" hidden>
          <h2>Connection</h2>
          <div class="conn-grid" data-conn>
            <div><p class="mono dim small">TARGET</p><p><b>${esc(primary.name || "VM #1")}</b> <span class="dim">· ${esc(primary.os || "Linux")}</span></p></div>
            <div><p class="mono dim small">TARGET IP</p><p class="mono conn-ip">${esc(targetIp)} ${inst?.targetIp ? `<button class="iconbtn xs" data-copy="${esc(inst.targetIp)}" aria-label="Copy target IP">⧉</button>` : ""}</p></div>
            <div><p class="mono dim small">PORTS</p><p class="mono">43/tcp (whois)</p></div>
            <div><p class="mono dim small">NETWORK</p><p class="mono">${esc(inst?.networkCidr || "—")} <span class="dim">isolated lab network</span></p></div>
            <div><p class="mono dim small">ACCESS</p><p>Lab terminal (always)${inst ? " · direct WHOIS from the Docker host" : ""}</p></div>
          </div>
          <h3>From the lab terminal</h3>
          <div class="cmdrow"><code class="mono">whois ${esc(LAB_DOMAIN)} -h ${esc(targetIp)}</code>${inst?.targetIp ? `<button class="iconbtn xs" data-copy="whois ${esc(LAB_DOMAIN)} -h ${esc(inst.targetIp)}" aria-label="Copy command">⧉</button>` : ""}</div>
          ${inst?.hostEndpoint ? `<h3>From this machine's shell</h3><div class="cmdrow"><code class="mono">whois ${esc(LAB_DOMAIN)} -h ${esc(inst.hostEndpoint.replace(":", " -p "))}</code><button class="iconbtn xs" data-copy="whois ${esc(LAB_DOMAIN)} -h ${esc(inst.hostEndpoint.replace(":", " -p "))}" aria-label="Copy command">⧉</button></div><p class="dim small">Loopback mapping of your isolated target — unique to your session.</p>` : `<p class="dim small">Start the lab to get connection details.</p>`}
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

        <section class="card terminal-card" aria-label="Integrated terminal">
          <div class="sech"><h2><span class="h-ic" aria-hidden="true">▸</span> Lab Terminal</h2><span class="mono dim small">scoped · no host shell</span></div>
          <div class="term-out" id="termOut" role="log" aria-label="Terminal output" tabindex="0"><div class="dim">Type <b>help</b> to see available commands. Runs inside your isolated lab environment.</div></div>
          <form class="term-in" id="termForm"><span class="mono term-ps" aria-hidden="true">lab ❯</span><input id="termInput" autocomplete="off" spellcheck="false" aria-label="Terminal input" placeholder="whois ${esc(LAB_DOMAIN)} -h ${esc(targetIp)}" ${inst ? "" : "disabled"}><button class="btn primary xs" type="submit" ${inst ? "" : "disabled"}>Run</button></form>
        </section>
      </div>

      <aside class="labrail" aria-label="Lab status and progress">
        <section class="card" aria-label="Lab status">
          <div class="sech"><h2>Lab Status</h2><span data-status-pill>${statusPill(inst?.status || "stopped")}</span></div>
          <p class="mono lab-elapsed" data-elapsed>${inst?.startedAt ? "…" : "Not running"}</p>
          <h3 class="rail-h">Target Information</h3>
          <dl class="kv">
            <div><dt>Target IP</dt><dd class="mono" data-target-ip>${esc(inst?.targetIp || "—")} ${inst?.targetIp ? `<button class="iconbtn xs" data-copy="${esc(inst.targetIp)}" aria-label="Copy target IP">⧉</button>` : ""}</dd></div>
            <div><dt>Type</dt><dd>${esc(primary.os || "Linux")}${primary.target_type ? ` (${esc(primary.target_type)})` : ""}</dd></div>
            <div><dt>Network</dt><dd>Isolated Lab Network${inst?.networkCidr ? ` <span class="mono dim">${esc(inst.networkCidr)}</span>` : ""}</dd></div>
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
              <label>${esc(o.title)}<input name="${esc(o.key)}" autocomplete="off" spellcheck="false" placeholder="your answer" ${inst ? "" : "disabled"}></label>
              <p class="mono small submit-fb" data-fb="${esc(o.key)}" role="status"></p>`).join("")}
            <button class="btn primary" type="submit" ${inst ? "" : "disabled"}>Submit Answer</button>
          </form>
        </section>

        <section class="card" aria-label="Lab progress">
          <h2>Lab Progress</h2>
          <p class="mono dim small" data-progress-count>${progress.done} / ${progress.total} completed · ${progress.pct}%</p>
          <ol class="checklist" data-checklist>
            <li class="check-item${progress.started ? " done" : ""}"><span class="check-box" aria-hidden="true">${progress.started ? "✓" : "○"}</span><span>Start the lab</span></li>
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
  res.json({ lab: { ...lab, tags: labTags(lab), courseSlug: course?.slug || null, url: course ? `/labs/${course.slug}/${lab.slug}` : null }, targets, objectives, progress, instance: pubInstance(instance), moduleProgress: modProg });
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

labApi.post("/labs/:id/start", ah(async (req, res) => {
  const lab = await resolveLab(req.params.id);
  if (!lab || lab.status !== "active") return res.status(404).json({ error: "Lab not found." });
  const existing = await svc.activeInstance(req.user.id, lab.id);
  if (existing) return res.json({ ok: true, reused: true, instance: pubInstance(existing), progress: await svc.labProgress(req.user.id, lab.id) });
  let provider;
  try { provider = await selectProvider(); }
  catch (e) { log("lab.start.noprovider", { lab: lab.id, error: String(e?.message || e).slice(0, 200) }); return res.status(500).json({ error: "Lab infrastructure unavailable. Contact your administrator." }); }
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
    inst = await svc.setInstanceStatus(inst, "failed", { error: "provisioning failed" }).catch(() => inst);
    return res.status(500).json({ error: "Could not start the lab target. Please retry.", instance: pubInstance(inst) });
  }
  res.json({ ok: true, instance: pubInstance(inst), progress: await svc.labProgress(req.user.id, lab.id) });
}));

labApi.post("/labs/:id/stop", ah(async (req, res) => {
  const lab = await resolveLab(req.params.id);
  if (!lab) return res.status(404).json({ error: "Lab not found." });
  const inst = await svc.activeInstance(req.user.id, lab.id) || await svc.latestInstance(req.user.id, lab.id);
  if (!inst || !ownOrAdmin(req, inst)) return res.status(404).json({ error: "No lab session to stop." });
  if (!["provisioning", "running", "resetting", "failed"].includes(inst.status)) {
    return res.json({ ok: true, instance: pubInstance(inst) });
  }
  let cur = inst;
  try { cur = await svc.setInstanceStatus(cur, "stopping"); } catch { /* already terminal */ }
  await destroyInstance(cur);
  cur = await svc.setInstanceStatus(cur, "stopped").catch(() => cur);
  cur = await svc.forceInstanceState(cur.id, { status: "stopped", provider_reference: "", network_name: "", target_ip: "", host_endpoint: "", stopped_at: new Date().toISOString() });
  log("lab.stop", { user: req.user.id, lab: lab.id });
  res.json({ ok: true, instance: pubInstance(cur), progress: await svc.labProgress(req.user.id, lab.id) });
}));

labApi.post("/labs/:id/reset", ah(async (req, res) => {
  const lab = await resolveLab(req.params.id);
  if (!lab) return res.status(404).json({ error: "Lab not found." });
  const inst = await svc.activeInstance(req.user.id, lab.id);
  if (!inst || !ownOrAdmin(req, inst)) return res.status(404).json({ error: "Start the lab before resetting it." });
  if (inst.status !== "running") return res.status(409).json({ error: `Cannot reset while ${inst.status}.` });
  let cur = await svc.setInstanceStatus(inst, "resetting");
  await destroyInstance(cur);
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

labApi.post("/labs/:id/terminal", ah(async (req, res) => {
  const lab = await resolveLab(req.params.id);
  if (!lab) return res.status(404).json({ error: "Lab not found." });
  const inst = await svc.activeInstance(req.user.id, lab.id);
  if (!inst || !ownOrAdmin(req, inst)) return res.status(409).json({ error: "Start the lab to use the terminal." });
  if (inst.status !== "running") return res.status(409).json({ error: `Terminal unavailable while ${inst.status}.` });
  const r = await runTerminalCommand(inst, req.body?.command);
  res.json({ ok: true, ...r });
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
  log("lab.admin.stop", { by: req.user.id, instance: inst.id });
  res.json({ ok: true, instance: pubInstance(cur) });
}));

export async function labById(id) {
  return get(`SELECT * FROM labs WHERE id=?`, [id]);
}
