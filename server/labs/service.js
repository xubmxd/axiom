// Lab service: runtime state + progress over the declarative definitions.
//
// Definitions (labs/*/lab.json) seed immutable metadata. Everything mutable
// — instances, objective progress, submissions, notes, hint views — lives
// here in the database, keyed to the existing users table.
import { all, get, run, uid, nowIso } from "../db.js";
import { coerceValidationType, verifyAnswer, hashAnswer } from "./answers.js";
import { loadAllDefinitions, normalizePlacement } from "./definitions.js";

export const ACTIVE_STATUSES = ["provisioning", "running", "resetting", "stopping"];

const TRANSITIONS = {
  stopped: ["provisioning"],
  provisioning: ["running", "failed", "stopping", "stopped"],
  running: ["resetting", "stopping", "failed"],
  resetting: ["running", "failed", "stopping"],
  stopping: ["stopped", "failed"],
  failed: ["provisioning", "stopping", "stopped"],
};

export function canTransition(from, to) {
  return (TRANSITIONS[from] || []).includes(to);
}

// ---------- seeding ----------
export async function seedFromDefinitions(root) {
  const loaded = loadAllDefinitions(root);
  const now = nowIso();
  for (const { def, file } of loaded) {
    const place = normalizePlacement(def);
    // Training path: auto-created from the definition on first sight.
    // Definitions own the slug; titles follow definitions on seed.
    let course = await get(`SELECT * FROM lab_courses WHERE slug=?`, [place.courseSlug]);
    if (!course) {
      await run(`INSERT INTO lab_courses(id, slug, title, subtitle, description, sort_order, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?)`,
        [uid("lc"), place.courseSlug, place.courseTitle, place.courseSubtitle, "", 0, now, now]);
      course = await get(`SELECT * FROM lab_courses WHERE slug=?`, [place.courseSlug]);
    } else {
      await run(`UPDATE lab_courses SET title=?, subtitle=?, updated_at=? WHERE id=?`,
        [place.courseTitle, place.courseSubtitle, now, course.id]);
    }
    let lab = await get(`SELECT * FROM labs WHERE slug=?`, [def.slug]);
    const tags = JSON.stringify(def.tags || []);
    if (!lab) {
      lab = { id: uid("lab") };
      await run(
        `INSERT INTO labs(id, slug, title, description, course_id, module_number, module_name, section_number, section_name, lab_number, difficulty, environment_type, status, tags, definition_path, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [lab.id, def.slug, def.title, def.description || "", course.id, place.moduleNumber, place.moduleTitle, place.section, place.sectionTitle, def.labNumber || 0,
          def.difficulty || "Easy", def.environment?.type || "single-target", def.status || "active", tags, file, now, now]
      );
      lab = await get(`SELECT * FROM labs WHERE slug=?`, [def.slug]);
    } else {
      await run(
        `UPDATE labs SET title=?, description=?, course_id=?, module_number=?, module_name=?, section_number=?, section_name=?, lab_number=?, difficulty=?, environment_type=?, status=?, tags=?, definition_path=?, updated_at=? WHERE id=?`,
        [def.title, def.description || "", course.id, place.moduleNumber, place.moduleTitle, place.section, place.sectionTitle, def.labNumber || 0,
          def.difficulty || "Easy", def.environment?.type || "single-target", def.status || "active", tags, file, now, lab.id]
      );
    }
    // targets: reconcile by name
    const seenTargets = new Set();
    for (const t of def.targets || []) {
      seenTargets.add(t.name);
      const ex = await get(`SELECT * FROM lab_targets WHERE lab_id=? AND name=?`, [lab.id, t.name]);
      const ports = JSON.stringify(t.ports || (t.type === "whois-server" ? [43] : []));
      // Optional `build` on a target names its docker build context relative
      // to lab-images/ (used by boot-time image warmup + on-demand builds).
      const meta = JSON.stringify({ ...(t.metadata || {}), ...(t.build ? { build: t.build } : {}) });
      if (!ex) {
        await run(`INSERT INTO lab_targets(id, lab_id, name, hostname, target_type, os, image_reference, network_role, service_ports, metadata_json, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
          [uid("lt"), lab.id, t.name, t.hostname || "", t.type || "generic", t.os || "Linux",
            t.image || def.environment?.image || "", t.networkRole || "target", ports, meta, now, now]);
      } else {
        await run(`UPDATE lab_targets SET hostname=?, target_type=?, os=?, image_reference=?, network_role=?, service_ports=?, metadata_json=?, updated_at=? WHERE id=?`,
          [t.hostname || "", t.type || "generic", t.os || "Linux", t.image || def.environment?.image || "",
            t.networkRole || "target", ports, meta, now, ex.id]);
      }
    }
    for (const old of await all(`SELECT * FROM lab_targets WHERE lab_id=?`, [lab.id])) {
      if (!seenTargets.has(old.name)) await run(`DELETE FROM lab_targets WHERE id=?`, [old.id]);
    }
    // objectives: reconcile by key
    const seenObj = new Set();
    let pos = 0;
    for (const o of def.objectives || []) {
      pos++;
      seenObj.add(o.key);
      const ex = await get(`SELECT * FROM lab_objectives WHERE lab_id=? AND objective_key=?`, [lab.id, o.key]);
      if (!ex) {
        await run(`INSERT INTO lab_objectives(id, lab_id, position, objective_key, title, description, objective_type, validation_type, expected_value_hash, created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
          [uid("lo"), lab.id, pos, o.key, o.title || "", o.description || "", o.type || "question", coerceValidationType(o.validation), o.expectedHash, now]);
      } else {
        await run(`UPDATE lab_objectives SET position=?, title=?, description=?, objective_type=?, validation_type=?, expected_value_hash=? WHERE id=?`,
          [pos, o.title || "", o.description || "", o.type || "question", coerceValidationType(o.validation), o.expectedHash, ex.id]);
      }
    }
    for (const old of await all(`SELECT * FROM lab_objectives WHERE lab_id=?`, [lab.id])) {
      if (!seenObj.has(old.objective_key)) await run(`DELETE FROM lab_objectives WHERE id=?`, [old.id]);
    }
    // hints: reconcile by position
    await run(`DELETE FROM lab_hints WHERE lab_id=?`, [lab.id]);
    let hpos = 0;
    for (const h of def.hints || []) {
      hpos++;
      await run(`INSERT INTO lab_hints(id, lab_id, position, title, body, is_enabled, created_at) VALUES(?,?,?,?,?,?,?)`,
        [uid("lh"), lab.id, hpos, h.title || `Hint ${hpos}`, h.body || "", h.enabled === false ? 0 : 1, now]);
    }
  }
  return { labs: loaded.length, courses: (await all(`SELECT id FROM lab_courses`)).length };
}

// ---------- training paths (catalog layer; the lab engine stays generic) ----------
export async function listLabCourses() {
  return all(`SELECT * FROM lab_courses ORDER BY sort_order ASC, title ASC`);
}

export async function getLabCourse(slug) {
  return get(`SELECT * FROM lab_courses WHERE slug=?`, [slug]);
}

export async function labsByCourse(courseId) {
  return all(`SELECT * FROM labs WHERE course_id=? AND status='active' ORDER BY module_number ASC, section_number ASC, lab_number ASC`, [courseId]);
}

// Lab display state: Completed > Running (live instance) > In progress > Not started.
// Running strictly reflects an actual active instance — never past completion.
export async function labState(userId, lab) {
  const progress = await labProgress(userId, lab.id);
  const inst = await activeInstance(userId, lab.id);
  const running = !!inst && ["provisioning", "running", "resetting"].includes(inst.status);
  const state = progress.complete ? "completed" : running ? "running" : progress.started ? "in-progress" : "not-started";
  return { progress, instance: inst, running, state };
}

// Course → modules → sections → labs, all driven by lab rows. No duplicate
// module records: modules are (course, number) groupings with the title
// carried on each lab row.
export async function courseStructure(userId, courseId) {
  const labs = await labsByCourse(courseId);
  const modules = new Map();
  for (const lab of labs) {
    const key = lab.module_number || 0;
    if (!modules.has(key)) modules.set(key, { number: key, title: lab.module_name || "", sections: new Map() });
    const mod = modules.get(key);
    if (!mod.title && lab.module_name) mod.title = lab.module_name;
    const skey = lab.section_number || lab.slug;
    if (!mod.sections.has(skey)) {
      mod.sections.set(skey, { section: lab.section_number || "", title: lab.section_name || lab.title, labs: [] });
    }
    const sec = mod.sections.get(skey);
    if (!sec.title && (lab.section_name || lab.title)) sec.title = lab.section_name || lab.title;
    sec.labs.push({ lab, ...(await labState(userId, lab)) });
  }
  const out = [...modules.values()]
    .sort((a, b) => a.number - b.number)
    .map((m) => ({ ...m, sections: [...m.sections.values()] }));
  for (const m of out) {
    let done = 0, total = 0;
    for (const s of m.sections) for (const l of s.labs) { total++; if (l.progress.complete) done++; }
    m.total = total; m.completed = done;
    m.pct = total ? Math.round((done / total) * 100) : 0;
  }
  return out;
}

export async function courseProgress(userId, courseId) {
  const labs = await labsByCourse(courseId);
  let completed = 0, inProgress = 0, running = 0;
  for (const lab of labs) {
    const { state } = await labState(userId, lab);
    if (state === "completed") completed++;
    else if (state === "running") { inProgress++; running++; }
    else if (state === "in-progress") inProgress++;
  }
  const total = labs.length;
  return {
    total, completed, inProgress, running,
    notStarted: total - completed - inProgress,
    pct: total ? Math.round((completed / total) * 100) : 0,
  };
}

// ---------- reads ----------
export async function listLabs() {
  return all(`SELECT * FROM labs WHERE status='active' ORDER BY module_number ASC, section_number ASC, lab_number ASC`);
}

export async function getLab(where, value) {
  const col = where === "id" ? "id" : "slug";
  return get(`SELECT * FROM labs WHERE ${col}=?`, [value]);
}

export async function labTargets(labId) {
  return all(`SELECT * FROM lab_targets WHERE lab_id=? ORDER BY name ASC`, [labId]);
}

export async function labObjectives(labId) {
  return all(`SELECT id, lab_id, position, objective_key, title, description, objective_type, validation_type FROM lab_objectives WHERE lab_id=? ORDER BY position ASC`, [labId]);
}

export async function labHints(labId) {
  return all(`SELECT id, lab_id, position, title, body, is_enabled FROM lab_hints WHERE lab_id=? AND is_enabled=1 ORDER BY position ASC`, [labId]);
}

export async function activeInstance(userId, labId) {
  const ph = ACTIVE_STATUSES.map(() => "?").join(",");
  return get(`SELECT * FROM lab_instances WHERE user_id=? AND lab_id=? AND status IN (${ph}) ORDER BY updated_at DESC LIMIT 1`,
    [userId, labId, ...ACTIVE_STATUSES]);
}

export async function latestInstance(userId, labId) {
  return get(`SELECT * FROM lab_instances WHERE user_id=? AND lab_id=? ORDER BY created_at DESC LIMIT 1`, [userId, labId]);
}

export async function getInstance(id) {
  return get(`SELECT * FROM lab_instances WHERE id=?`, [id]);
}

// ---------- lifecycle writes ----------
export async function createInstance({ userId, labId, provider }) {
  const now = nowIso();
  const id = uid("li");
  await run(`INSERT INTO lab_instances(id, lab_id, user_id, status, provider, provider_reference, started_at, created_at, updated_at) VALUES(?,?,?,?,?,?,?, ?,?)`,
    [id, labId, userId, "provisioning", provider, "", now, now, now]);
  return getInstance(id);
}

export async function setInstanceStatus(inst, to, extra = {}) {
  if (!canTransition(inst.status, to)) throw new Error(`Illegal lab state transition ${inst.status} → ${to}`);
  const now = nowIso();
  const next = {
    status: to,
    provider_reference: extra.providerReference ?? inst.provider_reference,
    network_name: extra.networkName ?? inst.network_name,
    network_cidr: extra.networkCidr ?? inst.network_cidr,
    target_ip: extra.targetIp ?? inst.target_ip,
    target_port: extra.targetPort ?? inst.target_port,
    host_endpoint: extra.hostEndpoint ?? inst.host_endpoint,
    error: extra.error ?? (to === "failed" ? inst.error : ""),
    reset_count: extra.resetCount ?? inst.reset_count,
    started_at: extra.startedAt ?? inst.started_at,
    stopped_at: to === "stopped" ? now : (extra.stoppedAt ?? inst.stopped_at),
    expires_at: extra.expiresAt ?? inst.expires_at,
    updated_at: now,
  };
  await run(`UPDATE lab_instances SET status=?, provider_reference=?, network_name=?, network_cidr=?, target_ip=?, target_port=?, host_endpoint=?, error=?, reset_count=?, started_at=?, stopped_at=?, expires_at=?, updated_at=? WHERE id=?`,
    [next.status, next.provider_reference, next.network_name, next.network_cidr, next.target_ip, next.target_port,
      next.host_endpoint, next.error, next.reset_count, next.started_at, next.stopped_at, next.expires_at, now, inst.id]);
  return getInstance(inst.id);
}

// Force-write for cleanup paths (orchestrator crash recovery): bypasses the
// transition guard, used only when reconciling with provider reality.
export async function forceInstanceState(id, patch) {
  const inst = await getInstance(id);
  if (!inst) return null;
  const now = nowIso();
  const cols = [];
  const vals = [];
  for (const [k, v] of Object.entries(patch)) {
    if (!["status", "provider_reference", "network_name", "network_cidr", "target_ip", "target_port", "host_endpoint", "error", "reset_count", "started_at", "stopped_at", "expires_at"].includes(k)) continue;
    cols.push(`${k}=?`);
    vals.push(v);
  }
  cols.push("updated_at=?");
  vals.push(now, id);
  await run(`UPDATE lab_instances SET ${cols.join(", ")} WHERE id=?`, vals);
  return getInstance(id);
}

// ---------- submissions ----------
export async function submitAnswer({ userId, lab, objectiveKey, answer, instanceId = "" }) {
  const objective = await get(`SELECT * FROM lab_objectives WHERE lab_id=? AND objective_key=?`, [lab.id, objectiveKey]);
  if (!objective) return { ok: false, error: "Unknown objective." };
  const now = nowIso();
  const correct = verifyAnswer(answer, objective.expected_value_hash, objective.validation_type);
  // Idempotent: an already-completed objective stays completed without a
  // duplicate "completed" event, but the attempt is still recorded.
  const prior = await get(`SELECT * FROM lab_objective_progress WHERE user_id=? AND lab_id=? AND objective_id=?`,
    [userId, lab.id, objective.id]);
  await run(`INSERT INTO lab_submissions(id, user_id, lab_id, instance_id, objective_id, answer_hash, is_correct, attempted_at) VALUES(?,?,?,?,?,?,?,?)`,
    [uid("ls"), userId, lab.id, instanceId, objective.id, hashAnswer(answer, objective.validation_type), correct ? 1 : 0, now]);
  if (correct && !prior?.completed) {
    if (!prior) {
      await run(`INSERT INTO lab_objective_progress(user_id, lab_id, instance_id, objective_id, completed, completed_at, updated_at) VALUES(?,?,?,?,?,?,?)`,
        [userId, lab.id, instanceId, objective.id, 1, now, now]);
    } else {
      await run(`UPDATE lab_objective_progress SET completed=1, completed_at=?, instance_id=?, updated_at=? WHERE user_id=? AND lab_id=? AND objective_id=?`,
        [now, instanceId, now, userId, lab.id, objective.id]);
    }
    return { ok: true, correct: true, completed: true };
  }
  return { ok: true, correct, completed: !!prior?.completed };
}

// ---------- progress ----------
export async function labProgress(userId, labId) {
  const objectives = await all(`SELECT * FROM lab_objectives WHERE lab_id=? ORDER BY position ASC`, [labId]);
  const done = await all(`SELECT objective_id FROM lab_objective_progress WHERE user_id=? AND lab_id=? AND completed=1`, [userId, labId]);
  const doneSet = new Set(done.map((d) => d.objective_id));
  const items = objectives.map((o) => ({ key: o.objective_key, title: o.title, description: o.description, completed: doneSet.has(o.id) }));
  const instance = await activeInstance(userId, labId);
  const started = !!(instance || await latestInstance(userId, labId));
  const total = items.length;
  const doneCount = items.filter((i) => i.completed).length;
  // "Start the lab" counts as the first checklist item in the UI.
  const stepsTotal = total + 1;
  const stepsDone = doneCount + (started ? 1 : 0);
  return {
    objectives: items,
    total: stepsTotal, done: stepsDone,
    objectiveTotal: total, objectiveDone: doneCount,
    started,
    complete: total > 0 && doneCount >= total,
    pct: stepsTotal ? Math.round((stepsDone / stepsTotal) * 100) : 0,
  };
}

export async function moduleProgress(userId, courseId, moduleNumber) {
  const labs = await all(`SELECT * FROM labs WHERE course_id=? AND module_number=? AND status='active'`, [courseId, moduleNumber]);
  let completed = 0;
  for (const l of labs) {
    const p = await labProgress(userId, l.id);
    if (p.complete) completed++;
  }
  return { total: labs.length, completed };
}

// ---------- notes ----------
export async function getNotes(userId, labId) {
  return get(`SELECT * FROM lab_notes WHERE user_id=? AND lab_id=? ORDER BY updated_at DESC LIMIT 1`, [userId, labId]);
}

export async function saveNotes(userId, labId, instanceId, body) {
  const now = nowIso();
  const ex = await get(`SELECT * FROM lab_notes WHERE user_id=? AND lab_id=? ORDER BY updated_at DESC LIMIT 1`, [userId, labId]);
  const text = String(body ?? "").slice(0, 100_000);
  if (!ex) {
    await run(`INSERT INTO lab_notes(id, user_id, lab_id, instance_id, body, created_at, updated_at) VALUES(?,?,?,?,?,?,?)`,
      [uid("ln"), userId, labId, instanceId || "", text, now, now]);
  } else {
    await run(`UPDATE lab_notes SET body=?, instance_id=?, updated_at=? WHERE id=?`, [text, instanceId || ex.instance_id, now, ex.id]);
  }
  return getNotes(userId, labId);
}

// ---------- hints ----------
export async function hintsFor(userId, labId) {
  const hints = await labHints(labId);
  const views = await all(`SELECT hint_id FROM lab_hint_views WHERE user_id=? AND lab_id=?`, [userId, labId]);
  const seen = new Set(views.map((v) => v.hint_id));
  return hints.map((h) => ({ id: h.id, position: h.position, title: h.title, revealed: seen.has(h.id), body: seen.has(h.id) ? h.body : null }));
}

export async function revealHint(userId, labId, hintId) {
  const hint = await get(`SELECT * FROM lab_hints WHERE id=? AND lab_id=? AND is_enabled=1`, [hintId, labId]);
  if (!hint) return null;
  const ex = await get(`SELECT * FROM lab_hint_views WHERE user_id=? AND lab_id=? AND hint_id=?`, [userId, labId, hintId]);
  if (!ex) await run(`INSERT INTO lab_hint_views(user_id, lab_id, hint_id, revealed_at) VALUES(?,?,?,?)`, [userId, labId, hintId, nowIso()]);
  return hint;
}

// ---------- admin ----------
export async function allActiveInstances() {
  const ph = ACTIVE_STATUSES.map(() => "?").join(",");
  return all(`SELECT li.*, l.slug lab_slug, l.title lab_title, lc.slug lab_course_slug, u.username FROM lab_instances li JOIN labs l ON l.id=li.lab_id LEFT JOIN lab_courses lc ON lc.id=l.course_id JOIN users u ON u.id=li.user_id WHERE li.status IN (${ph}) ORDER BY li.updated_at DESC`, [...ACTIVE_STATUSES]);
}
