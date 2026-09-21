// Declarative lab definitions: labs/<anything>/lab.json.
//
// The definition describes the environment (targets, objectives as hashes,
// hints, UI copy) AND its catalog placement: course, module, section.
// The database stores mutable runtime state (instances, progress,
// submissions). Definitions are the seed source of truth for immutable lab
// metadata — never for per-user runtime data.
//
// A future lab is added by dropping in a new lab.json (+ target build files)
// and restarting; no route changes required.
import fs from "node:fs";
import path from "node:path";

export function labsRoot(base = process.cwd()) {
  return path.join(base, "labs");
}

export function discoverDefinitionFiles(root = labsRoot()) {
  const out = [];
  const walk = (dir) => {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (e.name.startsWith(".")) continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) walk(full);
      else if (e.isFile() && e.name === "lab.json") out.push(full);
    }
  };
  walk(root);
  return out.sort();
}

export function loadDefinition(file) {
  const raw = fs.readFileSync(file, "utf8");
  const def = JSON.parse(raw);
  const problems = validateDefinition(def);
  if (problems.length) throw new Error(`Invalid lab definition ${file}: ${problems.join("; ")}`);
  return { def, file };
}

export function loadAllDefinitions(root = labsRoot()) {
  return discoverDefinitionFiles(root).map(loadDefinition);
}

export function validateDefinition(def) {
  const problems = [];
  if (!def || typeof def !== "object") return ["definition must be an object"];
  if (!def.slug || typeof def.slug !== "string") problems.push("slug is required");
  else if (!/^[a-z0-9][a-z0-9-]*$/.test(def.slug)) problems.push("slug must be lowercase alphanumeric + dashes");
  if (!def.title) problems.push("title is required");
  const norm = normalizePlacement(def);
  if (!norm.courseSlug) problems.push("course.slug is required (a lab must belong to a training path)");
  else if (!/^[a-z0-9][a-z0-9-]*$/.test(norm.courseSlug)) problems.push("course.slug must be lowercase alphanumeric + dashes");
  if (!Array.isArray(def.targets) || !def.targets.length) problems.push("at least one target is required");
  for (const t of def.targets || []) {
    if (!t.name) problems.push("each target needs a name");
  }
  if (!Array.isArray(def.objectives) || !def.objectives.length) problems.push("at least one objective is required");
  for (const o of def.objectives || []) {
    if (!o.key) problems.push("each objective needs a key");
    if (!o.expectedHash || !/^[0-9a-f]{64}$/.test(o.expectedHash)) problems.push(`objective ${o.key || "?"} needs a 64-char hex expectedHash`);
  }
  return problems;
}

// Catalog placement: explicit course/module/section identity. The nested
// shape is canonical; the original flat keys (moduleNumber/moduleName,
// section) are still accepted and mapped so older definitions keep working.
export function normalizePlacement(def) {
  const course = def.course && typeof def.course === "object" ? def.course : {};
  const module = def.module && typeof def.module === "object" ? def.module : {};
  const courseSlug = course.slug || def.courseSlug || "";
  const courseTitle = course.title || def.courseTitle || courseSlug.toUpperCase();
  const courseSubtitle = course.subtitle || def.courseSubtitle || "";
  const moduleNumber = Number(module.number ?? def.moduleNumber ?? 0) || 0;
  const moduleTitle = module.title || def.moduleName || "";
  const section = String(def.section || "");
  const sectionTitle = def.sectionTitle || def.sectionName || "";
  return { courseSlug, courseTitle, courseSubtitle, moduleNumber, moduleTitle, section, sectionTitle };
}
