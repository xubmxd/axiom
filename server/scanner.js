import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { config } from "./config.js";
import { all, get, run, uid, nowIso } from "./db.js";
import { log } from "./log.js";
import { extractTitle, countWords } from "./sanitize.js";

export const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });
export const natSort = (a, b) => collator.compare(a, b);

// ---- file classification ----
// Videos become lessons, HTML becomes reading content, known supplementary
// formats become resources. Unknown extensions are skipped (never lessons),
// so a folder of stray files can't pollute the library.
const VIDEO_EXT = new Set([".mp4", ".m4v", ".webm", ".mkv", ".mov"]);
const HTML_EXT = new Set([".html", ".htm"]);
const SUBTITLE_EXT = new Set([".srt", ".vtt"]);
const TEXT_EXT = new Set([".txt", ".md", ".markdown", ".csv", ".tsv", ".json", ".xml", ".yml", ".yaml"]);
const DOC_EXT = new Set([".pdf", ".epub"]);
const IMAGE_EXT = new Set([".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg", ".avif", ".bmp", ".jfif", ".ico", ".tif", ".tiff"]);
const ARCHIVE_EXT = new Set([".zip", ".rar", ".7z", ".tar", ".gz"]);
const CODE_EXT = new Set([".py", ".js", ".ts", ".sh", ".java", ".c", ".cpp", ".go", ".rs", ".sql", ".ps1"]);
const RESOURCE_EXT = new Set([...SUBTITLE_EXT, ...TEXT_EXT, ...DOC_EXT, ...IMAGE_EXT, ...ARCHIVE_EXT, ...CODE_EXT]);

export function classifyFile(name) {
  const base = String(name || "");
  if (!base || base.startsWith(".")) return "ignore";
  if (/^icon\./i.test(base)) return "icon";
  if (/^(thumbs\.db|desktop\.ini|\.ds_store)$/i.test(base)) return "ignore";
  // Release-stub junk bundled with downloaded courses: never course content.
  // Credits.txt is a promo/thanks stub (not a real reading page) and .url
  // files are Windows shortcut stubs. Ignored by exact name / extension so
  // legitimate lookalikes (e.g. "Course Credits.txt") still index normally.
  if (base.toLowerCase() === "credits.txt") return "ignore";
  const ext = path.extname(base).toLowerCase();
  if (ext === ".url") return "ignore";
  if (VIDEO_EXT.has(ext)) return "video";
  if (HTML_EXT.has(ext)) return "html";
  if (RESOURCE_EXT.has(ext)) return "resource";
  return "skip";
}

export function resourceKind(fileName) {
  const ext = path.extname(String(fileName || "")).toLowerCase();
  if (SUBTITLE_EXT.has(ext)) return "subtitle";
  if (TEXT_EXT.has(ext)) return "text";
  if (DOC_EXT.has(ext)) return "document";
  if (IMAGE_EXT.has(ext)) return "image";
  if (ARCHIVE_EXT.has(ext)) return "archive";
  if (CODE_EXT.has(ext)) return "code";
  return "other";
}

// basename without extension, normalized for companion matching
// ("1. Project #1.mp4" <-> "1. Project #1.txt")
export function companionKey(fileName) {
  return path.basename(String(fileName || ""), path.extname(String(fileName || ""))).toLowerCase().trim();
}

function slugify(name) {
  return name.toLowerCase().trim().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 80) || "course";
}
// Removes configured tag substrings (TITLE_STRIP) from a raw file/folder
// name BEFORE pretty-printing, so "Course - [TAG]" displays as "Course".
// Literal match, all occurrences. On-disk names, slugs and
// path_keys are never touched — this is display-only, which also keeps it
// working on read-only library mounts where renaming files would fail.
export function stripTitleTags(name) {
  let out = String(name || "");
  for (const tag of config.titleStrip || []) {
    if (tag) out = out.split(tag).join("");
  }
  return out;
}
function prettyTitle(name) {
  return stripTitleTags(name).replace(/[_-]+/g, " ").replace(/\s+/g, " ").trim() || String(name || "");
}
// Display title = original filename without extension. Numeric prefixes
// ("1.1.1. Whois Enumeration") are meaningful ordering metadata and must be
// preserved verbatim — only the extension is removed.
function lessonTitle(fileName) {
  const base = path.basename(String(fileName || ""), path.extname(String(fileName || "")));
  const t = prettyTitle(base);
  return t || String(fileName || "");
}

// ---- phase 1: pure filesystem walk (no DB) ----
// Every directory level and every file list is naturally ordered.
// Traversal is confined to the course root: symlinks resolving outside the
// root are skipped, as are non-regular files (fifos, sockets, devices).
// rootReal is the canonical course-root path; recursion threads it through
// so nested symlink checks share one identity (no per-entry realpath of root).
async function buildFileTree(absDir, rootReal = null) {
  if (!rootReal) rootReal = await fsp.realpath(absDir).catch(() => absDir);
  const node = { videos: [], pages: [], resources: [], children: [], icon: null };
  const entries = await fsp.readdir(absDir, { withFileTypes: true }).catch(() => []);
  for (const e of entries) {
    if (e.name.startsWith(".")) continue;
    const full = path.join(absDir, e.name);
    let lst;
    try { lst = await fsp.lstat(full); } catch { continue; }
    let isDir = false, isFile = false, size = 0;
    if (lst.isSymbolicLink()) {
      let real;
      try { real = await fsp.realpath(full); } catch { continue; }
      if (real !== rootReal && !real.startsWith(rootReal + path.sep)) continue; // escape → skip
      let rst;
      try { rst = await fsp.stat(full); } catch { continue; }
      if (rst.isDirectory()) isDir = true;
      else if (rst.isFile()) { isFile = true; size = rst.size || 0; }
      else continue;
    } else if (lst.isDirectory()) {
      isDir = true;
    } else if (lst.isFile()) {
      isFile = true; size = lst.size || 0;
    } else {
      continue; // fifo, socket, device, …
    }
    if (isDir) {
      const child = await buildFileTree(full, rootReal);
      child.name = e.name;
      node.children.push(child);
    } else if (isFile) {
      const cls = classifyFile(e.name);
      if (cls === "icon") {
        if (!node.icon) node.icon = e.name;
      } else if (cls === "video" || cls === "html" || cls === "resource") {
        const item = { name: e.name, size };
        if (cls === "video") node.videos.push(item);
        else if (cls === "html") node.pages.push(item);
        else node.resources.push(item);
      }
    }
  }
  node.videos.sort((a, b) => natSort(a.name, b.name));
  node.pages.sort((a, b) => natSort(a.name, b.name));
  node.resources.sort((a, b) => natSort(a.name, b.name));
  node.children.sort((a, b) => natSort(a.name, b.name));
  return node;
}

function subtreeHasContent(node) {
  if (node.videos.length || node.pages.length || node.resources.length) return true;
  return node.children.some(subtreeHasContent);
}

// course-relative posix paths of everything on disk (same membership rule the
// persist pass uses for group creation)
function collectRelPaths(tree) {
  const groups = new Set(), lessons = new Set(), pages = new Set(), resources = new Set();
  (function walk(node, relDir) {
    if (relDir !== "" && subtreeHasContent(node)) groups.add(relDir);
    for (const v of node.videos) lessons.add(relDir ? `${relDir}/${v.name}` : v.name);
    for (const p of node.pages) pages.add(relDir ? `${relDir}/${p.name}` : p.name);
    for (const r of node.resources) resources.add(relDir ? `${relDir}/${r.name}` : r.name);
    for (const c of node.children) walk(c, relDir ? `${relDir}/${c.name}` : c.name);
  })(tree, "");
  return { groups, lessons, pages, resources };
}

// ---- multiple course libraries ----
// Every root is a library directory managed from the admin panel
// (course_roots table); COURSES_ROOT env only seeds the default row.
// Two layouts are accepted per root and auto-detected on every scan:
//   structured: <root>/video/<course> + <root>/reading/<course>
//   flat:       <root>/<course>  (kind inferred from content)
// courses.dir_prefix records which layout a course was found in ("video",
// "reading", or "" for flat) so path resolution stays exact.
export function normalizeRootPath(p) {
  return path.resolve(String(p || "").trim());
}

function isDir(p) {
  try { return fs.statSync(p).isDirectory(); } catch { return false; }
}

export async function listCourseRoots(includeInactive = false) {
  try {
    const rows = await all(
      `SELECT * FROM course_roots ${includeInactive ? "" : "WHERE is_active=1"} ORDER BY created_at ASC`
    );
    if (rows?.length) return rows;
  } catch { /* table may not exist yet during early migrate */ }
  return [{ id: "root_default", path: path.resolve(config.coursesRoot || "courses"), label: "Default library", is_active: 1 }];
}

// Shared validation for the admin API: returns an error string or null.
// NOTE: the path is checked from inside the app process — under Docker that
// means inside the container, not on the host. The message says so.
export function validateRootPath(candidate, existingRoots = []) {
  const raw = String(candidate || "").trim();
  if (!raw) return "Path is required.";
  if (/\0/.test(raw)) return "Invalid path.";
  const norm = normalizeRootPath(raw);
  let stat = null;
  try { stat = fs.statSync(norm); } catch { return `Directory does not exist (checked inside the app container): ${norm}. If Axiom runs in Docker, mount the host directory into the container first, then add the container path.`; }
  if (!stat.isDirectory()) return `Not a directory: ${norm}`;
  const dataDir = path.resolve(config.dataDir || "data");
  if (norm === dataDir || norm.startsWith(dataDir + path.sep) || dataDir.startsWith(norm + path.sep)) {
    return "That path overlaps the app data directory — pick a directory outside DATA_DIR.";
  }
  for (const r of existingRoots) {
    const other = normalizeRootPath(r.path || "");
    if (!other) continue;
    if (norm === other) return "That directory is already added.";
    if (norm.startsWith(other + path.sep) || other.startsWith(norm + path.sep)) {
      return `That directory overlaps an existing library (${other}) — nested libraries would scan courses twice.`;
    }
  }
  return null;
}

export async function scanAll(manual = false) {
  const started = Date.now();
  await run(`UPDATE scan_state SET last_status='running', last_error='' WHERE id=1`);
  try {
    const roots = (await listCourseRoots(false)).map((r) => ({
      ...r,
      path: normalizeRootPath(r.path || config.coursesRoot),
    }));
    // de-dupe by resolved path (DB + env drift)
    const uniq = [];
    const seenPaths = new Set();
    for (const r of roots) {
      if (seenPaths.has(r.path)) continue;
      seenPaths.add(r.path);
      uniq.push(r);
    }
    const seen = new Set();
    const enabledIds = new Set(uniq.map((r) => r.id));
    const defaultPath = normalizeRootPath(config.coursesRoot || "courses");
    let courseCount = 0;
    const errors = [];
    const scanOne = async (kind, coursePath, name, root, prefix) => {
      try {
        const finalKind = await scanCourse(kind, coursePath, name, root, prefix);
        seen.add(`${root.id}:${finalKind}:${slugify(name)}`);
        courseCount++;
      } catch (e) {
        errors.push(`${name}: ${String(e?.message || e).slice(0, 200)}`);
      }
    };
    for (const root of uniq) {
      // The default library keeps the guided layout: its video/ + reading/
      // folders are created on first boot. Extra libraries are never
      // modified — a read-only external drive must scan as-is, so directory
      // creation there is best-effort and failures never skip the root.
      const isDefault = root.id === "root_default" || root.path === defaultPath;
      if (isDefault) {
        try {
          fs.mkdirSync(root.path, { recursive: true });
          for (const sub of ["video", "reading"]) fs.mkdirSync(path.join(root.path, sub), { recursive: true });
        } catch (e) {
          const msg = `Cannot access ${root.path}: ${String(e?.message || e).slice(0, 200)}`;
          errors.push(msg);
          try { await run(`UPDATE course_roots SET last_error=?, updated_at=? WHERE id=?`, [msg.slice(0, 500), nowIso(), root.id]); } catch {}
          continue;
        }
      } else if (!isDir(root.path)) {
        const msg = `Library missing: ${root.path} (was it unmounted?)`;
        errors.push(msg);
        try { await run(`UPDATE course_roots SET last_error=?, updated_at=? WHERE id=?`, [msg.slice(0, 500), nowIso(), root.id]); } catch {}
        continue;
      }
      const kinds = ["video", "reading"].filter((k) => isDir(path.join(root.path, k)));
      if (kinds.length) {
        // structured layout: <root>/video/<course>, <root>/reading/<course>
        for (const kind of kinds) {
          const kindDir = path.join(root.path, kind);
          const dirs = await fsp.readdir(kindDir, { withFileTypes: true }).catch(() => []);
          const names = dirs.filter((d) => d.isDirectory() && !d.name.startsWith(".")).map((d) => d.name).sort(natSort);
          for (const name of names) await scanOne(kind, path.join(kindDir, name), name, root, kind);
        }
      } else if (!isDefault) {
        // flat layout: course folders directly under the root (kind inferred
        // from content). Only for extra libraries — the default keeps its
        // guided video//reading/ structure.
        const dirs = await fsp.readdir(root.path, { withFileTypes: true }).catch(() => []);
        const names = dirs.filter((d) => d.isDirectory() && !d.name.startsWith(".")).map((d) => d.name).sort(natSort);
        for (const name of names) await scanOne("video", path.join(root.path, name), name, root, "");
      }
      try { await run(`UPDATE course_roots SET last_error=?, updated_at=? WHERE id=?`, ["", nowIso(), root.id]); } catch {}
    }
    // remove courses no longer on disk — but ONLY for roots we just scanned.
    // Courses from disabled roots are left untouched so disabling a library
    // hides nothing and deletes nothing; re-enabling restores it as-is.
    const existing = await all(`SELECT * FROM courses`);
    for (const c of existing) {
      const rid = c.root_id || "root_default";
      if (!enabledIds.has(rid)) continue;
      if (!seen.has(`${rid}:${c.kind}:${c.slug}`)) {
        await run(`DELETE FROM courses WHERE id=?`, [c.id]);
        log("course.removed", { course: c.title });
      }
    }
    const okAt = nowIso();
    const errSummary = errors.slice(0, 3).join("; ");
    await run(`UPDATE scan_state SET last_ok_at=?, last_status=?, last_error=?, course_count=? WHERE id=1`,
      [okAt, errors.length ? "ok" : "ok", errSummary.slice(0, 500), courseCount]);
    log("scan.ok", { courses: courseCount, roots: uniq.length, ms: Date.now() - started, manual });
    return { ok: true, courses: courseCount, roots: uniq.length, warnings: errors.slice(0, 5) };
  } catch (err) {
    await run(`UPDATE scan_state SET last_status='error', last_error=? WHERE id=1`, [String(err?.message || err).slice(0, 500)]);
    log("scan.error", { error: String(err?.message || err) });
    return { ok: false, error: String(err?.message || err) };
  }
}

// prefix is the layout segment between the library root and the course
// folder: "video"/"reading" for structured libraries, "" for flat ones
// (course folders directly under the root — kind inferred from content).
// Returns the final kind so the caller can build its seen-key.
async function scanCourse(kindHint, coursePath, dirName, root = null, prefix = null) {
  const now = nowIso();
  const slug = slugify(dirName);
  const title = prettyTitle(dirName);
  const rootId = root?.id || "root_default";
  const rootPath = normalizeRootPath(root?.path || config.coursesRoot);
  const tree = await buildFileTree(coursePath);
  let kind = kindHint, dirPrefix = prefix ?? kindHint;
  if (prefix === "") {
    kind = tree.videos.length ? "video" : "reading";
    dirPrefix = "";
  }
  let course = null;
  try {
    course = await get(`SELECT * FROM courses WHERE root_id=? AND kind=? AND slug=?`, [rootId, kind, slug]);
  } catch { course = null; }
  if (!course) {
    // Adopt pre-multi-root rows (root_id NULL) so progress survives the upgrade.
    try {
      course = await get(`SELECT * FROM courses WHERE kind=? AND slug=? AND (root_id IS NULL OR root_id='')`, [kind, slug]);
    } catch { /* fresh schema: no legacy rows */ }
  }
  const hasIcon = tree.icon ? 1 : 0;
  if (!course) {
    course = { id: uid("c"), kind, title, slug, dir_name: dirName, root_id: rootId, root_path: rootPath, dir_prefix: dirPrefix, has_icon: hasIcon, created_at: now, updated_at: now };
    try {
      await run(`INSERT INTO courses(id, kind, title, slug, dir_name, root_id, root_path, dir_prefix, has_icon, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
        [course.id, kind, title, slug, dirName, rootId, rootPath, dirPrefix, hasIcon, now, now]);
    } catch {
      // Older schema without the new columns (should not happen post-migrate).
      await run(`INSERT INTO courses(id, kind, title, slug, dir_name, has_icon, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?)`,
        [course.id, kind, title, slug, dirName, hasIcon, now, now]);
      course = await get(`SELECT * FROM courses WHERE id=?`, [course.id]);
    }
  } else {
    course.dir_prefix = dirPrefix;
    try {
      await run(`UPDATE courses SET title=?, dir_name=?, has_icon=?, root_id=?, root_path=?, dir_prefix=?, updated_at=? WHERE id=?`,
        [title, dirName, hasIcon, rootId, rootPath, dirPrefix, now, course.id]);
    } catch {
      await run(`UPDATE courses SET title=?, dir_name=?, has_icon=?, updated_at=? WHERE id=?`, [title, dirName, hasIcon, now, course.id]);
    }
    course = await get(`SELECT * FROM courses WHERE id=?`, [course.id]);
  }

  // phase 2: deactivate anything missing from disk FIRST (with fresh
  // timestamps), so the persist pass can re-link moved files to their old
  // ids — progress follows renames instead of being orphaned.
  const onDisk = collectRelPaths(tree);
  for (const g of await all(`SELECT * FROM content_groups WHERE course_id=? AND is_active=1`, [course.id])) {
    if (!onDisk.groups.has(g.path_key)) await run(`UPDATE content_groups SET is_active=0, updated_at=? WHERE id=?`, [now, g.id]);
  }
  for (const l of await all(`SELECT * FROM lessons WHERE course_id=? AND is_active=1`, [course.id])) {
    if (!onDisk.lessons.has(l.path_key)) await run(`UPDATE lessons SET is_active=0, updated_at=? WHERE id=?`, [now, l.id]);
  }
  for (const p of await all(`SELECT * FROM reading_pages WHERE course_id=? AND is_active=1`, [course.id])) {
    if (!onDisk.pages.has(p.path_key)) await run(`UPDATE reading_pages SET is_active=0, updated_at=? WHERE id=?`, [now, p.id]);
  }
  for (const r of await all(`SELECT * FROM resources WHERE course_id=? AND is_active=1`, [course.id])) {
    if (!onDisk.resources.has(r.path_key)) await run(`UPDATE resources SET is_active=0, updated_at=? WHERE id=?`, [now, r.id]);
  }

  // phase 3: persist top-down. Groups are created only for directories that
  // (transitively) contain indexed content — flat courses get no fake groups.
  const ctx = { seenGroups: new Set(), seenLessons: new Set(), seenPages: new Set(), seenResources: new Set(), pagePos: 0 };
  await persistDir(course, tree, "", null, 0, 0, ctx, now);
  const lc = await get(`SELECT COUNT(*) c FROM lessons WHERE course_id=? AND is_active=1`, [course.id]);
  const pc = await get(`SELECT COUNT(*) c FROM reading_pages WHERE course_id=? AND is_active=1`, [course.id]);
  await run(`UPDATE courses SET lesson_count=?, page_count=?, last_scanned_at=?, updated_at=? WHERE id=?`, [lc?.c || 0, pc?.c || 0, now, now, course.id]);
  return kind;
}

// relDir uses posix separators (course-relative). Root call has relDir "" and no group.
async function persistDir(course, node, relDir, parentGroupId, depth, siblingPos, ctx, now) {
  let groupId = null;
  if (relDir !== "") {
    if (!subtreeHasContent(node)) return; // empty branch: no group, no items
    const name = relDir.split("/").pop();
    groupId = await upsertGroup(course.id, relDir, parentGroupId, depth, name, siblingPos, now);
    ctx.seenGroups.add(relDir);
  }
  let lpos = 0;
  for (const v of node.videos) {
    lpos++;
    const rel = relDir ? `${relDir}/${v.name}` : v.name;
    ctx.seenLessons.add(rel);
    await upsertLesson(course.id, groupId, { ...v, rel }, lpos, now);
  }
  for (const p of node.pages) {
    ctx.pagePos++;
    const rel = relDir ? `${relDir}/${p.name}` : p.name;
    ctx.seenPages.add(rel);
    await upsertPage(course, groupId, { ...p, rel }, ctx.pagePos, now);
  }
  // companion matching: map this directory's lessons by companion key
  const dirLessons = await all(`SELECT id, file_name FROM lessons WHERE course_id=? AND ${groupId ? "group_id=?" : "group_id IS NULL"} AND is_active=1`, groupId ? [course.id, groupId] : [course.id]);
  const byKey = new Map();
  for (const l of dirLessons) {
    const k = companionKey(l.file_name);
    if (!byKey.has(k)) byKey.set(k, l.id);
  }
  for (const r of node.resources) {
    const rel = relDir ? `${relDir}/${r.name}` : r.name;
    ctx.seenResources.add(rel);
    await upsertResource(course.id, groupId, byKey.get(companionKey(r.name)) || null, { ...r, rel }, now);
  }
  let gpos = 0;
  for (const child of node.children) {
    gpos++;
    const rel = relDir ? `${relDir}/${child.name}` : child.name;
    await persistDir(course, child, rel, groupId, depth + 1, gpos, ctx, now);
  }
}

async function upsertGroup(courseId, relDir, parentGroupId, depth, name, position, now) {
  let row = await get(`SELECT * FROM content_groups WHERE course_id=? AND path_key=?`, [courseId, relDir]);
  if (!row) {
    const id = uid("g");
    await run(`INSERT INTO content_groups(id, course_id, parent_id, title, path_key, depth, position, sort_key, is_active, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
      [id, courseId, parentGroupId, prettyTitle(name), relDir, depth, position, relDir, 1, now, now]);
    return id;
  }
  await run(`UPDATE content_groups SET parent_id=?, title=?, depth=?, position=?, is_active=1, updated_at=? WHERE id=?`,
    [parentGroupId, prettyTitle(name), depth, position, now, row.id]);
  return row.id;
}

async function upsertLesson(courseId, groupId, v, pos, now) {
  const title = lessonTitle(v.name);
  let row = await get(`SELECT * FROM lessons WHERE course_id=? AND path_key=?`, [courseId, v.rel]);
  if (!row) {
    // moved/renamed file? same basename + size, currently inactive → reuse id (keeps progress)
    row = await get(`SELECT * FROM lessons WHERE course_id=? AND LOWER(file_name)=? AND file_size=? AND is_active=0 ORDER BY updated_at DESC LIMIT 1`,
      [courseId, v.name.toLowerCase(), v.size]);
    if (row) {
      await run(`UPDATE lessons SET path_key=?, group_id=?, file_name=?, position=?, sort_key=?, file_size=?, is_active=1, updated_at=? WHERE id=?`,
        [v.rel, groupId, v.name, pos, v.rel, v.size, now, row.id]);
      return;
    }
  }
  if (!row) {
    await run(`INSERT INTO lessons(id, course_id, group_id, title, path_key, file_name, position, sort_key, file_size, is_active, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
      [uid("l"), courseId, groupId, title || v.name, v.rel, v.name, pos, v.rel, v.size, 1, now, now]);
  } else {
    await run(`UPDATE lessons SET group_id=?, title=?, file_name=?, position=?, sort_key=?, file_size=?, is_active=1, updated_at=? WHERE id=?`,
      [groupId, title || row.title, v.name, pos, v.rel, v.size, now, row.id]);
  }
}

async function upsertPage(course, groupId, p, pos, now) {
  let raw = "";
  try { raw = await fsp.readFile(resolveInside(course, p.rel), "utf8"); } catch { raw = ""; }
  const titleP = extractTitle(raw, prettyTitle(path.basename(p.rel, path.extname(p.rel))));
  const words = countWords(raw);
  let row = await get(`SELECT * FROM reading_pages WHERE course_id=? AND path_key=?`, [course.id, p.rel]);
  if (!row) {
    const base = p.name.toLowerCase();
    row = await get(`SELECT * FROM reading_pages WHERE course_id=? AND LOWER(SUBSTR(path_key, LENGTH(path_key)-LENGTH(?)+1))=? AND file_size=? AND is_active=0 ORDER BY updated_at DESC LIMIT 1`,
      [course.id, base, base, p.size]);
  }
  if (!row) {
    await run(`INSERT INTO reading_pages(id, course_id, group_id, title, path_key, position, sort_key, word_count, file_size, is_active, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
      [uid("p"), course.id, groupId, titleP, p.rel, pos, p.rel, words, p.size, 1, now, now]);
  } else {
    await run(`UPDATE reading_pages SET group_id=?, title=?, position=?, word_count=?, file_size=?, is_active=1, updated_at=? WHERE id=?`,
      [groupId, titleP, pos, words, p.size, now, row.id]);
  }
}

async function upsertResource(courseId, groupId, lessonId, r, now) {
  const kind = resourceKind(r.name);
  const title = lessonTitle(r.name);
  const row = await get(`SELECT * FROM resources WHERE course_id=? AND path_key=?`, [courseId, r.rel]);
  if (!row) {
    await run(`INSERT INTO resources(id, course_id, group_id, lesson_id, title, path_key, file_name, kind, file_size, is_active, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
      [uid("r"), courseId, groupId, lessonId, title, r.rel, r.name, kind, r.size, 1, now, now]);
  } else {
    await run(`UPDATE resources SET group_id=?, lesson_id=?, title=?, file_name=?, kind=?, file_size=?, is_active=1, updated_at=? WHERE id=?`,
      [groupId, lessonId, title, r.name, kind, r.size, now, row.id]);
  }
}

// ---- safe path resolution ----
// Lexical containment first (blocks ../ traversal even for missing files),
// then canonical containment: when both sides exist on disk, a symlink chain
// that resolves outside the course root is rejected too.
// Multi-root: courses carry a denormalized root_path; legacy rows without
// one fall back to COURSES_ROOT so pre-upgrade installs keep working.
// dir_prefix is the layout segment ("video"/"reading", or "" for flat
// libraries); an explicit "" must NOT fall back to kind, hence ?? and not ||.
export function courseDir(course) {
  const base = course?.root_path || course?.rootPath || config.coursesRoot;
  const seg = course?.dir_prefix ?? course?.dirPrefix ?? course?.kind;
  return seg ? path.join(base, seg, course.dir_name) : path.join(base, course.dir_name);
}
export function resolveInside(course, relKey) {
  const base = courseDir(course);
  const target = path.normalize(path.join(base, relKey));
  if (target !== base && !target.startsWith(base + path.sep)) throw new Error("path traversal blocked");
  try {
    const realBase = fs.realpathSync(base);
    const realTarget = fs.realpathSync(target);
    if (realTarget !== realBase && !realTarget.startsWith(realBase + path.sep)) throw new Error("path traversal blocked");
  } catch (e) {
    if (/traversal blocked/.test(String(e?.message || ""))) throw e;
    // target (or base) missing from disk: lexical check above already passed
  }
  return target;
}

let watchers = [];
export function stopWatcher() {
  for (const w of watchers) { try { w.close(); } catch {} }
  watchers = [];
  clearTimeout(startWatcher._t);
}
// Watches every active library root (debounced rescan). Restarts cleanly so
// the admin API can re-arm it after roots change. Falls back to
// COURSES_ROOT when the DB isn't reachable yet (early boot).
export async function startWatcher(onChange) {
  stopWatcher();
  const fire = () => {
    if (!onChange) return;
    clearTimeout(startWatcher._t);
    startWatcher._t = setTimeout(() => onChange().catch(() => {}), 2500);
  };
  let roots = [];
  try {
    roots = await listCourseRoots(false);
  } catch { roots = []; }
  if (!roots.length) roots = [{ path: config.coursesRoot }];
  const paths = [...new Set(roots.map((r) => {
    try { return normalizeRootPath(r.path); } catch { return null; }
  }).filter(Boolean))];
  for (const p of paths) {
    try {
      fs.mkdirSync(p, { recursive: true });
      const w = fs.watch(p, { recursive: true }, (_evt, file) => {
        if (!file) return;
        fire();
      });
      watchers.push(w);
    } catch { /* best-effort: scan still works via Rescan button */ }
  }
  return () => stopWatcher();
}
