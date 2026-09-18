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
  const ext = path.extname(base).toLowerCase();
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
function prettyTitle(name) {
  return name.replace(/[_-]+/g, " ").replace(/\s+/g, " ").trim() || name;
}
function lessonTitle(fileName) {
  const t = prettyTitle(path.basename(fileName, path.extname(fileName))).replace(/^\d+\s*[-–_. ]+/, "");
  return t || fileName;
}

// ---- phase 1: pure filesystem walk (no DB) ----
// Every directory level and every file list is naturally ordered.
async function buildFileTree(absDir) {
  const node = { videos: [], pages: [], resources: [], children: [], icon: null };
  const entries = await fsp.readdir(absDir, { withFileTypes: true }).catch(() => []);
  for (const e of entries) {
    const cls = e.isDirectory() ? "dir" : classifyFile(e.name);
    if (cls === "dir") {
      if (e.name.startsWith(".")) continue;
      const child = await buildFileTree(path.join(absDir, e.name));
      child.name = e.name;
      node.children.push(child);
    } else if (cls === "icon") {
      if (!node.icon) node.icon = e.name;
    } else if (cls === "video" || cls === "html" || cls === "resource") {
      const st = await fsp.stat(path.join(absDir, e.name)).catch(() => null);
      const item = { name: e.name, size: st?.size || 0 };
      if (cls === "video") node.videos.push(item);
      else if (cls === "html") node.pages.push(item);
      else node.resources.push(item);
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

export async function scanAll(manual = false) {
  const started = Date.now();
  await run(`UPDATE scan_state SET last_status='running', last_error='' WHERE id=1`);
  try {
    fs.mkdirSync(config.coursesRoot, { recursive: true });
    for (const sub of ["video", "reading"]) fs.mkdirSync(path.join(config.coursesRoot, sub), { recursive: true });
    const seen = new Set();
    let courseCount = 0;
    for (const kind of ["video", "reading"]) {
      const kindDir = path.join(config.coursesRoot, kind);
      const dirs = await fsp.readdir(kindDir, { withFileTypes: true }).catch(() => []);
      const names = dirs.filter((d) => d.isDirectory() && !d.name.startsWith(".")).map((d) => d.name).sort(natSort);
      for (const name of names) {
        await scanCourse(kind, path.join(kindDir, name), name);
        seen.add(`${kind}:${slugify(name)}`);
        courseCount++;
      }
    }
    // remove courses no longer on disk
    const existing = await all(`SELECT * FROM courses`);
    for (const c of existing) {
      if (!seen.has(`${c.kind}:${c.slug}`)) {
        await run(`DELETE FROM courses WHERE id=?`, [c.id]);
        log("course.removed", { course: c.title });
      }
    }
    const okAt = nowIso();
    await run(`UPDATE scan_state SET last_ok_at=?, last_status='ok', last_error='', course_count=? WHERE id=1`, [okAt, courseCount]);
    log("scan.ok", { courses: courseCount, ms: Date.now() - started, manual });
    return { ok: true, courses: courseCount };
  } catch (err) {
    await run(`UPDATE scan_state SET last_status='error', last_error=? WHERE id=1`, [String(err?.message || err).slice(0, 500)]);
    log("scan.error", { error: String(err?.message || err) });
    return { ok: false, error: String(err?.message || err) };
  }
}

async function scanCourse(kind, coursePath, dirName) {
  const now = nowIso();
  const slug = slugify(dirName);
  const title = prettyTitle(dirName);
  let course = await get(`SELECT * FROM courses WHERE kind=? AND slug=?`, [kind, slug]);
  const tree = await buildFileTree(coursePath);
  const hasIcon = tree.icon ? 1 : 0;
  if (!course) {
    course = { id: uid("c"), kind, title, slug, dir_name: dirName, has_icon: hasIcon, created_at: now, updated_at: now };
    await run(`INSERT INTO courses(id, kind, title, slug, dir_name, has_icon, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?)`,
      [course.id, kind, title, slug, dirName, hasIcon, now, now]);
  } else {
    await run(`UPDATE courses SET title=?, dir_name=?, has_icon=?, updated_at=? WHERE id=?`, [course.title || title, dirName, hasIcon, now, course.id]);
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
export function courseDir(course) {
  return path.join(config.coursesRoot, course.kind, course.dir_name);
}
export function resolveInside(course, relKey) {
  const base = courseDir(course);
  const target = path.normalize(path.join(base, relKey));
  if (target !== base && !target.startsWith(base + path.sep)) throw new Error("path traversal blocked");
  return target;
}

let watcher = null;
export function startWatcher(onChange) {
  try {
    fs.watch(config.coursesRoot, { recursive: true }, (_evt, file) => {
      if (!file) return;
      clearTimeout(startWatcher._t);
      startWatcher._t = setTimeout(() => onChange && onChange().catch(() => {}), 2500);
    });
  } catch { watcher = null; }
}
