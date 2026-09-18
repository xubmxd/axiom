// Recursive filesystem-course engine tests (§26 gaps): PEN-style two-level
// nesting, arbitrary depth, prefix preservation, .vtt sidecars, idempotent
// rescans, add/delete detection, multi-course independence, empty dirs and
// symlink/traversal protection. Isolated tmp dirs (own process per file).
import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "lumen-recursive-"));
process.env.DATA_DIR = path.join(tmp, "data");
process.env.COURSES_ROOT = path.join(tmp, "courses");

const V = path.join(tmp, "courses", "video");
const w = (fp, content = "x".repeat(100)) => {
  fs.mkdirSync(path.dirname(fp), { recursive: true });
  fs.writeFileSync(fp, content);
};

let db, scanner;
before(async () => {
  db = await import("../server/db.js");
  scanner = await import("../server/scanner.js");
  await db.initDb();

  // PEN-style two-level course (generic depth, NOT pen-specific logic)
  w(`${V}/pentest/01. INFORMATION GATHERING/1.1. Passive Information Gathering/1.1.1. Whois Enumeration.mp4`);
  w(`${V}/pentest/01. INFORMATION GATHERING/1.1. Passive Information Gathering/1.1.1. Whois Enumeration.vtt`, "WEBVTT\n\n00:00.000 --> 00:01.000\nhi");
  w(`${V}/pentest/01. INFORMATION GATHERING/1.1. Passive Information Gathering/1.1.2. Google Hacking.mp4`);
  w(`${V}/pentest/01. INFORMATION GATHERING/1.1. Passive Information Gathering/1.1.10. Netcraft.mp4`);
  w(`${V}/pentest/01. INFORMATION GATHERING/1.2. Active Information Gathering/1.2.1. DNS Enumeration.mp4`);
  w(`${V}/pentest/01. INFORMATION GATHERING/1.2. Active Information Gathering/1.2.2. Port Scanning.mp4`);
  w(`${V}/pentest/02. VULNERABILITY SCANNING/2.1. Scanning with Nessus/2.1.1. Nessus Components.mp4`);
  w(`${V}/pentest/02. VULNERABILITY SCANNING/2.1. Scanning with Nessus/2.1.2. Performing a Scan.mp4`);
  w(`${V}/pentest/02. VULNERABILITY SCANNING/2.2. Scanning with Nmap/2.2.1. Nmap Basics.mp4`);
  w(`${V}/pentest/stray.nfo`, "junk");
  w(`${V}/pentest/run.exe`, "junk");
  fs.mkdirSync(`${V}/pentest/03. EMPTY SECTION`, { recursive: true });

  // flat course + deeply nested course (independence, arbitrary depth)
  w(`${V}/flatc/01.mp4`); w(`${V}/flatc/02.mp4`); w(`${V}/flatc/10.mp4`);
  w(`${V}/deepc/Section A/Section B/Section C/Section D/Lesson.mp4`);
  w(`${V}/deepc/Section A/Section B/Section C/Section D/Lesson.vtt`, "WEBVTT");

  await scanner.scanAll(true);
});

const courseId = async (dir) => (await db.get(`SELECT id FROM courses WHERE dir_name=?`, [dir])).id;

describe("two-level PEN-style hierarchy from directory nesting", () => {
  it("derives module/submodule/lesson purely from depth", async () => {
    const id = await courseId("pentest");
    const gs = await db.all(`SELECT * FROM content_groups WHERE course_id=? AND is_active=1`, [id]);
    const byPath = new Map(gs.map((g) => [g.path_key, g]));
    assert.ok(byPath.has("01. INFORMATION GATHERING"));
    assert.equal(byPath.get("01. INFORMATION GATHERING").depth, 1);
    assert.equal(byPath.get("01. INFORMATION GATHERING").parent_id, null);
    const sub = byPath.get("01. INFORMATION GATHERING/1.1. Passive Information Gathering");
    assert.ok(sub);
    assert.equal(sub.depth, 2);
    assert.equal(sub.parent_id, byPath.get("01. INFORMATION GATHERING").id);
    const ls = await db.all(`SELECT * FROM lessons WHERE course_id=? AND group_id=? AND is_active=1 ORDER BY position`, [id, sub.id]);
    assert.deepEqual(ls.map((l) => l.file_name),
      ["1.1.1. Whois Enumeration.mp4", "1.1.2. Google Hacking.mp4", "1.1.10. Netcraft.mp4"]);
  });

  it("sibling submodules sort naturally (1.1 before 1.2, 2.1 before 2.2)", async () => {
    const id = await courseId("pentest");
    const subs = await db.all(`SELECT path_key FROM content_groups WHERE course_id=? AND depth=2 AND is_active=1 ORDER BY position`, [id]);
    const keys = subs.map((s) => s.path_key);
    assert.ok(keys.indexOf("01. INFORMATION GATHERING/1.1. Passive Information Gathering")
      < keys.indexOf("01. INFORMATION GATHERING/1.2. Active Information Gathering"));
    assert.ok(keys.indexOf("02. VULNERABILITY SCANNING/2.1. Scanning with Nessus")
      < keys.indexOf("02. VULNERABILITY SCANNING/2.2. Scanning with Nmap"));
  });
});

describe("title preservation and sidecars", () => {
  it("keeps full numeric prefixes in lesson titles", async () => {
    const id = await courseId("pentest");
    const t = async (f) => (await db.get(`SELECT title FROM lessons WHERE course_id=? AND file_name=?`, [id, f])).title;
    assert.equal(await t("1.1.1. Whois Enumeration.mp4"), "1.1.1. Whois Enumeration");
    assert.equal(await t("2.1.1. Nessus Components.mp4"), "2.1.1. Nessus Components");
    assert.equal(await t("1.1.10. Netcraft.mp4"), "1.1.10. Netcraft");
  });

  it("attaches .vtt as subtitle sidecar, never as a lesson", async () => {
    const id = await courseId("pentest");
    const vids = await db.all(`SELECT * FROM lessons WHERE course_id=? AND is_active=1`, [id]);
    assert.equal(vids.length, 8); // 8 videos, vtt excluded
    assert.ok(!vids.some((l) => l.file_name.endsWith(".vtt")));
    const vid = await db.get(`SELECT * FROM lessons WHERE course_id=? AND file_name=?`, [id, "1.1.1. Whois Enumeration.mp4"]);
    const sub = await db.get(`SELECT * FROM resources WHERE course_id=? AND file_name=?`, [id, "1.1.1. Whois Enumeration.vtt"]);
    assert.ok(sub);
    assert.equal(sub.kind, "subtitle");
    assert.equal(sub.lesson_id, vid.id);
    const course = await db.get(`SELECT lesson_count FROM courses WHERE id=?`, [id]);
    assert.equal(course.lesson_count, 8);
  });

  it("ignores unknown files and empty directories safely", async () => {
    const id = await courseId("pentest");
    assert.equal((await db.get(`SELECT COUNT(*) n FROM lessons WHERE course_id=? AND file_name=?`, [id, "stray.nfo"]))?.n || 0, 0);
    assert.equal((await db.get(`SELECT COUNT(*) n FROM resources WHERE course_id=? AND file_name=?`, [id, "run.exe"]))?.n || 0, 0);
    assert.equal((await db.get(`SELECT COUNT(*) n FROM content_groups WHERE course_id=? AND path_key=?`, [id, "03. EMPTY SECTION"]))?.n ?? -1, 0);
  });
});

describe("flat and arbitrarily deep courses coexist", () => {
  it("flat course has lessons with no groups", async () => {
    const id = await courseId("flatc");
    assert.equal((await db.all(`SELECT * FROM content_groups WHERE course_id=? AND is_active=1`, [id])).length, 0);
    const ls = await db.all(`SELECT file_name FROM lessons WHERE course_id=? AND is_active=1 ORDER BY position`, [id]);
    assert.deepEqual(ls.map((l) => l.file_name), ["01.mp4", "02.mp4", "10.mp4"]);
  });

  it("four-deep nesting works with no depth cap", async () => {
    const id = await courseId("deepc");
    const gs = await db.all(`SELECT * FROM content_groups WHERE course_id=? AND is_active=1`, [id]);
    const byPath = new Map(gs.map((g) => [g.path_key, g]));
    const leaf = byPath.get("Section A/Section B/Section C/Section D");
    assert.ok(leaf);
    assert.equal(leaf.depth, 4);
    assert.equal(leaf.parent_id, byPath.get("Section A/Section B/Section C").id);
    const ls = await db.all(`SELECT * FROM lessons WHERE course_id=? AND is_active=1`, [id]);
    assert.equal(ls.length, 1);
    assert.equal(ls[0].group_id, leaf.id);
    assert.equal(ls[0].title, "Lesson");
  });
});

describe("rescan stability and change detection", () => {
  it("triple rescan is idempotent (no duplicate groups/lessons)", async () => {
    const count = async () => ({
      g: (await db.get(`SELECT COUNT(*) n FROM content_groups WHERE is_active=1`)).n,
      l: (await db.get(`SELECT COUNT(*) n FROM lessons WHERE is_active=1`)).n,
      r: (await db.get(`SELECT COUNT(*) n FROM resources WHERE is_active=1`)).n,
    });
    const a = await count();
    await scanner.scanAll(true);
    await scanner.scanAll(true);
    const b = await count();
    assert.deepEqual(b, a);
  });

  it("detects a brand-new nested section tree", async () => {
    const id = await courseId("pentest");
    const beforeIds = new Map((await db.all(`SELECT id, path_key FROM lessons WHERE course_id=?`, [id])).map((r) => [r.path_key, r.id]));
    w(`${V}/pentest/02. VULNERABILITY SCANNING/2.3. New Area/2.3.1. Fresh Lesson.mp4`);
    w(`${V}/pentest/02. VULNERABILITY SCANNING/2.3. New Area/2.3.1. Fresh Lesson.vtt`, "WEBVTT");
    await scanner.scanAll(true);
    const g = await db.get(`SELECT * FROM content_groups WHERE course_id=? AND path_key=?`, [id, "02. VULNERABILITY SCANNING/2.3. New Area"]);
    assert.ok(g && g.is_active === 1);
    assert.equal(g.depth, 2);
    const l = await db.get(`SELECT * FROM lessons WHERE course_id=? AND path_key=?`, [id, "02. VULNERABILITY SCANNING/2.3. New Area/2.3.1. Fresh Lesson.mp4"]);
    assert.ok(l && l.is_active === 1);
    assert.equal(l.title, "2.3.1. Fresh Lesson");
    const sub = await db.get(`SELECT * FROM resources WHERE course_id=? AND file_name=?`, [id, "2.3.1. Fresh Lesson.vtt"]);
    assert.equal(sub.lesson_id, l.id);
    // old identities untouched
    for (const [k, v] of beforeIds) {
      assert.equal((await db.get(`SELECT id FROM lessons WHERE course_id=? AND path_key=?`, [id, k])).id, v);
    }
  });

  it("soft-deletes removed lessons/groups without touching siblings", async () => {
    const id = await courseId("pentest");
    fs.rmSync(`${V}/pentest/01. INFORMATION GATHERING/1.1. Passive Information Gathering/1.1.10. Netcraft.mp4`);
    fs.rmSync(`${V}/pentest/02. VULNERABILITY SCANNING/2.2. Scanning with Nmap`, { recursive: true });
    await scanner.scanAll(true);
    const gone = await db.get(`SELECT * FROM lessons WHERE course_id=? AND file_name=?`, [id, "1.1.10. Netcraft.mp4"]);
    assert.equal(gone.is_active, 0);
    const goneGroup = await db.get(`SELECT * FROM content_groups WHERE course_id=? AND path_key=?`, [id, "02. VULNERABILITY SCANNING/2.2. Scanning with Nmap"]);
    assert.equal(goneGroup.is_active, 0);
    const sib = await db.get(`SELECT * FROM lessons WHERE course_id=? AND file_name=?`, [id, "1.1.2. Google Hacking.mp4"]);
    assert.equal(sib.is_active, 1);
  });

  it("user progress survives rescans and content changes", async () => {
    await db.run(`INSERT OR IGNORE INTO users(id, username, email, display_name, password_hash, role, status, avatar_color, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
      ["u_rec", "rec", "rec@r.r", "Rec", "x", "user", "active", "#000", new Date().toISOString(), new Date().toISOString()]);
    const id = await courseId("pentest");
    const l = await db.get(`SELECT * FROM lessons WHERE course_id=? AND file_name=?`, [id, "1.1.2. Google Hacking.mp4"]);
    await db.run(`INSERT OR REPLACE INTO video_progress(user_id, lesson_id, position_secs, duration_secs, completed, watch_secs, updated_at) VALUES(?,?,?,?,?,?,?)`,
      ["u_rec", l.id, 55, 120, 0, 20, new Date().toISOString()]);
    await scanner.scanAll(true);
    const kept = await db.get(`SELECT * FROM video_progress WHERE user_id=? AND lesson_id=?`, ["u_rec", l.id]);
    assert.equal(kept.position_secs, 55);
  });
});

describe("filesystem security", () => {
  it("blocks path traversal via resolveInside", async () => {
    const { resolveInside } = await import("../server/scanner.js");
    assert.throws(() => resolveInside({ kind: "video", dir_name: "pentest" }, "../../etc/passwd"), /traversal/);
    assert.throws(() => resolveInside({ kind: "video", dir_name: "pentest" }, "a/../../b"), /traversal/);
  });

  it("skips symlinks escaping the course root", async () => {
    const outside = path.join(tmp, "outside");
    fs.mkdirSync(outside, { recursive: true });
    fs.writeFileSync(path.join(outside, "secret.mp4"), "x".repeat(200));
    const id = await courseId("pentest");
    try { fs.symlinkSync(path.join(outside, "secret.mp4"), `${V}/pentest/evil-link.mp4`); } catch { return; }
    try { fs.symlinkSync(outside, `${V}/pentest/evil-dir`); } catch { /* windows */ }
    await scanner.scanAll(true);
    assert.equal((await db.all(`SELECT * FROM lessons WHERE course_id=? AND path_key LIKE '%evil%' AND is_active=1`, [id])).length, 0);
    assert.equal((await db.all(`SELECT * FROM resources WHERE course_id=? AND path_key LIKE '%evil%' AND is_active=1`, [id])).length, 0);
    assert.equal((await db.all(`SELECT * FROM content_groups WHERE course_id=? AND path_key LIKE '%evil%' AND is_active=1`, [id])).length, 0);
    fs.rmSync(`${V}/pentest/evil-link.mp4`, { force: true });
    fs.rmSync(`${V}/pentest/evil-dir`, { force: true, recursive: true });
  });
});
