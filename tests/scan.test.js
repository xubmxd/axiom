// Integration tests for the recursive scanner. Each test FILE runs in its own
// process under node --test, so pointing DATA_DIR/COURSES_ROOT at temp dirs
// here (before dynamic imports) keeps these fully isolated from real data.
import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "lumen-scan-"));
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
  // flat: 1,2,10 ordering, no groups
  w(`${V}/flat/01.mp4`); w(`${V}/flat/02.mp4`); w(`${V}/flat/10.mp4`);
  // one-level modular
  w(`${V}/onelevel/Module 01/01.mp4`); w(`${V}/onelevel/Module 01/02.mp4`); w(`${V}/onelevel/Module 01/10.mp4`);
  // deep: 3 levels, numeric dir + file ordering at every depth
  w(`${V}/deep/02-Setup/1. A.mp4`); w(`${V}/deep/02-Setup/2. B.mp4`); w(`${V}/deep/02-Setup/10. C.mp4`);
  w(`${V}/deep/10-Advanced/02-Sub/01-Sec/1. Deep.mp4`);
  w(`${V}/deep/10-Advanced/02-Sub/01-Sec/2. Deeper.mp4`);
  w(`${V}/deep/10-Advanced/02-Sub/10-Sec/1. Ten.mp4`);
  w(`${V}/deep/10-Advanced/10-Sub/1. TenSub.mp4`);
  // mixed: video + companion txt (same basename) + orphan pdf + html page + subs
  w(`${V}/mixed/1. Project #1.mp4`, "v".repeat(500));
  w(`${V}/mixed/1. Project #1.txt`, "notes");
  w(`${V}/mixed/1. Project #1.srt`, "subs");
  w(`${V}/mixed/guide.pdf`, "%pdf");
  w(`${V}/mixed/notes.html`, "<h1>Notes</h1><p>hi</p>");
  w(`${V}/mixed/stray.nfo`, "ignored");
  await scanner.scanAll(true);
});

const courseId = async (dir) => (await db.get(`SELECT id FROM courses WHERE dir_name=?`, [dir])).id;

describe("recursive course model", () => {
  it("flat courses get lessons but no fake groups", async () => {
    const id = await courseId("flat");
    assert.equal((await db.all(`SELECT * FROM content_groups WHERE course_id=? AND is_active=1`, [id])).length, 0);
    const ls = await db.all(`SELECT * FROM lessons WHERE course_id=? AND is_active=1 ORDER BY position`, [id]);
    assert.deepEqual(ls.map((l) => l.file_name), ["01.mp4", "02.mp4", "10.mp4"]);
    assert.ok(ls.every((l) => l.group_id === null));
  });

  it("one-level courses nest one deep with natural order", async () => {
    const id = await courseId("onelevel");
    const gs = await db.all(`SELECT * FROM content_groups WHERE course_id=? AND is_active=1`, [id]);
    assert.equal(gs.length, 1);
    assert.equal(gs[0].depth, 1);
    assert.equal(gs[0].parent_id, null);
    const ls = await db.all(`SELECT * FROM lessons WHERE course_id=? AND is_active=1 ORDER BY position`, [id]);
    assert.deepEqual(ls.map((l) => l.file_name), ["01.mp4", "02.mp4", "10.mp4"]);
    assert.ok(ls.every((l) => l.group_id === gs[0].id));
  });

  it("arbitrary depth nests recursively with natural ordering at every level", async () => {
    const id = await courseId("deep");
    const gs = await db.all(`SELECT * FROM content_groups WHERE course_id=? AND is_active=1`, [id]);
    const byPath = new Map(gs.map((g) => [g.path_key, g]));
    assert.ok(byPath.has("02-Setup") && byPath.has("10-Advanced/02-Sub/01-Sec"));
    assert.equal(byPath.get("10-Advanced/02-Sub/01-Sec").depth, 3);
    assert.equal(byPath.get("10-Advanced/02-Sub/01-Sec").parent_id, byPath.get("10-Advanced/02-Sub").id);
    // sibling dirs ordered naturally: 02-Sub before 10-Sub
    const subs = gs.filter((g) => g.path_key.startsWith("10-Advanced/") && g.depth === 2)
      .sort((a, b) => a.position - b.position).map((g) => g.path_key);
    assert.deepEqual(subs, ["10-Advanced/02-Sub", "10-Advanced/10-Sub"]);
    // files ordered naturally inside deepest group
    const ls = await db.all(`SELECT file_name FROM lessons WHERE course_id=? AND group_id=? AND is_active=1 ORDER BY position`,
      [id, byPath.get("10-Advanced/02-Sub/01-Sec").id]);
    assert.deepEqual(ls.map((l) => l.file_name), ["1. Deep.mp4", "2. Deeper.mp4"]);
  });

  it("classifies files: companion txt links to lesson, no duplicate lesson, pdf orphan, html is a page", async () => {
    const id = await courseId("mixed");
    const lessons = await db.all(`SELECT * FROM lessons WHERE course_id=? AND is_active=1`, [id]);
    assert.equal(lessons.length, 1); // the .txt/.srt did NOT become lessons
    const res = await db.all(`SELECT * FROM resources WHERE course_id=? AND is_active=1`, [id]);
    const kinds = new Map(res.map((r) => [r.file_name, r]));
    assert.equal(kinds.get("1. Project #1.txt").lesson_id, lessons[0].id);
    assert.equal(kinds.get("1. Project #1.txt").kind, "text");
    assert.equal(kinds.get("1. Project #1.srt").lesson_id, lessons[0].id);
    assert.equal(kinds.get("1. Project #1.srt").kind, "subtitle");
    assert.equal(kinds.get("guide.pdf").lesson_id, null);
    assert.equal(kinds.get("guide.pdf").kind, "document");
    assert.ok(!kinds.has("stray.nfo")); // unknown ext skipped
    const pages = await db.all(`SELECT * FROM reading_pages WHERE course_id=? AND is_active=1`, [id]);
    assert.equal(pages.length, 1); // notes.html classified as reading
    assert.equal(pages[0].title, "Notes");
  });

  it("stable identities: rescan with no changes keeps every id", async () => {
    const before = await db.all(`SELECT id, path_key FROM lessons UNION ALL SELECT id, path_key FROM reading_pages UNION ALL SELECT id, path_key FROM content_groups UNION ALL SELECT id, path_key FROM resources`);
    await scanner.scanAll(true);
    const after = await db.all(`SELECT id, path_key FROM lessons UNION ALL SELECT id, path_key FROM reading_pages UNION ALL SELECT id, path_key FROM content_groups UNION ALL SELECT id, path_key FROM resources`);
    assert.deepEqual(new Map(after.map((r) => [r.path_key, r.id])), new Map(before.map((r) => [r.path_key, r.id])));
  });

  it("adding content preserves existing progress", async () => {
    await db.run(`INSERT OR IGNORE INTO users(id, username, email, display_name, password_hash, role, status, avatar_color, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
      ["u_test", "t", "t@t.t", "T", "x", "user", "active", "#000", new Date().toISOString(), new Date().toISOString()]);
    const id = await courseId("flat");
    const l1 = await db.get(`SELECT * FROM lessons WHERE course_id=? AND file_name=?`, [id, "01.mp4"]);
    await db.run(`INSERT INTO video_progress(user_id, lesson_id, position_secs, duration_secs, completed, watch_secs, updated_at) VALUES(?,?,?,?,?,?,?)`,
      ["u_test", l1.id, 42, 100, 0, 30, new Date().toISOString()]);
    w(`${V}/flat/03.mp4`);
    await scanner.scanAll(true);
    const kept = await db.get(`SELECT * FROM video_progress WHERE user_id=? AND lesson_id=?`, ["u_test", l1.id]);
    assert.equal(kept.position_secs, 42);
    const ls = await db.all(`SELECT file_name FROM lessons WHERE course_id=? AND is_active=1 ORDER BY position`, [id]);
    assert.deepEqual(ls.map((l) => l.file_name), ["01.mp4", "02.mp4", "03.mp4", "10.mp4"]);
  });

  it("moving a file reuses its id (progress follows the move)", async () => {
    const id = await courseId("onelevel");
    const l = await db.get(`SELECT * FROM lessons WHERE course_id=? AND file_name=?`, [id, "02.mp4"]);
    await db.run(`INSERT INTO video_progress(user_id, lesson_id, position_secs, duration_secs, completed, watch_secs, updated_at) VALUES(?,?,?,?,?,?,?)`,
      ["u_test", l.id, 77, 100, 0, 10, new Date().toISOString()]);
    fs.mkdirSync(`${V}/onelevel/Module 02`, { recursive: true });
    fs.renameSync(`${V}/onelevel/Module 01/02.mp4`, `${V}/onelevel/Module 02/02.mp4`);
    await scanner.scanAll(true);
    const moved = await db.get(`SELECT * FROM lessons WHERE id=?`, [l.id]);
    assert.equal(moved.path_key, "Module 02/02.mp4");
    assert.equal(moved.is_active, 1);
    const kept = await db.get(`SELECT * FROM video_progress WHERE user_id=? AND lesson_id=?`, ["u_test", l.id]);
    assert.equal(kept.position_secs, 77);
  });

  it("deleting a file soft-deletes without touching siblings", async () => {
    const id = await courseId("flat");
    fs.rmSync(`${V}/flat/10.mp4`);
    await scanner.scanAll(true);
    const gone = await db.get(`SELECT * FROM lessons WHERE course_id=? AND file_name=?`, [id, "10.mp4"]);
    assert.equal(gone.is_active, 0);
    assert.equal((await db.all(`SELECT * FROM lessons WHERE course_id=? AND is_active=1`, [id])).length, 3);
  });
});

describe("range edge cases (unit)", () => {
  it("zero-byte files never produce a stream range", async () => {
    const { parseRange } = await import("../server/routes-media.js");
    assert.equal(parseRange("bytes=0-", 0), null);
    assert.equal(parseRange("bytes=0-0", 0), null);
    assert.equal(parseRange("bytes=-10", 0), null);
    assert.equal(parseRange("bytes=5-3", 100), null); // start > end
    assert.equal(parseRange("bytes=100-", 100), null); // beyond EOF
    assert.deepEqual(parseRange("bytes=0-", 100), { start: 0, end: 99 });
  });
});
