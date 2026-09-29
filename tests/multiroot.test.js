// Multi-library tests: structured default root + flat extra root in one
// scan, kind inference, same-slug coexistence, prefix-aware resolution,
// disabled roots preserving courses. Isolated tmp dirs (own process).
import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "lumen-multiroot-"));
process.env.DATA_DIR = path.join(tmp, "data");
process.env.COURSES_ROOT = path.join(tmp, "courses");

const D = path.join(tmp, "courses");           // default (structured)
const X = path.join(tmp, "extra");             // extra (flat: no video//reading/)
const w = (fp, content = "x".repeat(100)) => {
  fs.mkdirSync(path.dirname(fp), { recursive: true });
  fs.writeFileSync(fp, content);
};

let db, scanner;
before(async () => {
  db = await import("../server/db.js");
  scanner = await import("../server/scanner.js");
  // Fictional tag set explicitly: the default is empty and real patterns
  // live only in private server env files, never in the repo.
  const { config } = await import("../server/config.js");
  config.titleStrip = [" - [ @test_team ]"];
  await db.initDb();
  // default root must seed exactly one row (regression: pg COUNT string bug)
  assert.equal((await db.all(`SELECT * FROM course_roots`)).length, 1);
  // structured course in the default library
  w(`${D}/video/Structured/01.mp4`);
  // flat courses directly under the extra root
  w(`${X}/FlatVids/01.mp4`);
  w(`${X}/FlatVids/02.mp4`);
  w(`${X}/FlatDocs/page.html`, "<h1>Doc</h1><p>hi</p>");
  w(`${X}/Shared/01.mp4`);
  // same course name also exists in the default library (coexistence)
  w(`${D}/video/Shared/01.mp4`);
  // distributor tag in folder + file names: stripped from titles only
  w(`${X}/Tagged Course - [ @test_team ]/Lecture 1 - [ @test_team ].mp4`);
  // loose files at the library root are ignored (courses are folders)
  w(`${X}/loose.zip`, "PK");
  const now = new Date().toISOString();
  await db.run(`INSERT INTO course_roots(id, path, label, is_active, last_error, created_at, updated_at) VALUES(?,?,?,?,?,?,?)`,
    ["root_extra", X, "Extra", 1, "", now, now]);
  await scanner.scanAll(true);
});

describe("multiple libraries", () => {
  it("scans structured and flat layouts in one pass", async () => {
    const titles = (await db.all(`SELECT title FROM courses ORDER BY title`)).map((r) => r.title);
    assert.deepEqual(titles, ["FlatDocs", "FlatVids", "Shared", "Shared", "Structured", "Tagged Course"]);
  });

  it("strips configured tags from course and lesson titles (disk names kept)", async () => {
    const c = await db.get(`SELECT * FROM courses WHERE title=?`, ["Tagged Course"]);
    assert.ok(c);
    assert.equal(c.dir_name, "Tagged Course - [ @test_team ]"); // on-disk name untouched
    assert.match(c.slug, /test-team/); // identity still derived from the real name
    const ls = await db.all(`SELECT title, file_name FROM lessons WHERE course_id=? AND is_active=1`, [c.id]);
    assert.equal(ls.length, 1);
    assert.equal(ls[0].title, "Lecture 1");
    assert.equal(ls[0].file_name, "Lecture 1 - [ @test_team ].mp4");
  });

  it("infers flat kinds from content (video vs reading)", async () => {
    const v = await db.get(`SELECT kind, dir_prefix FROM courses WHERE dir_name=? AND root_id=?`, ["FlatVids", "root_extra"]);
    assert.equal(v.kind, "video");
    assert.equal(v.dir_prefix, "");
    const d = await db.get(`SELECT kind FROM courses WHERE dir_name=?`, ["FlatDocs"]);
    assert.equal(d.kind, "reading");
    const s = await db.get(`SELECT kind, dir_prefix FROM courses WHERE dir_name=? AND root_id=?`, ["Structured", "root_default"]);
    assert.equal(s.kind, "video");
    assert.equal(s.dir_prefix, "video");
  });

  it("same course name coexists in two libraries", async () => {
    const rows = await db.all(`SELECT root_id FROM courses WHERE slug=? ORDER BY root_id`, ["shared"]);
    assert.deepEqual(rows.map((r) => r.root_id), ["root_default", "root_extra"]);
  });

  it("resolves media paths per library layout", async () => {
    const flat = await db.get(`SELECT * FROM courses WHERE dir_name=? AND root_id=?`, ["FlatVids", "root_extra"]);
    assert.equal(scanner.courseDir(flat), path.join(X, "FlatVids"));
    const st = await db.get(`SELECT * FROM courses WHERE dir_name=?`, ["Structured"]);
    assert.equal(scanner.courseDir(st), path.join(D, "video", "Structured"));
    assert.throws(() => scanner.resolveInside(flat, "../../etc/passwd"), /traversal/);
    const l = await db.get(`SELECT l.* FROM lessons l JOIN courses c ON c.id=l.course_id WHERE c.dir_name=? AND c.root_id=?`, ["FlatVids", "root_extra"]);
    assert.ok(l);
  });

  it("flat lessons and pages are indexed", async () => {
    const v = await db.get(`SELECT id FROM courses WHERE dir_name=? AND root_id=?`, ["FlatVids", "root_extra"]);
    assert.equal((await db.all(`SELECT * FROM lessons WHERE course_id=? AND is_active=1`, [v.id])).length, 2);
    const d = await db.get(`SELECT id FROM courses WHERE dir_name=?`, ["FlatDocs"]);
    assert.equal((await db.all(`SELECT * FROM reading_pages WHERE course_id=? AND is_active=1`, [d.id])).length, 1);
  });

  it("disabling a library keeps its courses; rescan only covers enabled roots", async () => {
    await db.run(`UPDATE course_roots SET is_active=0 WHERE id=?`, ["root_extra"]);
    const r = await scanner.scanAll(true);
    assert.equal(r.roots, 1);
    assert.equal((await db.all(`SELECT * FROM courses`)).length, 6);
    await db.run(`UPDATE course_roots SET is_active=1 WHERE id=?`, ["root_extra"]);
    const r2 = await scanner.scanAll(true);
    assert.equal(r2.roots, 2);
    assert.equal((await db.all(`SELECT * FROM courses`)).length, 6);
  });

  it("release stubs never index (and vanish on rescan if previously stored)", async () => {
    w(`${X}/FlatVids/Credits.txt`, "thanks");
    w(`${X}/FlatVids/Important ReadMe.url`, "[InternetShortcut]");
    await scanner.scanAll(true);
    const v = await db.get(`SELECT id FROM courses WHERE dir_name=? AND root_id=?`, ["FlatVids", "root_extra"]);
    const res = await db.all(`SELECT file_name FROM resources WHERE course_id=? AND is_active=1`, [v.id]);
    assert.ok(!res.some((r) => r.file_name === "Credits.txt"));
    assert.ok(!res.some((r) => r.file_name === "Important ReadMe.url"));
    fs.rmSync(`${X}/FlatVids/Credits.txt`, { force: true });
    fs.rmSync(`${X}/FlatVids/Important ReadMe.url`, { force: true });
  });

  it("removing a flat course folder deletes only that course", async () => {
    fs.rmSync(path.join(X, "FlatDocs"), { recursive: true, force: true });
    await scanner.scanAll(true);
    assert.equal(await db.get(`SELECT * FROM courses WHERE dir_name=?`, ["FlatDocs"]), null);
    assert.ok(await db.get(`SELECT * FROM courses WHERE dir_name=?`, ["FlatVids"]));
  });

  it("validation rejects missing, duplicate and nested paths", async () => {
    const { validateRootPath } = scanner;
    assert.match(validateRootPath("/no/such/dir-xyz", []), /inside the app container/);
    assert.match(validateRootPath(X, [{ path: X }]), /already added/);
    const sub = path.join(X, "sub");
    fs.mkdirSync(sub, { recursive: true });
    assert.match(validateRootPath(sub, [{ path: X }]), /overlaps/);
    fs.rmdirSync(sub);
    assert.equal(validateRootPath(X, [{ path: D }]), null);
  });
});
