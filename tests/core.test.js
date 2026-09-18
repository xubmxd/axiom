import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// natural ordering
describe("natural ordering", () => {
  it("sorts 1,2,3,10 correctly", () => {
    const c = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });
    const files = ["10.mp4", "2.mp4", "1.mp4", "3.mp4"].sort(c.compare);
    assert.deepEqual(files, ["1.mp4", "2.mp4", "3.mp4", "10.mp4"]);
  });
});

describe("range requests", () => {
  it("parses open-ended, closed, suffix and invalid ranges", async () => {
    const { parseRange } = await import("../server/routes-media.js");
    assert.deepEqual(parseRange("bytes=0-99", 1000), { start: 0, end: 99 });
    assert.deepEqual(parseRange("bytes=1-", 1000), { start: 1, end: 999 }); // the crasher
    assert.deepEqual(parseRange("bytes=0-", 1000), { start: 0, end: 999 });
    assert.deepEqual(parseRange("bytes=-500", 1000), { start: 500, end: 999 });
    assert.deepEqual(parseRange("bytes=900-9999", 1000), { start: 900, end: 999 });
    assert.equal(parseRange("bytes=1000-", 1000), null); // start past EOF
    assert.equal(parseRange("bytes=50-10", 1000), null); // inverted
    assert.equal(parseRange("bytes=0-0", 0), null); // empty file
    assert.equal(parseRange("garbage", 1000), null);
  });
});

describe("html sanitizer", () => {
  it("strips scripts, event handlers, javascript: urls", async () => {
    const { sanitize } = await import("../server/sanitize.js");
    const { html } = sanitize(
      `<h1>T</h1><script>alert(1)</script><p onclick="evil()">hi</p><a href="javascript:alert(1)">x</a><a href="chapter-2/page.html">next</a>`,
      { mediaPrefix: "/m", linkPrefix: "/r/c", pageDir: "chapter-1" }
    );
    assert.ok(!html.includes("<script") && !html.includes("onclick") && !html.includes("javascript:"));
    assert.ok(html.includes("/r/c/chapter-2%2Fpage.html") || html.includes("/r/c/"));
  });
  it("blocks path traversal", async () => {
    const { resolveInside } = await import("../server/scanner.js");
    assert.throws(() => resolveInside({ kind: "video", dir_name: "X" }, "../../etc/passwd"), /traversal/);
  });
  it("day attribution splits midnight by tz", async () => {
    const { dayFor } = await import("../server/stats.js");
    // 00:30 in UTC+2 = 22:30 UTC previous day -> different calendar days
    const utc = new Date("2026-09-18T22:30:00Z");
    assert.equal(dayFor(0, utc), "2026-09-18");
    assert.equal(dayFor(-120, utc), "2026-09-19"); // UTC+2 -> local next day
  });
  it("adaptive bands are monotonic", async () => {
    const { intensityLevels, levelFor } = await import("../server/stats.js");
    const rows = [300, 600, 1200, 1800, 3600, 7200].map((s, i) => ({ video_secs: s, reading_secs: 0, day: `2026-01-0${i + 1}` }));
    const b = intensityLevels(rows);
    assert.ok(b.q1 < b.q2 && b.q2 < b.q3);
    assert.equal(levelFor(0, b), 0);
    assert.equal(levelFor(99999, b), 4);
  });
});

describe("reader sanitizer", () => {
  it("returns heading ids for sidebar anchors, without duplicate id attrs", async () => {
    const { sanitize } = await import("../server/sanitize.js");
    const { html, headings } = sanitize(`<h2>Command Line Basics</h2><h2 id="old">Second</h2>`,
      { mediaPrefix: "/m", linkPrefix: "/r/c", pageDir: "" });
    assert.equal(headings.length, 2);
    assert.ok(headings.every((h) => h.id && h.id.startsWith("s-")));
    assert.ok(html.includes(`id="${headings[0].id}"`));
    assert.ok(!html.includes('id="old"'));
    assert.equal((html.match(/ id="/g) || []).length, 2); // exactly one id per heading
  });
  it("drops multi-MB embedded data images but keeps tiny icons", async () => {
    const { sanitize } = await import("../server/sanitize.js");
    const big = "data:image/png;base64," + "A".repeat(100_000);
    const small = "data:image/png;base64," + "A".repeat(100);
    const { html } = sanitize(`<img src="${big}" alt="photo"><img src="${small}" alt="icon">`,
      { mediaPrefix: "/m", linkPrefix: "/r/c", pageDir: "" });
    assert.ok(!html.includes("A".repeat(5000))); // the 100KB dump is gone
    assert.ok(html.includes(small)); // the tiny icon survives
    assert.ok(html.length < 10000);
  });
  it("wraps tables so they scroll internally instead of overflowing", async () => {
    const { sanitize } = await import("../server/sanitize.js");
    const { html } = sanitize(`<table><tr><td>a</td></tr></table>`,
      { mediaPrefix: "/m", linkPrefix: "/r/c", pageDir: "" });
    assert.ok(html.includes('<div class="tscroll"><table>'));
    assert.ok(html.includes("</table></div>"));
  });
});
