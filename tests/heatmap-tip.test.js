import { describe, it } from "node:test";
import assert from "node:assert/strict";

// Placement engine behind the floating Activity tooltip: prefers above the
// cell, flips below at the top edge, clamps horizontally, always stays in
// the viewport (given a tip that fits — CSS max-width guarantees this).
const VW = 1440, VH = 900, TW = 180, TH = 90, PAD = 10;
const cell = (top, left, w = 14, h = 14) => ({ top, left, bottom: top + h, right: left + w });

function insideViewport(p) {
  assert.ok(p.x >= PAD, `x ${p.x} respects left margin`);
  assert.ok(p.y >= PAD, `y ${p.y} respects top margin`);
  assert.ok(p.x + TW <= VW - PAD, `right edge ${p.x + TW} inside ${VW}`);
  assert.ok(p.y + TH <= VH - PAD, `bottom edge ${p.y + TH} inside ${VH}`);
}

describe("heatmap tooltip placement", () => {
  it("sits above centered cells with room", async () => {
    const { placeTip } = await import("../public/js/tip.js");
    const p = placeTip(cell(400, 700), TW, TH, VW, VH);
    assert.equal(p.side, "above");
    assert.equal(p.y, 400 - TH - 10);
    assert.equal(p.x, Math.round(707 - TW / 2));
    insideViewport(p);
  });
  it("top-left / top-center / top-right flip below and clamp", async () => {
    const { placeTip } = await import("../public/js/tip.js");
    for (const [name, c] of [["tl", cell(60, 60)], ["tc", cell(60, 700)], ["tr", cell(60, 1360)]]) {
      const p = placeTip(c, TW, TH, VW, VH);
      assert.equal(p.side, "below", name);
      assert.equal(p.y, c.bottom + 10, name);
      insideViewport(p);
    }
  });
  it("middle-left / center / middle-right stay above and inside", async () => {
    const { placeTip } = await import("../public/js/tip.js");
    for (const [name, c] of [["ml", cell(450, 8)], ["c", cell(450, 700)], ["mr", cell(450, 1420)]]) {
      const p = placeTip(c, TW, TH, VW, VH);
      assert.equal(p.side, "above", name);
      insideViewport(p);
    }
    // left edge pins to the margin instead of centering off-screen
    assert.equal(placeTip(cell(450, 8), TW, TH, VW, VH).x, PAD);
  });
  it("bottom-left / bottom-center / bottom-right stay above", async () => {
    const { placeTip } = await import("../public/js/tip.js");
    for (const [name, c] of [["bl", cell(860, 60)], ["bc", cell(860, 700)], ["br", cell(860, 1360)]]) {
      const p = placeTip(c, TW, TH, VW, VH);
      assert.equal(p.side, "above", name);
      insideViewport(p);
    }
  });
  it("pins inside short viewports instead of overflowing", async () => {
    const { placeTip } = await import("../public/js/tip.js");
    // laptop height: below would overflow, so it pins to the bottom margin
    const p = placeTip(cell(20, 600, 14, 14), 180, 700, 1366, 768);
    assert.ok(p.y + 700 <= 768 - PAD || p.y === PAD);
    // phone width: horizontal clamp keeps it on screen
    const m = placeTip(cell(300, 300), 180, 90, 375, 667);
    assert.ok(m.x >= PAD && m.x + 180 <= 375 - PAD);
    assert.ok(m.y >= PAD && m.y + 90 <= 667 - PAD);
  });
  it("moves stably: adjacent cells shift by roughly one cell", async () => {
    const { placeTip } = await import("../public/js/tip.js");
    const a = placeTip(cell(400, 700), TW, TH, VW, VH);
    const b = placeTip(cell(400, 719), TW, TH, VW, VH);
    assert.equal(a.side, b.side);
    assert.ok(Math.abs(a.x - b.x) <= 20 && a.y === b.y);
  });
});
