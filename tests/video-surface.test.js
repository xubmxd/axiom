// Player surface behavior: taps/clicks on empty video space must never
// toggle playback. Play/pause lives on the center + transport buttons
// (and keyboard). Touch double-taps on the sides seek -10s/+10s.
// Executes the real public/js/video.js with a stub DOM.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";

const REPO = path.resolve(import.meta.dirname, "..");
const SRC = fs.readFileSync(path.join(REPO, "public/js/video.js"), "utf8");

function makeClassList() {
  const s = new Set();
  return {
    add: (c) => s.add(c),
    remove: (c) => s.delete(c),
    contains: (c) => s.has(c),
    toggle: (c, f) => { (f ?? !s.has(c)) ? s.add(c) : s.delete(c); },
  };
}

function makeEl(id) {
  const handlers = {};
  const el = {
    id,
    dataset: {},
    classList: makeClassList(),
    className: "",
    style: {},
    children: [],
    offsetWidth: 0,
    hidden: id === "pMenu",
    textContent: "",
    innerHTML: "",
    value: "1",
    _handlers: handlers,
    addEventListener: (t, fn) => { (handlers[t] ||= []).push(fn); },
    removeEventListener: () => {},
    setPointerCapture: () => {},
    appendChild: (c) => { el.children.push(c); return c; },
    getBoundingClientRect: () => ({ left: 0, width: 100 }),
    setAttribute: () => {},
    querySelector: (sel) => {
      const cls = sel.startsWith(".") ? sel.slice(1) : null;
      return el.children.find((c) => cls && c.className.split(" ").includes(cls)) || null;
    },
    closest: () => null,
    focus: () => {},
    onclick: null,
    ondblclick: null,
    oninput: null,
  };
  return el;
}

// touchHoverNone=true simulates a touch-first device.
function buildContext(touchHoverNone) {
  const els = {};
  const getEl = (id) => (els[id] ||= makeEl(id));
  const v = getEl("vid");
  v.paused = true;
  v.playCount = 0;
  v.pauseCount = 0;
  const fire = (type, ev = {}) => {
    for (const fn of (v._handlers[type] || [])) fn({ target: v, ...ev });
  };
  v.play = () => { v.paused = false; v.playCount++; fire("play"); fire("playing"); };
  v.pause = () => { v.paused = true; v.pauseCount++; fire("pause"); };
  v.duration = 100;
  v.currentTime = 0;
  v.volume = 1;
  v.muted = false;
  v.playbackRate = 1;
  v.textTracks = [];
  v.buffered = { length: 0 };
  v.tagName = "VIDEO";
  const root = {
    dataset: { lesson: "l1", course: "c1", threshold: "0.9", autoplay: "0", pos: "0", speed: "1" },
    classList: makeClassList(),
  };
  const sandbox = {
    console, Math, JSON, String, Number, performance,
    setInterval: () => 0,
    clearInterval: () => {},
    setTimeout: () => 0,
    clearTimeout: () => {},
    matchMedia: () => ({ matches: touchHoverNone }),
    screen: {},
    fetch: async () => ({ json: async () => ({}) }),
    document: {
      querySelector: (sel) => (sel === ".learn[data-lesson]" ? root : null),
      querySelectorAll: () => [],
      getElementById: (id) => getEl(id),
      createElement: (tag) => makeEl(tag),
      addEventListener: () => {},
      hidden: false,
      hasFocus: () => true,
    },
    window: { addEventListener: () => {} },
  };
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(SRC, sandbox, { filename: "video.js" });
  const player = getEl("player");
  const tap = ({ pointerType = "mouse", idle = false, touchEvent = false, clientX = undefined } = {}) => {
    if (idle) player.classList.add("idle");
    for (const fn of (player._handlers.pointerdown || [])) fn({ target: v, pointerType });
    if (typeof player.onclick === "function") {
      player.onclick({
        target: v,
        clientX,
        pointerType: undefined,
        sourceCapabilities: touchEvent ? { firesTouchEvents: true } : undefined,
      });
    }
  };
  return { v, player, bigPlay: getEl("bigPlay"), btnPlay: getEl("btnPlay"), tap };
}

const TOUCH = { pointerType: "touch", touchEvent: true };

describe("video surface never toggles playback", () => {
  it("touch reveal tap shows chrome without pausing", () => {
    const { v, player, tap } = buildContext(true);
    v.paused = false;
    tap({ ...TOUCH, idle: true });
    assert.equal(v.pauseCount, 0);
    assert.ok(!player.classList.contains("idle"));
    assert.equal(v.paused, false);
  });

  it("touch tap on visible chrome does not pause", () => {
    const { v, tap } = buildContext(true);
    v.paused = false;
    tap({ ...TOUCH, idle: false });
    assert.equal(v.pauseCount, 0);
  });

  it("pointerType-only touch tap (no sourceCapabilities) does not pause", () => {
    const { v, player, tap } = buildContext(true);
    v.paused = false;
    tap({ pointerType: "touch", idle: true, touchEvent: false });
    assert.equal(v.pauseCount, 0);
    assert.ok(!player.classList.contains("idle"));
  });

  it("mouse click on empty space does not pause", () => {
    const { v, tap } = buildContext(false);
    v.paused = false;
    tap({ pointerType: "mouse", idle: false });
    assert.equal(v.pauseCount, 0);
  });

  it("mouse click while idle only reveals", () => {
    const { v, player, tap } = buildContext(false);
    v.paused = false;
    tap({ pointerType: "mouse", idle: true });
    assert.equal(v.pauseCount, 0);
    assert.ok(!player.classList.contains("idle"));
  });

  it("touch tap while paused does not auto-play", () => {
    const { v, tap } = buildContext(true);
    v.paused = true;
    tap({ ...TOUCH, idle: false });
    assert.equal(v.playCount, 0);
    assert.equal(v.paused, true);
  });

  it("center + transport buttons toggle exactly once", () => {
    const { v, player, bigPlay, btnPlay } = buildContext(true);
    v.paused = true;
    bigPlay.onclick({ target: bigPlay });
    assert.equal(v.playCount, 1);
    assert.equal(v.paused, false);
    player.onclick({ target: { closest: () => bigPlay } });
    assert.equal(v.pauseCount, 0);
    assert.equal(v.playCount, 1);
    btnPlay.onclick();
    assert.equal(v.pauseCount, 1);
  });

  it("beat fires on pause only, never on resume", () => {
    const { v, player, bigPlay } = buildContext(true);
    v.paused = true;
    bigPlay.onclick({ target: bigPlay });
    assert.ok(!player.classList.contains("flash"));
    bigPlay.onclick({ target: bigPlay });
    assert.ok(player.classList.contains("flash"));
    assert.equal(v.paused, true);
  });
});

describe("video double-tap side seek", () => {
  it("seeks -10s/+10s cumulatively with ripple, middle resets", () => {
    const { v, player, tap } = buildContext(true);
    v.paused = false;
    v.currentTime = 50;
    const flashes = () => player.children.filter((c) => c.className.includes("seekflash"));
    tap({ ...TOUCH, idle: true, clientX: 10 });
    assert.equal(v.currentTime, 50);
    tap({ ...TOUCH, clientX: 10 });
    assert.equal(v.currentTime, 40);
    const left = flashes().find((c) => c.className.includes("left"));
    assert.ok(left && left.hidden === false);
    assert.ok(left.children.some((c) => c.className.includes("seekdelta") && c.textContent === "-10"));
    tap({ ...TOUCH, clientX: 10 });
    assert.equal(v.currentTime, 30);
    assert.ok(left.children.some((c) => c.className.includes("seekdelta") && c.textContent === "-20"));
    tap({ ...TOUCH, clientX: 90 });
    tap({ ...TOUCH, clientX: 90 });
    assert.equal(v.currentTime, 40);
    tap({ ...TOUCH, clientX: 50 });
    assert.equal(v.currentTime, 40);
  });

  it("clamps at zero and ignores slow second taps", () => {
    const { v, tap } = buildContext(true);
    v.paused = false;
    v.currentTime = 5;
    tap({ ...TOUCH, clientX: 10 });
    tap({ ...TOUCH, clientX: 10 });
    assert.equal(v.currentTime, 0);
    v.currentTime = 50;
    tap({ ...TOUCH, clientX: 50 });
    tap({ ...TOUCH, clientX: 10 });
    const end = Date.now() + 400;
    while (Date.now() < end) {}
    tap({ ...TOUCH, clientX: 10 });
    assert.equal(v.currentTime, 50);
  });
});
