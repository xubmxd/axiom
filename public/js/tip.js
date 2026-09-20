// Floating Activity heatmap tooltip.
//
// Why a portal: the old ::after tooltip lived inside .act-main, which is
// overflow:hidden (and .graph becomes a scroll container on small screens),
// so top-row tooltips were clipped no matter the z-index. This single
// element hangs off <body> with position:fixed, escaping every heatmap
// clipping ancestor. Collision logic (placeTip) is pure and unit-tested.
//
// Loaded as a module (deferred by default, DOM is ready). Without module
// support the CSS ::after fallback still shows — progressively enhanced.
export const TIP_PAD = 10; // viewport safety margin, px
const GAP = 10; // cell-to-tooltip gap, px

// Viewport rects in, tooltip origin out. Prefers above the cell, flips
// below when the top is constrained, pins inside when both are, and always
// clamps horizontally. Callers must keep tipW within the viewport
// (CSS max-width does this) for the guarantees below to hold.
export function placeTip(cell, tipW, tipH, vw, vh, pad = TIP_PAD) {
  let side = "above";
  let y = cell.top - tipH - GAP;
  if (y < pad) {
    side = "below";
    y = cell.bottom + GAP;
  }
  if (y + tipH > vh - pad) y = Math.max(pad, vh - tipH - pad);
  let x = (cell.left + cell.right) / 2 - tipW / 2;
  x = Math.min(Math.max(x, pad), Math.max(pad, vw - tipW - pad));
  return { x: Math.round(x), y: Math.round(y), side };
}

if (typeof document !== "undefined") init();

function init() {
  if (!document.querySelector(".cell[data-tip]")) return;
  const tip = document.createElement("div");
  tip.className = "heatip";
  tip.hidden = true;
  tip.setAttribute("aria-hidden", "true");
  document.body.appendChild(tip);
  // Suppresses the ::after fallback so the two never double-render.
  document.body.classList.add("has-heatip");

  let mode = null; // 'pointer' | 'focus' | null
  let raf = 0;

  const show = (cell, m) => {
    const text = cell.dataset ? cell.dataset.tip : null;
    if (!text) return;
    mode = m;
    tip.textContent = text;
    tip.hidden = false;
    // One frame batches measure+place, so gliding across adjacent cells
    // moves the visible tooltip instead of flashing it.
    cancelAnimationFrame(raf);
    raf = requestAnimationFrame(() => {
      const r = tip.getBoundingClientRect();
      const c = cell.getBoundingClientRect();
      const p = placeTip(c, r.width, r.height, window.innerWidth, window.innerHeight);
      tip.style.transform = "translate(" + p.x + "px," + p.y + "px)";
      tip.dataset.side = p.side;
      tip.classList.add("on");
    });
  };
  const hide = () => {
    mode = null;
    cancelAnimationFrame(raf);
    tip.classList.remove("on");
    tip.hidden = true;
  };
  const cellFromEvent = (e) => (e.target && e.target.closest ? e.target.closest(".cell[data-tip]") : null);
  const activeCell = () => {
    const a = document.activeElement;
    return a && a.closest ? a.closest(".cell[data-tip]") : null;
  };

  // Pointer: show on cell, hide when leaving to anything else.
  document.addEventListener("pointerover", (e) => {
    const c = cellFromEvent(e);
    if (c) show(c, "pointer");
    else if (mode === "pointer") hide();
  });
  // Keyboard: cells are focusable (tabindex=0).
  document.addEventListener("focusin", (e) => {
    const c = cellFromEvent(e);
    if (c) show(c, "focus");
  });
  document.addEventListener("focusout", (e) => {
    const to = e.relatedTarget;
    if (!to || !(to.closest && to.closest(".cell[data-tip]"))) hide();
  });
  // A stale position is worse than none: pointer tips dismiss on scroll or
  // resize, focus tips re-anchor to the focused cell.
  const onViewChange = () => {
    if (mode === "pointer") hide();
    else if (mode === "focus") {
      const a = activeCell();
      if (a) show(a, "focus");
      else hide();
    }
  };
  document.addEventListener("scroll", onViewChange, { capture: true, passive: true });
  window.addEventListener("resize", onViewChange);
  // Touch: tapping outside a cell dismisses a stuck tip.
  document.addEventListener("click", (e) => {
    if (mode && !cellFromEvent(e)) hide();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && mode) hide();
  });
}
