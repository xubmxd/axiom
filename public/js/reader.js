// Reading: scroll-based progress + resume + active-time only (visible + recent interaction).
// Completion is scroll-driven: only genuine scrolling past the threshold (or the
// manual button) completes a page — a short page that fits the viewport does NOT
// auto-complete on load.
(() => {
  const root = document.querySelector('.learn.reading[data-page]');
  if (!root) return;
  const pageId = root.dataset.page, courseId = root.dataset.course;
  const threshold = parseFloat(root.dataset.threshold || "0.9");
  const tabId = Math.random().toString(36).slice(2);
  const tzOffset = new Date().getTimezoneOffset();
  const bar = document.querySelector("#readProgress i");
  const doneBtn = document.getElementById("btnDone");
  const startPx = parseInt(root.dataset.scroll || "0", 10);
  let activeAccum = 0, lastInteract = Date.now(), maxPct = 0, done = doneBtn?.classList.contains("done");

  // Restore saved position after layout settles (images shift content):
  // try immediately, again on window load, and once more after 1.2s.
  function restore() {
    if (startPx > 0) {
      try { window.scrollTo(0, startPx); } catch {}
      maxPct = Math.max(maxPct, progress());
      paint();
    }
  }
  restore();
  window.addEventListener("load", () => { restore(); setTimeout(restore, 1200); });

  ["scroll", "pointermove", "keydown", "touchstart"].forEach((ev) =>
    window.addEventListener(ev, () => { lastInteract = Date.now(); }, { passive: true }));
  setInterval(() => {
    const visible = !document.hidden;
    const engaged = Date.now() - lastInteract < 60_000; // inactivity timeout (configurable server-side default 60s)
    if (visible && engaged) activeAccum += 2;
  }, 2000);
  setInterval(report, 12000);
  document.addEventListener("visibilitychange", () => { if (document.hidden) report(); });
  window.addEventListener("beforeunload", () => {
    navigator.sendBeacon?.("/api/progress/reading", new Blob([JSON.stringify({ pageId, scrollPct: maxPct, scrollPx: window.scrollY, activeDelta: activeAccum, tabId, tzOffset })], { type: "application/json" }));
  });
  let ticking = false;
  window.addEventListener("scroll", () => {
    if (ticking) return; ticking = true;
    requestAnimationFrame(() => {
      maxPct = Math.max(maxPct, progress());
      paint();
      ticking = false;
      if (!done && maxPct >= threshold) markDone(true);
    });
  }, { passive: true });

  function paint() {
    if (bar) bar.style.width = Math.round(Math.max(maxPct, progress()) * 100) + "%";
  }
  function progress() {
    const h = document.documentElement;
    const max = h.scrollHeight - h.clientHeight;
    return max <= 0 ? maxPct : Math.max(0, Math.min(1, h.scrollTop / max));
  }
  async function report() {
    const delta = activeAccum; activeAccum = 0;
    if (maxPct === 0 && delta === 0) return;
    try {
      const r = await fetch("/api/progress/reading", { method: "POST", headers: { "Content-Type": "application/json", "x-tz-offset": tzOffset }, body: JSON.stringify({ pageId, scrollPct: maxPct, scrollPx: Math.round(window.scrollY), activeDelta: delta, tabId, tzOffset }) });
      if ((await r.json()).completed) showDone();
    } catch {}
  }
  async function markDone(auto) {
    try {
      const r = await fetch("/api/progress/reading", { method: "POST", headers: { "Content-Type": "application/json", "x-tz-offset": tzOffset }, body: JSON.stringify({ pageId, scrollPct: maxPct, scrollPx: Math.round(window.scrollY), activeDelta: 0, completed: true, tabId, tzOffset }) });
      if ((await r.json()).completed) { showDone(); if (!auto) toast("Marked complete"); }
    } catch { toast("Couldn't save — retry"); }
  }
  function showDone() { done = true; if (doneBtn) { doneBtn.classList.add("done"); doneBtn.textContent = "✓ Completed"; } }
  if (doneBtn) doneBtn.onclick = () => markDone(false);
})();
