// Bulk mark-watched: multi-select video lessons on the course page and the
// learn sidebar, then mark all selected as watched / unwatched in one call.
// Supports per-module checkboxes ([data-bulk-mod]) that select all videos in
// that module's container (course page: section.mod/details.mod,
// sidebar: details.tnode).
(() => {
  const bars = [...document.querySelectorAll("[data-bulk-bar]")];
  const boxes = [...document.querySelectorAll(".bulk-check")];
  const mods = [...document.querySelectorAll("[data-bulk-mod]")];
  if (!bars.length || !boxes.length) return;
  const tzOffset = new Date().getTimezoneOffset();

  const selected = () => boxes.filter((b) => b.checked).map((b) => b.value);
  const scopeOf = (mod) => mod.closest("section.mod, details.mod, details.tnode");
  const boxesIn = (scope) => scope ? [...scope.querySelectorAll(".bulk-check")] : [];

  function sync() {
    const n = selected().length;
    for (const bar of bars) {
      const count = bar.querySelector("[data-bulk-count]");
      if (count) count.textContent = `${n} selected`;
      for (const sel of ["[data-bulk-done]", "[data-bulk-undone]", "[data-bulk-clear]"]) {
        const btn = bar.querySelector(sel);
        if (btn) btn.disabled = n === 0;
      }
      const all = bar.querySelector("[data-bulk-select-all]");
      if (all) {
        all.checked = n > 0 && n === boxes.length;
        all.indeterminate = n > 0 && n < boxes.length;
      }
    }
    // per-module state follows its own descendant checkboxes
    for (const mod of mods) {
      const items = boxesIn(scopeOf(mod));
      const c = items.filter((b) => b.checked).length;
      mod.checked = items.length > 0 && c === items.length;
      mod.indeterminate = c > 0 && c < items.length;
    }
  }

  for (const bar of bars) {
    bar.querySelector("[data-bulk-select-all]")?.addEventListener("change", (e) => {
      for (const b of boxes) b.checked = e.target.checked;
      sync();
    });
    bar.querySelector("[data-bulk-clear]")?.addEventListener("click", () => {
      for (const b of boxes) b.checked = false;
      sync();
    });
    bar.querySelector("[data-bulk-done]")?.addEventListener("click", () => send(true, bar));
    bar.querySelector("[data-bulk-undone]")?.addEventListener("click", () => send(false, bar));
  }
  for (const mod of mods) {
    // a checkbox inside <summary> would otherwise toggle the <details>
    mod.addEventListener("click", (e) => e.stopPropagation());
    mod.closest("label")?.addEventListener("click", (e) => e.stopPropagation());
    mod.addEventListener("change", () => {
      for (const b of boxesIn(scopeOf(mod))) b.checked = mod.checked;
      sync();
    });
  }
  boxes.forEach((b) => b.addEventListener("change", sync));
  sync();

  async function send(completed, bar) {
    const lessonIds = selected();
    if (!lessonIds.length) return;
    const btns = [...bar.querySelectorAll("button")];
    btns.forEach((b) => { b.disabled = true; });
    try {
      const r = await fetch("/api/progress/video/bulk", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-tz-offset": String(tzOffset) },
        body: JSON.stringify({ lessonIds, completed, tzOffset }),
      });
      const j = await r.json();
      if (!r.ok || !j.ok) throw new Error(j.error || "Bulk update failed");
      toast(completed ? `Marked ${j.updated} as watched` : `Marked ${j.updated} as unwatched`);
      setTimeout(() => location.reload(), 600);
    } catch (e) {
      toast(e.message || "Couldn't save — retry");
      sync();
    }
  }
})();
