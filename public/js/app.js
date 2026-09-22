function toast(msg) {
  const box = document.getElementById("toasts");
  if (!box) return;
  const el = document.createElement("div");
  el.className = "toast"; el.textContent = msg;
  box.appendChild(el);
  setTimeout(() => el.remove(), 3200);
}
window.toast = toast;
document.addEventListener("DOMContentLoaded", () => {
  const t = document.getElementById("navToggle"), m = document.getElementById("mobileNav");
  if (t && m) t.onclick = () => { const open = m.classList.toggle("open"); t.setAttribute("aria-expanded", String(open)); };
  // Desktop sidebar collapse. One toggle lives in the sidebar header in both
  // states, so the Axiom mark stays a visible home anchor even collapsed.
  // Preference persists per browser (no backend needed).
  const nt = document.getElementById("appnavToggle");
  if (nt) {
    const apply = (collapsed) => {
      document.body.classList.toggle("nav-collapsed", collapsed);
      nt.setAttribute("aria-expanded", String(!collapsed));
      nt.setAttribute("aria-label", collapsed ? "Expand sidebar" : "Collapse sidebar");
      nt.textContent = collapsed ? "⟩" : "⟨";
      try { localStorage.setItem("axiom:nav", collapsed ? "0" : "1"); } catch {}
    };
    let init = false;
    try { init = localStorage.getItem("axiom:nav") === "0"; } catch {}
    apply(init);
    nt.onclick = () => apply(document.body.classList.contains("nav-collapsed") === false);
  }
  // close the account menu on outside click / Escape is native to <details>
  document.addEventListener("click", (e) => {
    document.querySelectorAll("details.acct[open]").forEach((d) => { if (!d.contains(e.target)) d.removeAttribute("open"); });
  });
  const st = document.getElementById("sideToggle"), learn = document.querySelector(".learn");
  const side = document.getElementById("side");
  // Mobile lesson navigation: selecting a lesson auto-collapses the module
  // panel (MPA navigation reloads the page, so the collapsed intent is kept
  // in sessionStorage and applied on the next lesson load — mobile only,
  // desktop behavior unchanged). State changes only from real user actions:
  // tapping a lesson link, the sidebar toggle, or the reopen control.
  if (st && learn && side) {
    const KEY = "axiom:learn-side";
    const mq = window.matchMedia("(max-width: 900px)");
    const isMobile = () => mq.matches;
    const stage = learn.querySelector(".stage");
    const reopen = document.createElement("button");
    reopen.type = "button";
    reopen.id = "sideReopen";
    reopen.className = "btn xs modules-reopen";
    reopen.setAttribute("aria-controls", "side");
    reopen.innerHTML = `<span aria-hidden="true">☰</span> Modules`;
    reopen.setAttribute("aria-label", "Show course modules");
    if (stage) stage.prepend(reopen);
    const read = () => { try { return sessionStorage.getItem(KEY); } catch { return null; } };
    const save = (v) => { try { sessionStorage.setItem(KEY, v); } catch {} };
    const sync = () => {
      const hidden = learn.classList.contains("side-hidden");
      reopen.setAttribute("aria-expanded", String(!hidden));
      reopen.setAttribute("aria-label", hidden ? "Show course modules" : "Hide course modules");
    };
    // Apply the post-selection collapsed state on mobile loads only; the
    // initial visit (no stored intent) stays expanded.
    try { if (isMobile() && read() === "hidden") learn.classList.add("side-hidden"); } catch {}
    sync();
    st.onclick = () => {
      learn.classList.toggle("side-hidden");
      if (isMobile()) save(learn.classList.contains("side-hidden") ? "hidden" : "open");
      sync();
    };
    reopen.onclick = () => {
      // Reopen control only shows while collapsed on mobile; clicking it
      // always expands.
      learn.classList.remove("side-hidden");
      if (isMobile()) save("open");
      sync();
      side.querySelector("a,button,summary")?.focus?.({ preventScroll: true });
    };
    // Real selection event: a lesson/page link inside the module panel.
    // Collapse immediately for feedback; the stored intent collapses the
    // freshly loaded lesson page. Desktop untouched. No preventDefault —
    // navigation proceeds exactly as before.
    side.addEventListener("click", (e) => {
      const a = e.target.closest?.('a[href^="/learn/"]');
      if (!a || !isMobile()) return;
      learn.classList.add("side-hidden");
      save("hidden");
      sync();
    });
    // Viewport changes only re-sync the reopen control's labels; the
    // collapsed/expanded state itself is never altered by resize/orientation.
    mq.addEventListener?.("change", sync);
  } else if (st && learn) st.onclick = () => learn.classList.toggle("side-hidden");
  const bf = document.getElementById("btnFocus");
  if (bf && learn) bf.onclick = () => { learn.classList.toggle("focus"); bf.textContent = learn.classList.contains("focus") ? "Exit focus" : "Focus mode"; };
  // Ctrl/⌘+K focuses the topbar search from anywhere (except while typing).
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
      if (/input|select|textarea/i.test(e.target.tagName)) return;
      e.preventDefault();
      document.querySelector(".tsearch input")?.focus();
    }
  });
});
window.saveJSON = (url, msgId) => async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const body = {};
  for (const [k, v] of fd) body[k] = e.target.querySelector(`[name="${k}"]`)?.type === "checkbox" ? e.target.querySelector(`[name="${k}"]`).checked : v;
  const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const j = await r.json();
  const m = document.getElementById(msgId);
  if (j.ok) { toast("Saved"); if (m) m.innerHTML = ""; }
  else { toast(j.error || "Save failed"); if (m) m.innerHTML = `<div class="alert">${j.error || "Failed"}</div>`; }
  return false;
};
