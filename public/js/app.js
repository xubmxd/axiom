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
  // Mobile navigation drawer: slide-in panel + scrim, focus trap, Escape and
  // focus return. The drawer is inert while closed so hidden links cannot be
  // reached from the keyboard.
  const t = document.getElementById("navToggle"), m = document.getElementById("mobileNav");
  const scrim = document.getElementById("navScrim");
  if (t && m && scrim) {
    const closeBtn = document.getElementById("navClose");
    let restoreFocus = null;
    const isOpen = () => m.classList.contains("open");
    const focusables = () => [...m.querySelectorAll('a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])')]
      .filter((el) => el.getClientRects().length > 0);
    const open = () => {
      restoreFocus = document.activeElement;
      m.inert = false;
      m.classList.add("open");
      scrim.classList.add("open");
      m.setAttribute("aria-hidden", "false");
      t.setAttribute("aria-expanded", "true");
      t.setAttribute("aria-label", "Close navigation");
      document.body.classList.add("mnav-open");
      (closeBtn || focusables()[0])?.focus({ preventScroll: true });
    };
    const shut = (restore = true) => {
      if (!isOpen()) return;
      m.classList.remove("open");
      scrim.classList.remove("open");
      m.setAttribute("aria-hidden", "true");
      t.setAttribute("aria-expanded", "false");
      t.setAttribute("aria-label", "Open navigation");
      document.body.classList.remove("mnav-open");
      m.inert = true;
      if (!restore) return;
      const target = restoreFocus && restoreFocus.isConnected ? restoreFocus : t;
      target.focus({ preventScroll: true });
    };
    t.onclick = () => (isOpen() ? shut() : open());
    closeBtn?.addEventListener("click", () => shut());
    scrim.addEventListener("click", () => shut());
    m.addEventListener("click", (e) => {
      if (e.target.closest?.("a[href]")) shut(false);
    });
    document.addEventListener("keydown", (e) => {
      if (!isOpen()) return;
      if (e.key === "Escape") { e.preventDefault(); shut(); return; }
      if (e.key !== "Tab") return;
      const f = focusables();
      if (!f.length) return;
      const first = f[0], last = f[f.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    });
    const desktop = window.matchMedia("(min-width: 901px)");
    desktop.addEventListener?.("change", (e) => { if (e.matches) shut(false); });
  }
  // Desktop sidebar collapse. One toggle lives in the sidebar header in both
  // states, so the CarnoSec mark stays a visible home anchor even collapsed.
  // Preference persists per browser (no backend needed).
  const nt = document.getElementById("appnavToggle");
  if (nt) {
    const apply = (collapsed) => {
      document.body.classList.toggle("nav-collapsed", collapsed);
      nt.setAttribute("aria-expanded", String(!collapsed));
      nt.setAttribute("aria-label", collapsed ? "Expand sidebar" : "Collapse sidebar");
      nt.textContent = collapsed ? "⟩" : "⟨";
      try { localStorage.setItem("carnosec:nav", collapsed ? "0" : "1"); } catch {}
    };
    let init = false;
    try { init = localStorage.getItem("carnosec:nav") === "0"; } catch {}
    apply(init);
    nt.onclick = () => apply(document.body.classList.contains("nav-collapsed") === false);
  }
  // Account menu: close on outside click and on Escape (details only handles
  // outside click natively), returning focus to the summary.
  document.addEventListener("click", (e) => {
    document.querySelectorAll("details.acct[open]").forEach((d) => { if (!d.contains(e.target)) d.removeAttribute("open"); });
  });
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    document.querySelectorAll("details.acct[open]").forEach((d) => {
      d.removeAttribute("open");
      d.querySelector("summary")?.focus({ preventScroll: true });
    });
  });
  const st = document.getElementById("sideToggle"), learn = document.querySelector(".learn");
  const side = document.getElementById("side");
  // Lesson navigation: the module panel is a sticky desktop sidebar and a
  // left drawer on mobile. The drawer shares the navigation drawer's
  // interaction model — scrim, Escape, focus trap, focus return and a body
  // scroll lock — while desktop collapse behaviour is unchanged. Mobile opens
  // closed so the lesson stays above the fold; the inline "Modules" control
  // in the breadcrumb row is the way back in.
  if (st && learn && side) {
    const mq = window.matchMedia("(max-width: 900px)");
    const isMobile = () => mq.matches;
    const stage = learn.querySelector(".stage");
    const scrim = document.getElementById("sideScrim");
    const closeBtn = document.getElementById("sideClose");
    const reopen = document.createElement("button");
    reopen.type = "button";
    reopen.id = "sideReopen";
    reopen.className = "modules-reopen";
    reopen.setAttribute("aria-controls", "side");
    reopen.setAttribute("title", "Show course modules");
    reopen.innerHTML = `<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M9 4v16"/></svg><span>Modules</span>`;
    reopen.setAttribute("aria-label", "Show course modules");
    // Inline at the start of the breadcrumb row (library / course / …)
    // so it shares the line instead of taking its own row above it.
    const crumbs = stage?.querySelector(".crumbs");
    if (crumbs) crumbs.prepend(reopen);
    else if (stage) stage.prepend(reopen);
    const drawerOpen = () => learn.classList.contains("side-drawer-open");
    const focusables = () => [...side.querySelectorAll('a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),summary,[tabindex]:not([tabindex="-1"])')]
      .filter((el) => {
        if (!el.getClientRects().length) return false;
        // Links inside a closed module group are not keyboard reachable,
        // even though Chromium still reports a box for them.
        for (let p = el; p && p !== side; p = p.parentElement) {
          if (p.tagName === "DETAILS" && !p.open) return false;
        }
        return true;
      });
    const sync = () => {
      const mobile = isMobile();
      const expanded = mobile && drawerOpen();
      const hidden = learn.classList.contains("side-hidden");
      reopen.setAttribute("aria-expanded", String(mobile ? expanded : !hidden));
      reopen.setAttribute("aria-label", (mobile ? expanded : !hidden) ? "Hide course modules" : "Show course modules");
      reopen.setAttribute("title", (mobile ? expanded : !hidden) ? "Hide course modules" : "Show course modules");
      if (mobile) {
        // The drawer is a modal while open; while closed it is inert so its
        // links are not reachable behind the lesson.
        side.inert = !expanded;
        if (expanded) {
          side.removeAttribute("aria-hidden");
          side.setAttribute("aria-modal", "true");
          side.setAttribute("role", "dialog");
        } else {
          side.setAttribute("aria-hidden", "true");
          side.removeAttribute("aria-modal");
          side.removeAttribute("role");
        }
        document.body.classList.toggle("modules-open", expanded);
      } else {
        side.inert = false;
        side.removeAttribute("aria-hidden");
        side.removeAttribute("aria-modal");
        side.removeAttribute("role");
        document.body.classList.remove("modules-open");
      }
      scrim?.classList.toggle("open", expanded);
    };
    const closeDrawer = (restore = true) => {
      if (!isMobile() || !drawerOpen()) return;
      learn.classList.add("side-hidden");
      learn.classList.remove("side-drawer-open");
      sync();
      if (restore) reopen.focus({ preventScroll: true });
    };
    const openDrawer = () => {
      if (!isMobile()) return;
      learn.classList.remove("side-hidden");
      learn.classList.add("side-drawer-open");
      sync();
      // Land on the current lesson so the drawer opens at the reader's place.
      const target = side.querySelector(".sles-a.on") || closeBtn || focusables()[0];
      target?.focus();
    };
    if (isMobile()) {
      learn.classList.add("side-hidden");
      learn.classList.remove("side-drawer-open");
    }
    sync();
    // Desktop collapse toggle.
    st.onclick = () => {
      learn.classList.toggle("side-hidden");
      sync();
    };
    reopen.onclick = () => {
      if (isMobile()) openDrawer();
      else {
        learn.classList.remove("side-hidden");
        sync();
        side.querySelector("a,button,summary")?.focus?.({ preventScroll: true });
      }
    };
    closeBtn?.addEventListener("click", () => closeDrawer());
    scrim?.addEventListener("click", () => closeDrawer());
    // Choosing a lesson closes the drawer for immediate feedback; the new
    // page opens collapsed on mobile anyway. Navigation is not intercepted.
    side.addEventListener("click", (e) => {
      const a = e.target.closest?.('a[href^="/learn/"]');
      if (!a || !isMobile()) return;
      learn.classList.add("side-hidden");
      learn.classList.remove("side-drawer-open");
      sync();
    });
    document.addEventListener("keydown", (e) => {
      if (!isMobile() || !drawerOpen()) return;
      if (e.key === "Escape") { e.preventDefault(); closeDrawer(); return; }
      if (e.key !== "Tab") return;
      const f = focusables();
      if (!f.length) return;
      const first = f[0], last = f[f.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    });
    // Crossing the breakpoint never leaves a drawer over the page or a body
    // scroll lock behind. Entering desktop restores the full sticky sidebar.
    mq.addEventListener?.("change", (e) => {
      learn.classList.remove("side-drawer-open");
      if (e.matches) learn.classList.add("side-hidden");
      else learn.classList.remove("side-hidden");
      sync();
    });
  } else if (st && learn) st.onclick = () => learn.classList.toggle("side-hidden");
  // Learn sidebar v2: Select mode, Expand all, lesson search. Navigation-first:
  // checkboxes + bulk toolbar stay hidden until selection is actually used.
  (() => {
    const side = document.getElementById("side");
    if (!side || !side.classList.contains("side-new")) return;
    const selectBtn = side.querySelector("[data-side-select]");
    const expandBtn = side.querySelector("[data-side-expand]");
    const search = side.querySelector("#sideSearch");
    const setSelecting = (on) => {
      side.dataset.selecting = on ? "on" : "off";
      selectBtn?.setAttribute("aria-pressed", String(on));
      if (selectBtn) selectBtn.textContent = on ? "Done" : "Select";
      side.querySelectorAll(".bulk-check").forEach((b) => { b.tabIndex = on ? 0 : -1; });
      if (!on) {
        let changed = false;
        side.querySelectorAll(".bulk-check:checked").forEach((b) => { b.checked = false; changed = true; });
        side.querySelectorAll("[data-bulk-mod]").forEach((m) => { m.checked = false; m.indeterminate = false; });
        if (changed) side.querySelector(".bulk-check")?.dispatchEvent(new Event("change", { bubbles: true }));
      } else {
        side.querySelector(".side-selbar [data-bulk-select-all]")?.focus?.({ preventScroll: true });
      }
    };
    selectBtn?.addEventListener("click", () => setSelecting(side.dataset.selecting !== "on"));
    const mods = () => [...side.querySelectorAll("details.smod")];
    const syncExpandLabel = () => {
      if (!expandBtn) return;
      const anyClosed = mods().some((d) => !d.open);
      expandBtn.textContent = anyClosed ? "Expand all" : "Collapse all";
    };
    expandBtn?.addEventListener("click", () => {
      const all = mods();
      const anyClosed = all.some((d) => !d.open);
      if (anyClosed) all.forEach((d) => { d.open = true; });
      else all.forEach((d) => { d.open = d.hasAttribute("data-active-child"); });
      syncExpandLabel();
    });
    side.querySelector(".side-scroll")?.addEventListener("toggle", (e) => {
      if (e.target?.matches?.("details.smod")) syncExpandLabel();
    }, true);
    syncExpandLabel();
    // Client-side lesson filter: matches bubble up so ancestors stay visible.
    if (search) {
      let empty = side.querySelector(".side-empty");
      if (!empty) {
        empty = document.createElement("p");
        empty.className = "side-empty";
        empty.textContent = "No lessons match your search.";
        side.querySelector(".side-scroll")?.appendChild(empty);
      }
      const applyFilter = () => {
        const q = search.value.trim().toLowerCase();
        const on = q.length > 0;
        side.dataset.searching = on ? "on" : "off";
        if (!on) {
          side.querySelectorAll("[data-match]").forEach((el) => el.removeAttribute("data-match"));
          side.querySelectorAll("details.smod").forEach((d) => { if (!d.hasAttribute("data-active-child")) d.open = false; else d.open = true; });
          side.dataset.nomatch = "off";
          syncExpandLabel();
          return;
        }
        let matches = 0;
        // leaves first (reverse DOM = deepest first), then ancestors inherit
        const all = [...side.querySelectorAll("details.smod, .sles-row")].reverse();
        side.querySelectorAll("[data-match]").forEach((el) => el.removeAttribute("data-match"));
        for (const el of all) {
          const self = (el.dataset.title || "").includes(q);
          const desc = el.querySelector?.("[data-match]") ? true : false;
          if (self || desc) { el.setAttribute("data-match", ""); if (el.classList.contains("sles-row")) matches++; }
          if (el.matches?.("details.smod") && (self || desc)) el.open = true;
        }
        // count group-title matches too for the empty-state decision
        if (!matches) matches = side.querySelectorAll("details.smod[data-match]").length;
        side.dataset.nomatch = matches ? "off" : "on";
      };
      search.addEventListener("input", applyFilter);
    }
  })();
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
window.saveJSON = (url, msgId, formEl) => async (e) => {
  e.preventDefault();
  const form = formEl || e.target;
  const fd = new FormData(form);
  const body = {};
  for (const [k, v] of fd) body[k] = form.querySelector(`[name="${k}"]`)?.type === "checkbox" ? form.querySelector(`[name="${k}"]`).checked : v;
  const status = form.querySelector("[data-form-status]");
  const btn = form.querySelector('button[type="submit"]');
  const setStatus = (text, bad = false) => {
    if (status) { status.textContent = text; status.classList.toggle("bad", bad); }
    const m = document.getElementById(msgId);
    if (m) {
      m.innerHTML = "";
      if (bad) {
        const div = document.createElement("div");
        div.className = "alert"; div.textContent = text;
        m.appendChild(div);
      }
    }
  };
  if (btn) btn.disabled = true;
  setStatus("Saving…");
  try {
    const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok || !j.ok) throw new Error(j.error || "Save failed.");
    setStatus("Saved just now");
    toast("Saved");
    if (form.id === "passForm") form.reset();
  } catch (err) {
    setStatus(err.message || "Save failed. Nothing was changed.", true);
    toast(err.message || "Save failed");
  } finally {
    if (btn) btn.disabled = false;
  }
};
