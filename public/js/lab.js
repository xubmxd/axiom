// Cyber Range lab workspace: tabs, lifecycle, submissions, notes, terminal.
// Server is the source of truth — every mutation goes through the lab API
// and the UI reflects the server's response (progress is never faked).
document.addEventListener("DOMContentLoaded", () => {
  const wrap = document.querySelector(".labwrap");
  if (!wrap) return;
  const labId = wrap.dataset.lab;

  // ---------- tabs (click + arrow-key navigation) ----------
  const tabs = [...wrap.querySelectorAll('[role="tab"]')];
  const panels = [...wrap.querySelectorAll('[role="tabpanel"]')];
  function selectTab(btn, focus = false) {
    for (const t of tabs) {
      const on = t === btn;
      t.setAttribute("aria-selected", String(on));
      t.tabIndex = on ? 0 : -1;
      if (on && focus) t.focus();
    }
    for (const p of panels) p.hidden = p.id !== btn.getAttribute("aria-controls");
  }
  tabs.forEach((t, i) => {
    t.addEventListener("click", () => selectTab(t));
    t.addEventListener("keydown", (e) => {
      if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
      e.preventDefault();
      const next = tabs[(i + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length];
      selectTab(next, true);
    });
  });

  // ---------- copy buttons ----------
  // Async clipboard needs a secure context (HTTPS/localhost); plain-HTTP
  // LAN access falls back to the legacy execCommand path.
  async function copyText(text) {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        return true;
      }
      throw new Error("async clipboard unavailable");
    } catch {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      let ok = false;
      try { ok = document.execCommand("copy"); } catch { ok = false; }
      ta.remove();
      return ok;
    }
  }
  wrap.addEventListener("click", async (e) => {
    const b = e.target.closest("[data-copy]");
    if (!b) return;
    toast(await copyText(b.dataset.copy || "") ? "Copied" : "Copy failed — select and copy manually");
  });

  const msgEl = wrap.querySelector("[data-action-msg]");
  const say = (t) => { if (msgEl) msgEl.textContent = t; };

  // ---------- lifecycle (authoritative reload after state change) ----------
  wrap.addEventListener("click", async (e) => {
    const b = e.target.closest("[data-lab-action]");
    if (!b) return;
    const action = b.dataset.labAction;
    b.disabled = true;
    say(action === "start" ? "Provisioning isolated target…" : action === "reset" ? "Rebuilding environment…" : "Tearing down…");
    try {
      const r = await fetch(`/api/labs/${encodeURIComponent(labId)}/${action}`, { method: "POST" });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.error || `${action} failed`);
      toast(action === "start" ? "Lab running" : action === "reset" ? "Lab reset complete" : "Lab stopped");
      location.reload();
    } catch (err) {
      say(err.message || "Action failed.");
      toast(err.message || "Action failed.");
      b.disabled = false;
    }
  });

  // ---------- submissions (no page reload) ----------
  const form = document.getElementById("submitForm");
  if (form) {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const answers = {};
      for (const input of form.querySelectorAll("input[name]")) {
        if (input.value.trim()) answers[input.name] = input.value;
      }
      if (!Object.keys(answers).length) { toast("Enter an answer first."); return; }
      const btn = form.querySelector('button[type="submit"]');
      btn.disabled = true;
      try {
        const r = await fetch(`/api/labs/${encodeURIComponent(labId)}/submit`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ answers }),
        });
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(j.error || "Submission failed.");
        for (const [key, result] of Object.entries(j.results || {})) {
          const fb = form.querySelector(`[data-fb="${CSS.escape(key)}"]`);
          if (fb) {
            fb.textContent = result.correct ? "✓ Correct" : result.error || "✗ Incorrect — try again";
            fb.classList.toggle("fb-ok", !!result.correct);
            fb.classList.toggle("fb-bad", !result.correct);
          }
          const input = form.querySelector(`input[name="${CSS.escape(key)}"]`);
          if (input && result.correct) { input.disabled = true; }
        }
        if (j.progress) paintProgress(j.progress);
        const allOk = Object.values(j.results || {}).every((x) => x.correct || x.completed);
        toast(allOk ? "Answer accepted" : "Checked — see feedback above");
      } catch (err) {
        toast(err.message || "Submission failed.");
      } finally { btn.disabled = false; }
    });
  }

  function paintProgress(p) {
    const count = wrap.querySelector("[data-progress-count]");
    if (count) count.textContent = `${p.done} / ${p.total} completed · ${p.pct}%`;
    const list = wrap.querySelector("[data-checklist]");
    if (list) {
      const items = list.querySelectorAll(".check-item");
      // item 0 = start the lab; the rest map to objectives in order
      if (items[0] && p.started) { items[0].classList.add("done"); items[0].querySelector(".check-box").textContent = "✓"; }
      (p.objectives || []).forEach((o, i) => {
        const li = items[i + 1];
        if (li && o.completed) { li.classList.add("done"); li.querySelector(".check-box").textContent = "✓"; }
      });
    }
  }

  // ---------- elapsed timer ----------
  const elapsedEl = wrap.querySelector("[data-elapsed]");
  const startedAt = wrap.dataset.startedAt;
  if (elapsedEl && startedAt) {
    const t0 = new Date(startedAt).getTime();
    const tick = () => {
      const s = Math.max(0, Math.floor((Date.now() - t0) / 1000));
      const h = String(Math.floor(s / 3600)).padStart(2, "0");
      const m = String(Math.floor((s % 3600) / 60)).padStart(2, "0");
      const ss = String(s % 60).padStart(2, "0");
      elapsedEl.textContent = `● ${h}:${m}:${ss}`;
    };
    tick();
    setInterval(tick, 1000);
  }

  // ---------- notes (explicit save + autosave) ----------
  const notes = document.getElementById("labNotes");
  const notesMsg = document.getElementById("notesMsg");
  async function saveNotes(silent) {
    if (!notes) return;
    try {
      const r = await fetch(`/api/labs/${encodeURIComponent(labId)}/notes`, {
        method: "PUT", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ body: notes.value }),
      });
      if (!r.ok) throw new Error();
      if (notesMsg) notesMsg.textContent = `Saved ${new Date().toLocaleTimeString()}`;
      if (!silent) toast("Notes saved");
    } catch { if (notesMsg) notesMsg.textContent = "Save failed — retry."; }
  }
  document.getElementById("saveNotes")?.addEventListener("click", () => saveNotes(false));
  let notesT = null;
  notes?.addEventListener("input", () => {
    if (notesMsg) notesMsg.textContent = "Editing…";
    clearTimeout(notesT);
    notesT = setTimeout(() => saveNotes(true), 2500);
  });

  // ---------- hints ----------
  wrap.addEventListener("click", async (e) => {
    const b = e.target.closest("[data-reveal-hint]");
    if (!b) return;
    b.disabled = true;
    try {
      const r = await fetch(`/api/labs/${encodeURIComponent(labId)}/hints/${encodeURIComponent(b.dataset.revealHint)}/reveal`, { method: "POST" });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.error || "Could not reveal hint.");
      const li = b.closest("li");
      if (li) li.innerHTML = `<div class="sech"><b></b></div><p></p>`;
      const title = li.querySelector("b"), body = li.querySelector("p");
      title.textContent = j.hint.title; body.textContent = j.hint.body;
      toast("Hint revealed");
    } catch (err) { toast(err.message || "Failed."); b.disabled = false; }
  });

  // ---------- integrated terminal (scoped; never a host shell) ----------
  const termForm = document.getElementById("termForm");
  const termInput = document.getElementById("termInput");
  const termOut = document.getElementById("termOut");
  function print(text, cls = "") {
    if (!termOut) return;
    const div = document.createElement("div");
    div.className = `term-line ${cls}`;
    div.textContent = text;
    termOut.appendChild(div);
    termOut.scrollTop = termOut.scrollHeight;
  }
  termForm?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const command = termInput.value.slice(0, 512);
    if (!command.trim()) return;
    print(`lab ❯ ${command}`, "term-echo");
    termInput.value = "";
    termInput.disabled = true;
    try {
      const r = await fetch(`/api/labs/${encodeURIComponent(labId)}/terminal`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ command }),
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.error || "Terminal unavailable.");
      if (j.clear && termOut) termOut.innerHTML = "";
      if (j.output) print(j.output);
    } catch (err) {
      print(err.message || "Command failed.", "term-err");
    } finally { termInput.disabled = false; termInput.focus(); }
  });
});
