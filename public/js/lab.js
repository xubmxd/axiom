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

  // ---------- stale-page guard ----------
  // The page is server-rendered: if the lab changed state elsewhere (other
  // tab, back-forward cache restore, a request lost to a reload), the
  // buttons no longer match reality — e.g. a stale Reset hits a stopped lab.
  // Reload on bfcache restore, and poll the true status in the background:
  // on mismatch offer a reload (never force it — notes/terminal hold state).
  window.addEventListener("pageshow", (e) => { if (e.persisted) location.reload(); });
  let stalePrompted = false;
  setInterval(async () => {
    if (stalePrompted || document.hidden) return;
    try {
      const r = await fetch(`/api/labs/${encodeURIComponent(labId)}/status`);
      const j = await r.json().catch(() => ({}));
      const serverStatus = j.instance ? j.instance.status : "stopped";
      if (serverStatus !== wrap.dataset.status) {
        stalePrompted = true;
        toast("Lab status changed — reload for the current state");
        if (msgEl) {
          msgEl.innerHTML = "";
          const span = document.createElement("span");
          span.textContent = "Lab status changed elsewhere. ";
          const btn = document.createElement("button");
          btn.className = "btn xs";
          btn.textContent = "Reload";
          btn.onclick = () => location.reload();
          msgEl.append(span, btn);
        }
      }
    } catch { /* next poll */ }
  }, 30000);

  // ---------- lifecycle (authoritative reload after state change) ----------
  // Docker teardown can take a minute on a slow daemon, and the request may
  // be queued behind another op — so a timed-out request does NOT mean the
  // op failed. On timeout we poll the true server-side status and reload as
  // soon as it reaches the expected state (self-healing "stuck" UI).
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  async function reconcileStatus(action, btn) {
    const want = action === "start" || action === "reset" ? "running" : "stopped";
    say(`${action === "stop" ? "Tearing down" : action === "reset" ? "Rebuilding" : "Provisioning"} is taking longer than expected — checking actual status…`);
    const deadline = Date.now() + 120000;
    for (;;) {
      await sleep(3000);
      let st = null;
      try {
        const r = await fetch(`/api/labs/${encodeURIComponent(labId)}/status`);
        const j = await r.json().catch(() => ({}));
        st = j.instance ? j.instance.status : "stopped";
      } catch { /* retry until deadline */ }
      if (st === want || (!st && want === "stopped")) {
        toast(action === "start" ? "Lab running" : action === "reset" ? "Lab reset complete" : "Lab stopped");
        location.reload();
        return;
      }
      if (st === "failed") {
        say("The operation failed server-side. Reload to see the current status, then retry.");
        btn.disabled = false;
        return;
      }
      if (Date.now() > deadline) {
        say("Still no response — the server may still be working. Reload the page to see the current status.");
        btn.disabled = false;
        return;
      }
    }
  }
  wrap.addEventListener("click", async (e) => {
    const b = e.target.closest("[data-lab-action]");
    if (!b) return;
    const action = b.dataset.labAction;
    b.disabled = true;
    say(action === "start" ? "Provisioning isolated target…" : action === "reset" ? "Rebuilding environment…" : "Tearing down… (usually under a minute)");
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 100000);
    try {
      const r = await fetch(`/api/labs/${encodeURIComponent(labId)}/${action}`, { method: "POST", signal: ctrl.signal });
      clearTimeout(timer);
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.error || `${action} failed`);
      toast(action === "start" ? "Lab running" : action === "reset" ? "Lab reset complete" : "Lab stopped");
      location.reload();
    } catch (err) {
      clearTimeout(timer);
      if (err && err.name === "AbortError") { reconcileStatus(action, b); return; }
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

  // ---------- student VPN pack (personal WireGuard config for Kali) ----------
  const vpnBox = wrap.querySelector("[data-vpn]");
  if (vpnBox) {
    const vpnLine = vpnBox.querySelector("[data-vpn-line]");
    const vpnSay = (t) => { if (vpnLine) vpnLine.textContent = t; };
    vpnBox.addEventListener("click", async (e) => {
      const dl = e.target.closest("[data-vpn-download]");
      const re = e.target.closest("[data-vpn-regenerate]");
      const st = e.target.closest("[data-vpn-status]");
      if (dl) {
        dl.disabled = true;
        try {
          const r = await fetch(`/api/vpn/pack`);
          if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || "Pack unavailable.");
          const blob = await r.blob();
          const fn = /filename="([^"]+)"/.exec(r.headers.get("content-disposition") || "")?.[1] || "axiom-vpn.conf";
          const a = document.createElement("a");
          a.href = URL.createObjectURL(blob);
          a.download = fn;
          document.body.appendChild(a);
          a.click();
          a.remove();
          setTimeout(() => URL.revokeObjectURL(a.href), 5000);
          toast("VPN pack downloaded — wg-quick up to join");
          location.reload();
        } catch (err) { toast(err.message || "Download failed."); dl.disabled = false; }
      }
      if (re) {
        re.disabled = true;
        try {
          const r = await fetch(`/api/vpn/regenerate`, { method: "POST" });
          const j = await r.json().catch(() => ({}));
          if (!r.ok) throw new Error(j.error || "Regenerate failed.");
          toast("New pack issued — download it again");
          location.reload();
        } catch (err) { toast(err.message || "Failed."); re.disabled = false; }
      }
      if (st) {
        st.disabled = true;
        try {
          const r = await fetch(`/api/vpn/status`);
          const j = await r.json().catch(() => ({}));
          vpnSay(j.configured
            ? `Pack ready · your VPN IP ${j.clientIp || ""}${j.connected ? " · connected" : j.gateway ? " · no handshake yet — is wg-quick up?" : " · gateway offline"}`
            : "No pack yet.");
        } catch { vpnSay("Status unavailable — retry."); }
        finally { st.disabled = false; }
      }
    });
  }

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

// ---------- CarnoSec vulnerability scanner console (Module 7.2) ----------
// No-dependency renderer over the owner-scoped scanner API. Everything
// below only runs when the server rendered a [data-scanner] shell.
(() => {
  const root = document.querySelector("[data-scanner]");
  if (!root) return;
  const wrap = root.closest(".labwrap");
  const labId = wrap?.dataset.lab;
  if (!labId) return;
  const $ = (sel) => root.querySelector(sel);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const api = (p, body) => fetch(`/api/labs/${encodeURIComponent(labId)}/scanner/${p}`, body === undefined
    ? {}
    : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const msg = (t) => { const m = $("[data-scanner-msg]"); if (m) m.textContent = t; };

  async function loadConsole() {
    let cfg;
    try {
      const r = await api("config");
      cfg = await r.json();
      if (!r.ok) throw new Error(cfg.error || "Scanner unavailable.");
    } catch (e) {
      msg(e.message || "Start the lab to use the scanner.");
      return;
    }
    const tpl = $("[data-scanner-templates]");
    if (tpl) {
      const cats = [...new Set((cfg.templates || []).map((t) => t.category))];
      tpl.innerHTML = `<dl class="kv">${cats.map((c) => {
        const names = (cfg.templates || []).filter((t) => t.category === c).map((t) => esc(t.name)).join(", ");
        return `<div><dt>${esc(c)}</dt><dd>${names}</dd></div>`;
      }).join("")}</dl>`;
    }
    const tgt = $("[data-scanner-targets]");
    if (tgt) {
      tgt.innerHTML = (cfg.targets || []).length
        ? (cfg.targets || []).map((t) => `<label class="check"><input type="checkbox" name="target" value="${esc(t.ip)}" checked> ${esc(t.name)} <span class="mono dim">${esc(t.ip)}</span></label>`).join("")
        : `<p class="dim small">This console has no range — templates and settings only.</p>`;
    }
    const set = $("[data-scanner-settings]");
    if (set) {
      const adv = cfg.advanced || {};
      set.innerHTML = `<dl class="kv">${Object.entries(adv).map(([k, v]) => `<div><dt>${esc(k)}</dt><dd class="mono">${esc(v)}</dd></div>`).join("")}</dl>`;
    }
    refreshScans();
  }

  async function refreshScans() {
    const list = $("[data-scanner-list]");
    if (!list) return;
    let scans = [];
    try {
      const r = await api("scans");
      const j = await r.json();
      if (r.ok) scans = j.scans || [];
    } catch { /* keep previous */ }
    if (!scans.length) { list.innerHTML = `<p class="dim small">No scans yet.</p>`; return; }
    list.innerHTML = `<dl class="kv">${scans.map((s) => `<div><dt>${esc(s.name)}</dt><dd><button class="link mono" data-scan="${esc(s.id)}">${esc(s.status)}${s.status === "running" ? ` · ${s.progress}%` : ""}</button> <span class="dim small">${esc(s.targets.join(", "))}</span></dd></div>`).join("")}</dl>`;
    if (scans.some((s) => s.status === "running" || s.status === "queued")) {
      clearTimeout(refreshScans._t);
      refreshScans._t = setTimeout(refreshScans, 3000);
    }
  }

  async function showScan(jobId) {
    const fbox = $("[data-scanner-findings]");
    const sbox = $("[data-scanner-sitemap]");
    try {
      const r = await api(`scans/${encodeURIComponent(jobId)}`);
      const j = await r.json();
      if (!r.ok) throw new Error(j.error || "Scan not found.");
      const groups = new Map();
      for (const f of j.findings || []) {
        if (!groups.has(f.pluginId)) groups.set(f.pluginId, { name: f.pluginName, family: f.family, severity: f.severity, items: [] });
        groups.get(f.pluginId).items.push(f);
      }
      if (fbox) {
        fbox.innerHTML = groups.size ? [...groups.entries()].map(([pid, g]) => `
          <details><summary><b>${esc(g.name)}</b> <span class="chip xs">${esc(g.severity)}</span> <span class="dim small">${g.items.length} target${g.items.length === 1 ? "" : "s"} · ${esc(g.family)}</span></summary>
          ${g.items.map((f) => `<div class="cmdrow"><code class="mono">${esc(f.targetIp)}:${f.port}</code><button class="btn xs" data-finding="${esc(f.id)}">Open finding</button></div>`).join("")}
          </details>`).join("") : `<p class="dim small">No findings.</p>`;
      }
      if (sbox) {
        sbox.innerHTML = (j.sitemap || []).length ? `<dl class="kv">${j.sitemap.map((p) => `<div><dt class="mono">${esc(p.path)}</dt><dd><button class="link mono" data-page="${esc(p.url)}" data-job="${esc(jobId)}">${esc(p.title || p.url)}</button> <span class="dim small">${esc(p.targetIp)} · ${p.status} · ${p.links.length} links</span></dd></div>`).join("")}</dl>`
          : `<p class="dim small">No sitemap pages. Web-application scans list discovered pages here.</p>`;
      }
    } catch (e) {
      if (fbox) fbox.innerHTML = `<p class="dim small">${esc(e.message)}</p>`;
    }
    refreshScans();
  }

  async function showFinding(fid) {
    const fbox = $("[data-scanner-findings]");
    try {
      const lab = `findings/${encodeURIComponent(fid)}`;
      const r = await api(lab);
      const j = await r.json();
      if (!r.ok) throw new Error(j.error || "Finding not found.");
      const f = j.finding;
      const detail = Object.entries(f.details || {}).map(([k, v]) => `<div><dt>${esc(k)}</dt><dd class="mono">${esc(v)}</dd></div>`).join("");
      if (fbox) {
        fbox.innerHTML = `<div class="card">
          <h3>${esc(f.title)}</h3>
          <dl class="kv">
            <div><dt>Severity</dt><dd>${esc(f.severity)}</dd></div>
            <div><dt>Target</dt><dd class="mono">${esc(f.targetIp)}:${f.port}/${esc(f.protocol)}</dd></div>
            <div><dt>Plugin</dt><dd>${esc(f.pluginName)} <span class="dim small">(${esc(f.family)})</span></dd></div>
            ${detail}
          </dl>
          <h3>Description</h3><p class="dim small">${esc(f.description)}</p>
          <h3>Evidence</h3><p class="mono small">${esc(f.evidence)}</p>
          <h3>Remediation</h3><p class="dim small">${esc(f.remediation)}</p>
          <button class="btn xs" data-back>Back to findings</button>
        </div>`;
        fbox.querySelector("[data-back]")?.addEventListener("click", () => {
          const open = fbox.dataset.job;
          if (open) showScan(open);
        });
        fbox.dataset.job = f.jobId;
      }
    } catch (e) {
      if (fbox) fbox.innerHTML = `<p class="dim small">${esc(e.message)}</p>`;
    }
  }

  async function showPage(jobId, url) {
    const sbox = $("[data-scanner-sitemap]");
    try {
      const r = await api(`page?jobId=${encodeURIComponent(jobId)}&url=${encodeURIComponent(url)}`);
      const j = await r.json();
      if (!r.ok) throw new Error(j.error || "Page not found.");
      if (sbox) {
        sbox.innerHTML = `<div class="card"><h3 class="mono">${esc(j.page.url)}</h3>
          <p class="dim small">HTTP ${j.page.status} · ${esc(j.page.title)}</p>
          <pre class="mono small" style="white-space:pre-wrap">${esc(j.page.html.slice(0, 8000))}</pre></div>`;
      }
    } catch (e) {
      if (sbox) sbox.innerHTML = `<p class="dim small">${esc(e.message)}</p>`;
    }
  }

  root.addEventListener("click", (e) => {
    const s = e.target.closest("[data-scan]");
    if (s) { e.preventDefault(); showScan(s.dataset.scan); return; }
    const f = e.target.closest("[data-finding]");
    if (f) { e.preventDefault(); showFinding(f.dataset.finding); return; }
    const p = e.target.closest("[data-page]");
    if (p) { e.preventDefault(); showPage(p.dataset.job, p.dataset.page); return; }
  });

  const form = root.querySelector("[data-scanner-new]");
  form?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(form);
    const targets = [...root.querySelectorAll('input[name="target"]:checked')].map((c) => c.value);
    msg("Launching scan…");
    try {
      const r = await api("scans", {
        name: fd.get("name") || "Untitled scan",
        template: fd.get("template") || "basic",
        targets,
        ports: fd.get("ports") || "",
        auth: fd.get("authUser") ? { user: fd.get("authUser"), password: fd.get("authPassword") || "" } : null,
        assessment: { mode: fd.get("assessment") || "default", webapp: !!form.querySelector('input[name="webapp"]')?.checked },
        pluginFilter: fd.get("pluginFilter") || "",
      });
      const j = await r.json();
      if (!r.ok) throw new Error(j.error || "Launch failed.");
      msg(`Scan launched (${j.scan.targets.length} targets). Results appear below as it completes.`);
      refreshScans();
      const poll = setInterval(async () => {
        try {
          const rr = await api(`scans/${encodeURIComponent(j.scan.id)}`);
          const jj = await rr.json();
          if (jj.scan && (jj.scan.status === "complete" || jj.scan.status === "failed")) {
            clearInterval(poll);
            showScan(j.scan.id);
          }
        } catch { clearInterval(poll); }
      }, 3000);
    } catch (err) { msg(err.message || "Launch failed."); }
  });

  loadConsole();
})();
