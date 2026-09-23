// Premium video experience: genuine watch-time only (playing && visible), throttled saves,
// 90% auto-complete, autoplay countdown, keyboard controls, PiP/fullscreen/speed.
// Player chrome (timeline, buttons, menus) is an overlay that never takes layout height.
(() => {
  const root = document.querySelector(".learn[data-lesson]");
  if (!root) return;
  const lessonId = root.dataset.lesson, courseId = root.dataset.course;
  const threshold = parseFloat(root.dataset.threshold || "0.9");
  const autoplayOn = root.dataset.autoplay !== "0";
  const tabId = Math.random().toString(36).slice(2);
  const tzOffset = new Date().getTimezoneOffset();
  const v = document.getElementById("vid"), player = document.getElementById("player");
  const btnPlay = document.getElementById("btnPlay"), tCur = document.getElementById("tCur"), tDur = document.getElementById("tDur");
  const seek = document.getElementById("seek"), fill = document.getElementById("seekFill"), buf = document.getElementById("seekBuf"), seekTip = document.getElementById("seekTip");
  const btnMute = document.getElementById("btnMute"), vol = document.getElementById("vol");
  const btnFull = document.getElementById("btnFull"), btnPip = document.getElementById("btnPip");
  const btnMenu = document.getElementById("btnMenu"), menu = document.getElementById("pMenu");
  const btnCC = document.getElementById("btnCC"), mTheater = document.getElementById("mTheater");
  const spin = document.getElementById("pSpin");
  const nextId = document.querySelector("[data-next-id]")?.dataset.nextId;
  const prevId = document.querySelector("[data-prev-id]")?.dataset.prevId;
  let restored = parseFloat(root.dataset.pos || "0");
  let watchAccum = 0, lastTick = null, saveTimer = null, ended = false;
  // Icon swaps (mirror of PLAYER_ICONS in server/views.js, the source of truth).
  const IC = {
    play: '<svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor" aria-hidden="true"><path d="M7 4.5v15l13-7.5-13-7.5Z"/></svg>',
    pause: '<svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor" aria-hidden="true"><rect x="6" y="4" width="4.5" height="16" rx="1.2"/><rect x="13.5" y="4" width="4.5" height="16" rx="1.2"/></svg>',
    vol: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M11 5 6 9H2v6h4l5 4V5Z"/><path d="M15.54 8.46a5 5 0 0 1 0 7.07"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14"/></svg>',
    volx: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M11 5 6 9H2v6h4l5 4V5Z"/><line x1="22" x2="16" y1="9" y2="15"/><line x1="16" x2="22" y1="9" y2="15"/></svg>',
    max: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M8 3H5a2 2 0 0 0-2 2v3"/><path d="M21 8V5a2 2 0 0 0-2-2h-3"/><path d="M3 16v3a2 2 0 0 0 2 2h3"/><path d="M16 21h3a2 2 0 0 0 2-2v-3"/></svg>',
    min: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M8 3v3a2 2 0 0 1-2 2H3"/><path d="M21 8h-3a2 2 0 0 1-2-2V3"/><path d="M3 16h3a2 2 0 0 1 2 2v3"/><path d="M16 21v-3a2 2 0 0 1 2-2h3"/></svg>',
  };
  v.playbackRate = parseFloat(root.dataset.speed || "1");

  v.addEventListener("loadedmetadata", () => {
    tDur.textContent = fmt(v.duration);
    if (restored > 0 && restored < (v.duration || 1) - 5) { try { v.currentTime = restored; } catch {} }
  });
  v.addEventListener("play", () => { player.classList.remove("paused"); player.classList.add("playing"); btnPlay.innerHTML = IC.pause; wake(); });
  v.addEventListener("pause", () => { player.classList.add("paused"); player.classList.remove("playing"); btnPlay.innerHTML = IC.play; wake(); flush(); lastTick = null; });
  player.classList.add("paused");
  v.addEventListener("timeupdate", () => {
    tCur.textContent = fmt(v.currentTime);
    const pct = v.duration ? (v.currentTime / v.duration * 100) : 0;
    if (v.duration) fill.style.width = pct + "%";
    seek.setAttribute("aria-valuenow", String(Math.round(pct)));
    // auto-complete at threshold of genuine position (once — ended flag
    // stops the POST flood on every subsequent timeupdate)
    if (!ended && v.duration && v.currentTime / v.duration >= threshold) { ended = true; markDone(true); }
  });
  v.addEventListener("progress", () => {
    try {
      if (v.duration && v.buffered.length) buf.style.width = (v.buffered.end(v.buffered.length - 1) / v.duration * 100) + "%";
    } catch {}
  });
  // genuine watch-time accumulator: only while playing + visible + focused-ish
  setInterval(() => {
    if (!v.paused && !document.hidden && document.hasFocus?.() !== false) {
      const now = performance.now();
      if (lastTick) watchAccum += Math.min(2, (now - lastTick) / 1000);
      lastTick = now;
    } else lastTick = v.paused ? null : performance.now();
  }, 500);
  // throttled save every 10s + on pause/hide
  setInterval(flush, 10000);
  document.addEventListener("visibilitychange", () => { if (document.hidden) flush(); });
  window.addEventListener("beforeunload", () => flush(true));

  async function flush(sync = false) {
    const delta = watchAccum; watchAccum = 0;
    const payload = JSON.stringify({ lessonId, position: v.currentTime || 0, duration: v.duration || 0, watchDelta: delta, tabId, tzOffset, "x-tz-offset": tzOffset });
    if (sync && navigator.sendBeacon) {
      // sendBeacon can't set headers; tz falls back to server default — acceptable for final flush
      const b = new Blob([payload], { type: "application/json" });
      const ok = navigator.sendBeacon("/api/progress/video", b);
      if (!ok) watchAccum += delta; // re-queue watch time if the beacon was rejected
      return;
    }
    try {
      const r = await fetch("/api/progress/video", { method: "POST", headers: { "Content-Type": "application/json", "x-tz-offset": tzOffset }, body: payload });
      const j = await r.json();
      if (j.completed) { ended = true; showDone(); }
    } catch { watchAccum += delta; }
  }

  async function markDone(auto) {
    try {
      const r = await fetch("/api/progress/video", { method: "POST", headers: { "Content-Type": "application/json", "x-tz-offset": tzOffset }, body: JSON.stringify({ lessonId, position: v.currentTime, duration: v.duration, watchDelta: 0, completed: true, tabId, tzOffset }) });
      if ((await r.json()).completed) { ended = true; showDone(); if (!auto) toast("Marked complete"); }
    } catch { toast("Couldn't save — retry"); }
  }
  function showDone() {
    const b = document.getElementById("btnDone");
    if (b) { b.classList.add("done"); b.textContent = "✓ Completed"; }
    const badge = document.getElementById("pDone");
    if (badge) badge.hidden = false;
  }
  document.getElementById("btnDone").onclick = () => markDone(false);

  v.addEventListener("ended", () => {
    ended = true;
    flush();
    markDone(true);
    if (!nextId || !autoplayOn) return;
    const box = document.getElementById("nextUp"); box.hidden = false;
    let n = 5; const cd = document.getElementById("cd"); cd.textContent = n;
    const iv = setInterval(() => { n--; cd.textContent = n; if (n <= 0) { clearInterval(iv); location.href = "/learn/video/" + nextId; } }, 1000);
    document.getElementById("cancelAuto").onclick = () => { clearInterval(iv); box.hidden = true; };
    document.getElementById("playNow").onclick = () => { location.href = "/learn/video/" + nextId; };
  });

  // loading / error states (real media events only)
  player.classList.add("loading");
  v.addEventListener("canplay", () => player.classList.remove("loading"));
  v.addEventListener("waiting", () => player.classList.add("loading"));
  v.addEventListener("playing", () => player.classList.remove("loading"));
  v.addEventListener("error", () => {
    player.classList.remove("loading");
    const e = document.getElementById("pError");
    if (e) e.hidden = false;
  });

  // ---- overlay chrome: control auto-hide ----
  let idleTimer = null;
  function wake() {
    player.classList.remove("idle");
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => {
      // never strand the user: keep chrome while paused, scrubbing, or in menu
      if (!v.paused && !seek.classList.contains("scrubbing") && menu.hidden) player.classList.add("idle");
      else wake();
    }, 2800);
  }
  player.addEventListener("pointermove", wake, { passive: true });
  player.addEventListener("pointerdown", wake, { passive: true });
  player.addEventListener("keydown", wake);
  wake();

  // Tap-to-reveal on touch: the first tap while chrome is auto-hidden only
  // brings the controls back — it must not toggle play / fullscreen.
  // Capture the idle state on pointerdown (before wake() below clears it)
  // and consume the click/dblclick that follows the reveal tap.
  let revealTap = false;
  player.addEventListener("pointerdown", (e) => {
    if (player.classList.contains("idle") && !v.paused &&
        !e.target.closest("button,input,a,.nextUp,.pbar-wrap,.pmenu")) {
      revealTap = true;
    } else {
      revealTap = false;
    }
  }, { capture: true });
  // ---- transport controls ----
  const togglePlay = () => { v.paused ? v.play() : v.pause(); };
  btnPlay.onclick = togglePlay;
  document.getElementById("btnRw").onclick = () => { v.currentTime = Math.max(0, v.currentTime - 5); wake(); };
  document.getElementById("btnFf").onclick = () => { if (v.duration) v.currentTime = Math.min(v.duration, v.currentTime + 5); wake(); };
  // Click-to-toggle on the player surface — but never when interacting with
  // controls, menus, links, the seek bar, or the autoplay prompt. A reveal
  // tap (chrome was hidden) only wakes the overlay.
  player.onclick = (e) => {
    if (e.target.closest("button,input,a,.nextUp,.pbar-wrap,.pmenu")) { revealTap = false; return; }
    if (revealTap) { revealTap = false; wake(); return; }
    // Fallback for input paths without a preceding pointerdown.
    if (player.classList.contains("idle") && !v.paused) { wake(); return; }
    togglePlay();
  };
  player.ondblclick = (e) => {
    if (e.target.closest("button,input,a,.nextUp,.pbar-wrap,.pmenu")) { revealTap = false; return; }
    if (revealTap) { revealTap = false; wake(); return; }
    if (player.classList.contains("idle") && !v.paused) { wake(); return; }
    toggleFS();
  };

  // ---- timeline: click + drag scrub with hover time preview ----
  const ratioAt = (clientX) => {
    const r = seek.getBoundingClientRect();
    return Math.max(0, Math.min(1, (clientX - r.left) / r.width));
  };
  seek.addEventListener("pointerdown", (e) => {
    if (!v.duration) return;
    seek.classList.add("scrubbing");
    try { seek.setPointerCapture(e.pointerId); } catch {}
    v.currentTime = ratioAt(e.clientX) * v.duration;
    wake();
  });
  seek.addEventListener("pointermove", (e) => {
    if (!v.duration) return;
    const r = ratioAt(e.clientX);
    // hover preview bubble (scrub position while dragging), clamped inside
    const w = seek.getBoundingClientRect().width;
    seekTip.textContent = fmt(r * v.duration);
    seekTip.style.left = Math.min(Math.max(r * w, 26), w - 26) + "px";
    if (seek.classList.contains("scrubbing")) v.currentTime = r * v.duration;
  });
  const endScrub = () => seek.classList.remove("scrubbing");
  seek.addEventListener("pointerup", endScrub);
  seek.addEventListener("pointercancel", endScrub);
  document.getElementById("btnPrev").onclick = () => { if (prevId) location.href = "/learn/video/" + prevId; };
  document.getElementById("btnNext").onclick = () => nextId && (location.href = "/learn/video/" + nextId);

  // ---- volume (persisted per browser) ----
  const VOL_KEY = "axiom:vol";
  try {
    const saved = JSON.parse(localStorage.getItem(VOL_KEY) || "null");
    if (saved && typeof saved.volume === "number") {
      v.volume = Math.max(0, Math.min(1, saved.volume));
      vol.value = String(v.volume);
    }
    if (saved && typeof saved.muted === "boolean") v.muted = saved.muted;
  } catch {}
  const syncMute = () => {
    btnMute.innerHTML = (v.muted || v.volume === 0) ? IC.volx : IC.vol;
    btnMute.setAttribute("aria-pressed", String(v.muted));
  };
  btnMute.onclick = () => { v.muted = !v.muted; syncMute(); wake(); };
  vol.oninput = (e) => { v.volume = +e.target.value; v.muted = false; syncMute(); };
  v.addEventListener("volumechange", () => {
    syncMute();
    try { localStorage.setItem(VOL_KEY, JSON.stringify({ volume: v.volume, muted: v.muted })); } catch {}
  });
  syncMute();

  // ---- settings menu: speed (persisted), theater, shortcut hints ----
  document.querySelectorAll("#mSpeed button").forEach((b) => {
    b.onclick = () => {
      const s = +b.dataset.speed;
      v.playbackRate = s;
      document.querySelectorAll("#mSpeed button").forEach((x) => x.setAttribute("aria-pressed", String(x === b)));
      fetch("/api/settings/prefs", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ autoplay: autoplayOn ? 1 : 0, playback_speed: s }) });
      closeMenu();
      wake();
    };
  });
  const closeMenu = () => { menu.hidden = true; btnMenu.setAttribute("aria-expanded", "false"); };
  btnMenu.onclick = (e) => {
    e.stopPropagation();
    const open = menu.hidden;
    menu.hidden = !open;
    btnMenu.setAttribute("aria-expanded", String(open));
    if (open) menu.querySelector("button")?.focus();
    wake();
  };
  document.addEventListener("pointerdown", (e) => {
    if (!menu.hidden && !e.target.closest("#pMenu,#btnMenu")) closeMenu();
  });
  mTheater.onclick = () => {
    const on = root.classList.toggle("theater");
    mTheater.setAttribute("aria-pressed", String(on));
    wake();
  };

  // ---- captions: only rendered when subtitle tracks genuinely exist ----
  if (btnCC) {
    const tracks = [...v.textTracks].filter((t) => t.kind === "subtitles" || t.kind === "captions");
    if (!tracks.length) btnCC.hidden = true;
    else {
      const syncCC = () => btnCC.setAttribute("aria-pressed", String(tracks[0].mode === "showing"));
      btnCC.onclick = () => {
        const on = tracks[0].mode !== "showing";
        tracks.forEach((t, i) => { t.mode = on && i === 0 ? "showing" : "disabled"; });
        syncCC();
        wake();
      };
      syncCC();
    }
  }

  // ---- fullscreen (whole player wrapper: video + custom controls + progress) ----
  // Wrapper first so VIDEO + CUSTOM CONTROLS + PROGRESS BAR stay in
  // fullscreen where supported; video-element fallbacks (incl. iOS
  // webkitEnterFullscreen) only when the wrapper request is unavailable
  // or rejected. State always derives from the real browser state.
  const isFS = () => !!(
    document.fullscreenElement ||
    document.webkitFullscreenElement ||
    (typeof v.webkitDisplayingFullscreen === "boolean" ? v.webkitDisplayingFullscreen : false)
  );
  async function enterFS() {
    try {
      if (player.requestFullscreen) { await player.requestFullscreen(); return true; }
      if (typeof player.webkitRequestFullscreen === "function") { player.webkitRequestFullscreen(); return true; }
    } catch { /* fall through to video-element fallbacks */ }
    try {
      if (v.requestFullscreen) { await v.requestFullscreen(); return true; }
      if (typeof v.webkitRequestFullscreen === "function") { v.webkitRequestFullscreen(); return true; }
    } catch { /* fall through to iOS native video fullscreen */ }
    if (typeof v.webkitEnterFullscreen === "function") {
      try {
        // iOS Safari/iPhone: only the video element can go fullscreen, and
        // the page (incl. custom controls) is hidden — enable native ones.
        v.controls = true;
        v.webkitEnterFullscreen();
        return true;
      } catch { v.controls = false; }
    }
    return false;
  }
  async function exitFS() {
    try {
      if (document.fullscreenElement && document.exitFullscreen) { await document.exitFullscreen(); return; }
      if (document.webkitFullscreenElement && document.webkitExitFullscreen) { document.webkitExitFullscreen(); return; }
    } catch {}
    // iOS native video fullscreen is exited from the video's own UI;
    // webkitendfullscreen below restores state.
  }
  async function toggleFS() {
    try {
      if (isFS()) { await exitFS(); }
      else {
        const ok = await enterFS();
        if (!ok) { toast("Fullscreen isn't supported in this browser"); return; }
        // Best-effort landscape on narrow touch layouts; ignored everywhere
        // it isn't supported or allowed (desktop unaffected).
        try {
          const p = screen.orientation?.lock?.("landscape");
          if (p && typeof p.catch === "function") await p.catch(() => {});
        } catch {}
      }
    } catch { toast("Couldn't enter fullscreen"); }
  }
  function syncFS() {
    const on = isFS();
    player.classList.toggle("fs", on);
    if (!on) { try { screen.orientation?.unlock?.(); } catch {} }
    if (btnFull) { btnFull.innerHTML = on ? IC.min : IC.max; btnFull.setAttribute("aria-label", on ? "Exit fullscreen (f)" : "Fullscreen (f)"); }
    wake();
  }
  v.addEventListener("webkitbeginfullscreen", () => { v.controls = true; syncFS(); });
  v.addEventListener("webkitendfullscreen", () => { v.controls = false; syncFS(); });
  document.addEventListener("fullscreenchange", syncFS);
  document.addEventListener("webkitfullscreenchange", syncFS);
  btnFull.onclick = toggleFS;

  // ---- picture-in-picture with feature detection (no broken button) ----
  const pipOK = !!document.pictureInPictureEnabled && !v.disablePictureInPicture;
  if (!pipOK) btnPip.hidden = true;
  async function togglePip() {
    if (!pipOK) return;
    try { document.pictureInPictureElement ? await document.exitPictureInPicture() : await v.requestPictureInPicture(); }
    catch { toast("PiP not supported"); }
  }
  btnPip.onclick = togglePip;

  document.addEventListener("keydown", (e) => {
    if (/input|select|textarea/i.test(e.target.tagName)) return;
    // Space/Enter on a focused button already activates it natively —
    // handling it here too would toggle twice.
    if (e.target.closest?.("button") && (e.key === " " || e.key === "Enter")) return;
    if (e.key === "Escape" && !menu.hidden) { closeMenu(); return; }
    if (e.key === " " || e.key.toLowerCase() === "k") { e.preventDefault(); togglePlay(); }
    else if (e.key === "ArrowRight") v.currentTime += 5;
    else if (e.key === "ArrowLeft") v.currentTime -= 5;
    else if (e.key.toLowerCase() === "f") toggleFS();
    else if (e.key.toLowerCase() === "m") { v.muted = !v.muted; }
    else if (e.key.toLowerCase() === "p") togglePip();
    wake();
  });
  function fmt(s) { s = Math.floor(s || 0); const h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60), x = s % 60; return h ? `${h}:${String(m).padStart(2, "0")}:${String(x).padStart(2, "0")}` : `${m}:${String(x).padStart(2, "0")}`; }
})();
