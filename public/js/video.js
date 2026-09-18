// Premium video experience: genuine watch-time only (playing && visible), throttled saves,
// 90% auto-complete, autoplay countdown, keyboard controls, PiP/fullscreen/speed.
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
  const seek = document.getElementById("seek"), fill = document.getElementById("seekFill");
  const nextId = document.querySelector("[data-next-id]")?.dataset.nextId;
  const prevId = document.querySelector("[data-next-id]")?.dataset.prevId;
  let restored = parseFloat(root.dataset.pos || "0");
  let watchAccum = 0, lastTick = null, saveTimer = null, ended = false;
  v.playbackRate = parseFloat(document.getElementById("selSpeed")?.value || "1");

  v.addEventListener("loadedmetadata", () => {
    tDur.textContent = fmt(v.duration);
    if (restored > 0 && restored < (v.duration || 1) - 5) { try { v.currentTime = restored; } catch {} }
  });
  v.addEventListener("play", () => { player.classList.remove("paused"); btnPlay.textContent = "⏸"; lastTick = performance.now(); });
  v.addEventListener("pause", () => { player.classList.add("paused"); flush(); lastTick = null; });
  player.classList.add("paused");
  v.addEventListener("timeupdate", () => {
    tCur.textContent = fmt(v.currentTime);
    if (v.duration) fill.style.width = (v.currentTime / v.duration * 100) + "%";
    // auto-complete at threshold of genuine position
    if (!ended && v.duration && v.currentTime / v.duration >= threshold) markDone(true);
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
    const payload = JSON.stringify({ lessonId, position: v.currentTime || 0, duration: v.duration || 0, watchDelta: watchAccum, tabId, tzOffset, "x-tz-offset": tzOffset });
    watchAccum = 0;
    if (sync && navigator.sendBeacon) {
      // sendBeacon can't set headers; tz falls back to server default — acceptable for final flush
      const b = new Blob([payload], { type: "application/json" });
      navigator.sendBeacon("/api/progress/video", b);
      return;
    }
    try {
      const r = await fetch("/api/progress/video", { method: "POST", headers: { "Content-Type": "application/json", "x-tz-offset": tzOffset }, body: payload });
      const j = await r.json();
      if (j.completed) showDone();
    } catch {}
  }

  async function markDone(auto) {
    try {
      const r = await fetch("/api/progress/video", { method: "POST", headers: { "Content-Type": "application/json", "x-tz-offset": tzOffset }, body: JSON.stringify({ lessonId, position: v.currentTime, duration: v.duration, watchDelta: 0, completed: true, tabId, tzOffset }) });
      if ((await r.json()).completed) { showDone(); if (!auto) toast("Marked complete"); }
    } catch { toast("Couldn't save — retry"); }
  }
  function showDone() { const b = document.getElementById("btnDone"); if (b) { b.classList.add("done"); b.textContent = "✓ Completed"; } }
  document.getElementById("btnDone").onclick = () => markDone(false);

  v.addEventListener("ended", () => {
    flush();
    markDone(true);
    if (!nextId || !autoplayOn) return;
    const box = document.getElementById("nextUp"); box.hidden = false;
    let n = 5; const cd = document.getElementById("cd"); cd.textContent = n;
    const iv = setInterval(() => { n--; cd.textContent = n; if (n <= 0) { clearInterval(iv); location.href = "/learn/video/" + nextId; } }, 1000);
    document.getElementById("cancelAuto").onclick = () => { clearInterval(iv); box.hidden = true; };
    document.getElementById("playNow").onclick = () => { location.href = "/learn/video/" + nextId; };
  });

  // controls
  btnPlay.onclick = () => v.paused ? v.play() : v.pause();
  // Click-to-toggle on the player surface — but never when interacting with
  // controls, links, the seek bar, or the autoplay prompt.
  player.onclick = (e) => { if (e.target.closest("button,select,input,a,.nextUp,.pbar-wrap")) return; v.paused ? v.play() : v.pause(); };
  player.ondblclick = (e) => { if (e.target.closest("button,select,input,a,.nextUp,.pbar-wrap")) return; toggleFS(); };
  seek.onclick = (e) => { const r = seek.getBoundingClientRect(); if (v.duration) v.currentTime = Math.max(0, Math.min(1, (e.clientX - r.left) / r.width)) * v.duration; };
  document.getElementById("btnPrev").onclick = () => { if (prevId) location.href = "/learn/video/" + prevId; };
  document.getElementById("btnNext").onclick = () => nextId && (location.href = "/learn/video/" + nextId);
  document.getElementById("btnMute").onclick = () => { v.muted = !v.muted; };
  document.getElementById("vol").oninput = (e) => { v.volume = +e.target.value; v.muted = false; };
  document.getElementById("selSpeed").onchange = (e) => { v.playbackRate = +e.target.value; fetch("/api/settings/prefs", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ autoplay: autoplayOn ? 1 : 0, playback_speed: +e.target.value }) }); };
  const btnFull = document.getElementById("btnFull");
  async function toggleFS() {
    try {
      if (document.fullscreenElement || document.webkitFullscreenElement) {
        if (document.exitFullscreen) await document.exitFullscreen();
        else if (document.webkitExitFullscreen) document.webkitExitFullscreen();
      } else if (player.requestFullscreen) {
        await player.requestFullscreen();
      } else if (v.requestFullscreen) {
        await v.requestFullscreen();
      } else if (v.webkitEnterFullscreen) {
        // iOS Safari: element fullscreen is unsupported — fall back to the
        // native video fullscreen. Our controls are hidden with the page,
        // so temporarily enable the native ones.
        v.controls = true;
        v.webkitEnterFullscreen();
      } else {
        toast("Fullscreen isn't supported in this browser");
      }
    } catch { toast("Couldn't enter fullscreen"); }
  }
  v.addEventListener("webkitendfullscreen", () => { v.controls = false; });
  function syncFS() {
    const on = !!(document.fullscreenElement || document.webkitFullscreenElement);
    player.classList.toggle("fs", on);
    if (btnFull) { btnFull.textContent = on ? "🗗" : "⛶"; btnFull.setAttribute("aria-label", on ? "Exit fullscreen (f)" : "Fullscreen (f)"); }
  }
  document.addEventListener("fullscreenchange", syncFS);
  document.addEventListener("webkitfullscreenchange", syncFS);
  btnFull.onclick = toggleFS;
  document.getElementById("btnPip").onclick = async () => { try { document.pictureInPictureElement ? await document.exitPictureInPicture() : await v.requestPictureInPicture(); } catch { toast("PiP not supported"); } };
  document.addEventListener("keydown", (e) => {
    if (/input|select|textarea/i.test(e.target.tagName)) return;
    if (e.key === " " || e.key.toLowerCase() === "k") { e.preventDefault(); v.paused ? v.play() : v.pause(); }
    else if (e.key === "ArrowRight") v.currentTime += 10;
    else if (e.key === "ArrowLeft") v.currentTime -= 10;
    else if (e.key.toLowerCase() === "f") toggleFS();
    else if (e.key.toLowerCase() === "m") v.muted = !v.muted;
  });
  function fmt(s) { s = Math.floor(s || 0); const h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60), x = s % 60; return h ? `${h}:${String(m).padStart(2, "0")}:${String(x).padStart(2, "0")}` : `${m}:${String(x).padStart(2, "0")}`; }
})();
