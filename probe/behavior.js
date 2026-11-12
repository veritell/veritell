// Veritell behaviour probe. Sends counts only: never a coordinate, key, text, element name or URL.
// Specification: probe/BEHAVIOR.md. Positions live only in a few scalars and are never sent.
(function () {
  "use strict";
  var C = "__VERITELL_BEHAVIOR__";
  if (!C || typeof C !== "object") return;

  var MAXC = 1e6, MAXMS = 864e5, MAXCV = 1e5;
  var T0 = performance.now();
  var n = { moves: 0, strokes: 0, straight: 0, steady: 0, clicks: 0, sized: 0, centered: 0,
    teleport: 0, touches: 0, keys: 0, pastes: 0, scrolls: 0, submits: 0, untrusted: 0, actions: 0 };
  var sent = 0, dirty = false, done = false, idleTimer = 0;
  var hiddenMs = 0, hiddenSince = document.visibilityState === "hidden" ? T0 : -1;

  // Stroke: running sums only.
  var s = null; // {n, x0, y0, x, y, t, len, k, sp, sp2}
  // Last two mouse moves (for teleport): position and time.
  var m1 = null, m2 = null; // m1 newest
  var lastTouch = -1e9, lastKey = -1e9, lastScroll = -1e9, lastKeyDown = -1;
  var kg = { n: 0, sum: 0, sq: 0 };
  var times = []; // at most 64 action times

  function bump(name) { if (n[name] < MAXC) n[name]++; }
  function untrusted(e) { if (!e.isTrusted) bump("untrusted"); }
  function action(t) { bump("actions"); times.push(t); if (times.length > 64) times.shift(); }

  function cv(count, sum, sq) {
    var mean = sum / count;
    if (!(mean > 0)) return 0;
    var v = sq / count - mean * mean;
    return Math.min(MAXCV, Math.round(1000 * Math.sqrt(v > 0 ? v : 0) / mean));
  }

  function endStroke() {
    var r = s;
    s = null;
    if (!r || r.n < 6) return;
    var dist = Math.hypot(r.x - r.x0, r.y - r.y0);
    if (dist < 40) return;
    bump("strokes");
    if (r.len <= 1.002 * dist) bump("straight");
    if (r.k >= 4) {
      var mean = r.sp / r.k, v = r.sp2 / r.k - mean * mean;
      if (Math.sqrt(v > 0 ? v : 0) <= 0.05 * mean) bump("steady");
    }
  }

  function onMove(e) {
    if (e.pointerType !== "mouse") return;
    var t = performance.now(), x = e.clientX, y = e.clientY;
    bump("moves"); untrusted(e); dirty = true;
    if (s && t - s.t > 120) endStroke();
    if (!s) {
      s = { n: 1, x0: x, y0: y, x: x, y: y, t: t, len: 0, k: 0, sp: 0, sp2: 0 };
    } else {
      var d = Math.hypot(x - s.x, y - s.y), dt = t - s.t;
      s.n++; s.len += d;
      if (dt > 0) { var v = d / dt; s.k++; s.sp += v; s.sp2 += v * v; }
      s.x = x; s.y = y; s.t = t;
    }
    m2 = m1; m1 = { x: x, y: y, t: t };
  }

  function teleported(t, x, y) {
    var inWin = (m1 && t - m1.t <= 500 ? 1 : 0) + (m2 && t - m2.t <= 500 ? 1 : 0);
    if (inWin > 1) return false;
    var ref = inWin ? m2 : m1; // last position known before the 500 ms window
    return !ref || Math.hypot(x - ref.x, y - ref.y) > 3;
  }

  function onClick(e) {
    var t = performance.now();
    untrusted(e); dirty = true;
    // Safari on iOS reports a tap's click as pointerType "mouse", so a recent
    // touch rules a click out whatever its pointerType says.
    var mouse = t - lastTouch > 700 &&
      (!(typeof PointerEvent === "function" && e instanceof PointerEvent) || e.pointerType === "mouse");
    if (!mouse || !(e.detail >= 1)) return;
    endStroke();
    bump("clicks"); action(t);
    var x = e.clientX, y = e.clientY;
    if (teleported(t, x, y)) bump("teleport");
    var el = e.target;
    if (el && el.getBoundingClientRect) {
      var r = el.getBoundingClientRect();
      if (r.width >= 24 && r.height >= 24) {
        bump("sized");
        if (Math.abs(x - (r.left + r.width / 2)) <= 1 && Math.abs(y - (r.top + r.height / 2)) <= 1) bump("centered");
      }
    }
  }

  function onTouch(e) {
    var t = performance.now();
    lastTouch = t; dirty = true;
    bump("touches"); untrusted(e); action(t);
  }

  function onKey(e) {
    var t = performance.now();
    var gap = t - lastKey;
    lastKey = t;
    if (e.repeat) return;
    dirty = true;
    bump("keys"); untrusted(e);
    if (lastKeyDown >= 0 && t - lastKeyDown < 2000) {
      var g = t - lastKeyDown;
      kg.n++; kg.sum += g; kg.sq += g * g;
    }
    lastKeyDown = t;
    if (gap >= 500) action(t);
  }

  function onPaste(e) { dirty = true; bump("pastes"); untrusted(e); }

  function onScroll(e) {
    var t = performance.now();
    if (t - lastScroll > 500) { bump("scrolls"); untrusted(e); action(t); dirty = true; }
    lastScroll = t;
  }

  function onSubmit(e) {
    bump("submits"); untrusted(e); dirty = true;
    send("submit");
  }

  function body(trigger, now) {
    var o = { v: 1, nonce: String(C.nonce), trigger: trigger,
      dur_ms: Math.min(MAXMS, Math.round(now - T0)) };
    var h = hiddenMs + (hiddenSince >= 0 ? now - hiddenSince : 0);
    o.hidden_ms = Math.min(o.dur_ms, Math.round(h));
    for (var k in n) o[k] = n[k];
    o.key_gap_cv = kg.n >= 5 ? cv(kg.n, kg.sum, kg.sq) : null;
    o.gap_cv = null; o.gap_med_ms = null;
    if (times.length >= 4) {
      var gaps = [], sum = 0, sq = 0, i;
      for (i = 1; i < times.length; i++) {
        var g = times[i] - times[i - 1];
        gaps.push(g); sum += g; sq += g * g;
      }
      o.gap_cv = cv(gaps.length, sum, sq);
      gaps.sort(function (a, b) { return a - b; });
      var mid = gaps.length >> 1;
      o.gap_med_ms = Math.min(MAXMS, Math.round(gaps.length & 1 ? gaps[mid] : (gaps[mid - 1] + gaps[mid]) / 2));
    }
    return JSON.stringify(o);
  }

  function post(json) {
    try {
      var ok = false;
      if (navigator.sendBeacon) ok = navigator.sendBeacon(C.endpoint, new Blob([json], { type: "application/json" }));
      if (!ok) {
        fetch(C.endpoint, { method: "POST", body: json, keepalive: true, credentials: "same-origin",
          headers: { "content-type": "application/json" } }).catch(function () {});
      }
    } catch (_) { /* ignored */ }
  }

  function send(trigger) {
    if (done || sent >= 3) return;
    endStroke();
    sent++; dirty = false;
    post(body(trigger, performance.now()));
    if (sent >= 3) stop();
  }

  function onVis() {
    var now = performance.now();
    if (document.visibilityState === "hidden") {
      if (hiddenSince < 0) hiddenSince = now;
      if (sent === 0 || dirty) send("hide");
    } else if (hiddenSince >= 0) {
      hiddenMs += now - hiddenSince; hiddenSince = -1;
    }
  }

  function onHide() {
    if (sent === 0 || dirty) send("hide");
    stop();
  }

  var L = [
    [document, "pointermove", onMove], [document, "click", onClick], [document, "touchstart", onTouch],
    [document, "keydown", onKey], [document, "paste", onPaste], [document, "scroll", onScroll],
    [document, "submit", onSubmit], [document, "visibilitychange", onVis], [window, "pagehide", onHide]
  ];
  var opts = { capture: true, passive: true };

  function stop() {
    if (done) return;
    done = true;
    clearTimeout(idleTimer);
    for (var i = 0; i < L.length; i++) L[i][0].removeEventListener(L[i][1], L[i][2], opts);
  }

  for (var i = 0; i < L.length; i++) L[i][0].addEventListener(L[i][1], L[i][2], opts);
  idleTimer = setTimeout(function () { if (sent === 0) send("idle"); }, 30000);
})();
