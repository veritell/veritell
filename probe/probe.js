/*
 * Veritell client probe (report schema v1, see SCHEMA.md).
 *
 * Observes the JavaScript environment and POSTs the raw observations to the
 * gateway. It contains no expected values, no browser names and no scoring:
 * all judgement happens on the server. Data minimisation: only the fields
 * listed in the schema are read (no canvas hashing, audio or font probing).
 *
 * This file is also the template for per-build scripts (see SEALING.md):
 * names with the double dollar prefix are renamed per build, marked blocks
 * are reordered, comments are stripped and leading white space is dropped.
 * Run unbuilt, it behaves as a plain, unsealed probe.
 */
(function () {
  "use strict";

  // The gateway replaces the quoted token on the next line with a JSON object.
  // While it is still a string the script is not served by the gateway: do nothing.
  var $$config = "__VERITELL_CONFIG__";
  if (!$$config || typeof $$config !== "object" || typeof $$config.endpoint !== "string") return;

  // The builder replaces the quoted token on the next line with the build
  // configuration (an object). While it is a string the report is sent plain.
  var $$build = "__VERITELL_BUILD__";

  // Schema limits (bytes, bytes, entries).
  var $$MAX_BODY = 32768, $$MAX_STRING = 512, $$MAX_ITEMS = 64;
  // Waits for the worker and for permissions.query.
  var $$WORKER_MS = 1500, $$PERM_MS = 1000;
  // Absolute deadline, the schema allows 3 s.
  var $$HARD_MS = 2900;

  var $$iframeEl = null, $$worker = null, $$blobUrl = null, $$ctl = null;
  var $$finished = false, $$hardTimer = null;

  /*
   * The realm collector: one self-contained function whose source text runs in
   * the main world (called directly), in a hidden iframe (compiled by the
   * iframe's own Function constructor, so its globals are the iframe's) and in
   * a dedicated worker (toString() embedded in a Blob). It refers to nothing
   * outside itself. The parameter is an optional Function.prototype.toString
   * from a fresh realm, used to read sources without trusting the page's own.
   */
  function $$collect($$ref) {
    "use strict";
    var $$G = typeof globalThis !== "undefined" ? globalThis : self;
    var $$nav = $$G.navigator;
    var $$gopd = Object.getOwnPropertyDescriptor;

    // Runs fn; on any failure (or an undefined result) returns the fallback.
    function $$T($$fn, $$fb) {
      try { var $$v = $$fn(); return $$v === undefined ? $$fb : $$v; } catch ($$e) { return $$fb; }
    }
    // Non-negative 32-bit integer or 0.
    function $$u32($$n) {
      $$n = Number($$n);
      if (!isFinite($$n)) return 0;
      $$n = Math.floor($$n);
      return $$n < 0 || $$n > 4294967295 ? 0 : $$n;
    }

    var $$r = {};

    $$r.ua = $$T(function () { return String($$nav.userAgent); }, "");
    $$r.platform = $$T(function () { return String($$nav.platform); }, "");
    $$r.languages = $$T(function () {
      var $$out = [], $$a = $$nav.languages;
      for (var $$i = 0; $$i < $$a.length && $$i < 64; $$i++) $$out.push(String($$a[$$i]));
      return $$out;
    }, []);
    $$r.hc = $$T(function () { return $$u32($$nav.hardwareConcurrency); }, 0);
    // null when the property does not exist at all (workers).
    $$r.webdriver = $$T(function () { return "webdriver" in $$nav ? !!$$nav.webdriver : null; }, null);
    // Brand names only, not versions.
    $$r.uad = $$T(function () {
      var $$u = $$nav.userAgentData;
      if (!$$u) return null;
      var $$brands = [], $$bs = $$u.brands || [];
      for (var $$i = 0; $$i < $$bs.length && $$i < 64; $$i++) $$brands.push(String($$bs[$$i].brand));
      return { platform: String($$u.platform), mobile: !!$$u.mobile, brands: $$brands };
    }, null);

    // ---- engine behaviour ----
    var $$en = {};
    // Wording of the TypeError for a property read on null. Some engines put
    // the variable name into the message, so this one name is never renamed.
    $$en.err_msg = $$T(function () {
      var n = null;
      try { n.x; } catch ($$e) { return String($$e.message); }
      return "";
    }, "");
    // Length of the native eval source text.
    $$en.eval_len = $$T(function () { return $$u32(eval.toString().length); }, 0);
    // Does the second line of an Error stack look like a V8 frame?
    $$en.stack_at = $$T(function () {
      var $$s = new Error("p").stack;
      var $$lines = typeof $$s === "string" ? $$s.split("\n") : [];
      return $$lines.length > 1 && /^    at /.test($$lines[1]);
    }, false);
    // Presence tests for engine specific APIs (typeof / in only).
    $$en.features = {
      /*@shuffle*/
      error_capture_stack_trace: $$T(function () { return typeof Error.captureStackTrace === "function"; }, false),
      error_stack_trace_limit: $$T(function () { return "stackTraceLimit" in Error; }, false),
      intl_v8_break_iterator: $$T(function () { return typeof Intl === "object" && "v8BreakIterator" in Intl; }, false),
      fn_to_source: $$T(function () { return typeof Function.prototype.toSource === "function"; }, false),
      internal_error: $$T(function () { return typeof InternalError === "function"; }, false),
      error_line_number: $$T(function () { return "lineNumber" in new Error("p"); }, false),
      error_line: $$T(function () { return "line" in new Error("p"); }, false),
      /*@end*/
    };
    $$en.math = $$T(function () {
      return [Math.tan(-1e300), Math.sinh(1), Math.expm1(1), Math.cosh(10), Math.atanh(0.5)].join(",");
    }, "");
    $$r.engine = $$en;

    // ---- tamper checks ----
    // Report only what an untouched engine cannot produce; skip absent targets.
    var $$tam = [], $$idx = Object.create(null);
    function $$add($$target, $$kind) {
      var $$e = $$idx[$$target];
      if (!$$e) { $$e = $$idx[$$target] = { target: $$target, kinds: [] }; $$tam.push($$e); }
      if ($$e.kinds.indexOf($$kind) < 0) $$e.kinds.push($$kind);
    }
    // Engines format native sources differently (whitespace, "get " prefixes):
    // match loosely, "function <anything>() { [native code] }".
    var $$NATIVE = /^function\s*[^(]*\(\)\s*\{\s*\[native code\]\s*\}$/;
    var $$TS = typeof $$ref === "function" ? $$ref : Function.prototype.toString;
    function $$src($$f) { try { return $$TS.call($$f); } catch ($$e) { return null; } }

    // Checks one function that should be a native built-in.
    //  noCall:  skip the wrong-receiver call (promise returning functions)
    //  isToStr: this is Function.prototype.toString, report to_string_self
    function $$checkFn($$target, $$f, $$noCall, $$isToStr) {
      // to_string: the source text is not a native-code string.
      var $$s = $$src($$f);
      if ($$s === null || !$$NATIVE.test($$s)) $$add($$target, $$isToStr ? "to_string_self" : "to_string");
      // proxy (shape): native non-constructor functions own exactly length and
      // name and never a prototype; script functions own a prototype.
      $$T(function () {
        var $$names = Object.getOwnPropertyNames($$f);
        if ($$names.indexOf("prototype") >= 0 || $$names.indexOf("name") < 0 || $$names.indexOf("length") < 0) $$add($$target, "proxy");
      }, 0);
      // proxy (behaviour): a native built-in called on a foreign receiver
      // throws a TypeError; anything else is a stand-in.
      if (!$$noCall) {
        try { $$f.call({}); $$add($$target, "proxy"); }
        catch ($$e) { if (!$$e || $$e.name !== "TypeError") $$add($$target, "proxy"); }
      }
    }

    // Navigator accessors: getters on the interface prototype, not own properties.
    $$T(function () {
      var $$Nav = $$G.Navigator || $$G.WorkerNavigator;
      var $$label = $$G.Navigator ? "Navigator" : "WorkerNavigator";
      var $$NP = $$Nav && $$Nav.prototype;
      if (!$$NP || !$$nav) return;
      if (Object.getPrototypeOf($$nav) !== $$NP) $$add("navigator", "prototype_chain");
      var $$names = [
        /*@shuffle*/
        "userAgent",
        "platform",
        "languages",
        "hardwareConcurrency",
        "webdriver",
        "plugins",
        "userAgentData",
        /*@end*/
      ];
      for (var $$i = 0; $$i < $$names.length; $$i++) {
        $$T((function ($$name) {
          return function () {
            var $$pd = $$gopd($$NP, $$name);
            if ($$gopd($$nav, $$name)) $$add("navigator." + $$name, "own_property");
            // Not implemented by this engine.
            if (!$$pd) return;
            var $$tg = $$label + ".prototype." + $$name;
            if (typeof $$pd.get !== "function" || $$pd.set !== undefined || $$pd.enumerable !== true || $$pd.configurable !== true) {
              $$add($$tg, "descriptor");
            }
            if (typeof $$pd.get === "function") $$checkFn($$tg, $$pd.get, false, false);
          };
        })($$names[$$i]), 0);
      }
    }, 0);

    // Screen values must come from the prototype too.
    $$T(function () {
      var $$sc = $$G.screen;
      if (!$$sc) return;
      var $$names = [
        /*@shuffle*/
        "width",
        "height",
        "availWidth",
        "availHeight",
        "colorDepth",
        "pixelDepth",
        /*@end*/
      ];
      for (var $$i = 0; $$i < $$names.length; $$i++) if ($$gopd($$sc, $$names[$$i])) $$add("screen." + $$names[$$i], "own_property");
    }, 0);

    // Methods: [path, owner prototype, property, enumerable, promise returning].
    // WebIDL operations are enumerable, ECMAScript built-ins are not.
    var $$methods = [
      /*@shuffle*/
      ["Function.prototype.toString", $$G.Function && $$G.Function.prototype, "toString", false, false],
      ["Permissions.prototype.query", $$G.Permissions && $$G.Permissions.prototype, "query", true, true],
      ["WebGLRenderingContext.prototype.getParameter", $$G.WebGLRenderingContext && $$G.WebGLRenderingContext.prototype, "getParameter", true, false],
      ["HTMLCanvasElement.prototype.toDataURL", $$G.HTMLCanvasElement && $$G.HTMLCanvasElement.prototype, "toDataURL", true, false],
      ["Date.prototype.getTimezoneOffset", $$G.Date && $$G.Date.prototype, "getTimezoneOffset", false, false],
      ["Intl.DateTimeFormat.prototype.resolvedOptions", $$G.Intl && $$G.Intl.DateTimeFormat && $$G.Intl.DateTimeFormat.prototype, "resolvedOptions", false, false],
      /*@end*/
    ];
    for (var $$m = 0; $$m < $$methods.length; $$m++) {
      $$T((function ($$spec) {
        return function () {
          var $$owner = $$spec[1], $$path = $$spec[0];
          if (!$$owner) return;
          var $$pd = $$gopd($$owner, $$spec[2]);
          if (!$$pd) return;
          // descriptor: writable, configurable data property, spec'd enumerability.
          if (typeof $$pd.value !== "function" || $$pd.writable !== true || $$pd.configurable !== true || $$pd.enumerable !== $$spec[3]) {
            $$add($$path, "descriptor");
          }
          if (typeof $$pd.value === "function") $$checkFn($$path, $$pd.value, $$spec[4], $$spec[2] === "toString");
        };
      })($$methods[$$m]), 0);
    }
    $$r.tamper = $$tam;
    return $$r;
  }

  // ---- outer script helpers ----

  // Realm object with every documented fallback, used if the collector itself breaks.
  function $$emptyRealm() {
    var $$f = {};
    ["error_capture_stack_trace", "error_stack_trace_limit", "intl_v8_break_iterator", "fn_to_source",
      "internal_error", "error_line_number", "error_line"].forEach(function ($$k) { $$f[$$k] = false; });
    return {
      ua: "", platform: "", languages: [], hc: 0, webdriver: null, uad: null,
      engine: { err_msg: "", eval_len: 0, stack_at: false, features: $$f, math: "" },
      tamper: []
    };
  }

  function $$u32($$n) {
    $$n = Number($$n);
    if (!isFinite($$n)) return 0;
    $$n = Math.floor($$n);
    return $$n < 0 || $$n > 4294967295 ? 0 : $$n;
  }

  function $$tryOr($$fn, $$fb) {
    try { var $$v = $$fn(); return $$v === undefined ? $$fb : $$v; } catch ($$e) { return $$fb; }
  }

  function $$reason($$e) {
    return String(($$e && $$e.name) || "error").slice(0, 40);
  }

  // Copies a value enforcing the limits: long strings cut to 170 chars (under
  // 512 bytes of UTF-8), arrays and objects cut to 64 entries.
  function $$clean($$v, $$depth) {
    if (typeof $$v === "string") return $$v.length > 170 && $$utf8Len($$v) > $$MAX_STRING ? $$v.slice(0, 170) : $$v;
    if ($$v === null || typeof $$v !== "object" || $$depth > 8) return $$v;
    var $$out, $$i;
    if (Array.isArray($$v)) {
      $$out = [];
      for ($$i = 0; $$i < $$v.length && $$i < $$MAX_ITEMS; $$i++) $$out.push($$clean($$v[$$i], $$depth + 1));
      return $$out;
    }
    $$out = {};
    var $$keys = Object.keys($$v);
    for ($$i = 0; $$i < $$keys.length && $$i < $$MAX_ITEMS; $$i++) $$out[$$keys[$$i]] = $$clean($$v[$$keys[$$i]], $$depth + 1);
    return $$out;
  }

  function $$utf8Len($$s) {
    try { return new TextEncoder().encode($$s).length; } catch ($$e) { return $$s.length * 3; }
  }

  // Replaces every object key by its name in the build's key map, at every
  // depth. Arrays are walked, values are unchanged. A key without a name is
  // dropped (every key of a valid report has one).
  function $$mapKeys($$v, $$map, $$depth) {
    if ($$v === null || typeof $$v !== "object" || $$depth > 16) return $$v;
    var $$out, $$i;
    if (Array.isArray($$v)) {
      $$out = [];
      for ($$i = 0; $$i < $$v.length; $$i++) $$out.push($$mapKeys($$v[$$i], $$map, $$depth + 1));
      return $$out;
    }
    $$out = {};
    var $$keys = Object.keys($$v);
    for ($$i = 0; $$i < $$keys.length; $$i++) {
      var $$name = $$map[$$keys[$$i]];
      if (typeof $$name === "string") $$out[$$name] = $$mapKeys($$v[$$keys[$$i]], $$map, $$depth + 1);
    }
    return $$out;
  }

  // Standard base64 (with padding) of a byte array.
  function $$b64($$bytes) {
    var $$s = "";
    for (var $$i = 0; $$i < $$bytes.length; $$i += 4096) {
      $$s += String.fromCharCode.apply(null, $$bytes.subarray($$i, $$i + 4096));
    }
    return btoa($$s);
  }

  // Builds the sealed request body: AES-GCM under SHA-256(build key || nonce),
  // additional data = build id. Rejects if anything is unavailable.
  async function $$seal($$report, $$cfg) {
    var $$subtle = crypto.subtle;
    var $$enc = new TextEncoder();
    var $$kb = Uint8Array.from(atob($$cfg.k), function ($$c) { return $$c.charCodeAt(0); });
    var $$nb = $$enc.encode($$report.nonce);
    var $$mat = new Uint8Array($$kb.length + $$nb.length);
    $$mat.set($$kb, 0);
    $$mat.set($$nb, $$kb.length);
    var $$raw = await $$subtle.digest("SHA-256", $$mat);
    var $$key = await $$subtle.importKey("raw", $$raw, { name: "AES-GCM" }, false, ["encrypt"]);
    var $$iv = crypto.getRandomValues(new Uint8Array(12));
    var $$plain = $$enc.encode(JSON.stringify($$mapKeys($$report, $$cfg.map, 0)));
    var $$ct = new Uint8Array(await $$subtle.encrypt(
      { name: "AES-GCM", iv: $$iv, additionalData: $$enc.encode($$cfg.id), tagLength: 128 }, $$key, $$plain));
    var $$all = new Uint8Array($$iv.length + $$ct.length);
    $$all.set($$iv, 0);
    $$all.set($$ct, $$iv.length);
    var $$out = JSON.stringify({ b: $$cfg.id, n: $$report.nonce, d: $$b64($$all) });
    if ($$out.length > 65000) throw new Error("size");
    return $$out;
  }

  // Resolves with the notification permission state, or null on any failure.
  function $$permQuery() {
    return new Promise(function ($$resolve) {
      var $$t = setTimeout(function () { $$resolve(null); }, $$PERM_MS);
      function $$end($$v) { clearTimeout($$t); $$resolve($$v); }
      try {
        navigator.permissions.query({ name: "notifications" }).then(function ($$st) {
          $$end($$st && typeof $$st.state === "string" ? $$st.state : null);
        }, function () { $$end(null); });
      } catch ($$e) { $$end(null); }
    });
  }

  // Resolves with the worker's realm or null; the reason goes into errors.
  function $$runWorker($$srcText, $$errors) {
    return new Promise(function ($$resolve) {
      var $$settled = false, $$timer = null;
      function $$end($$val, $$msg) {
        if ($$settled) return;
        $$settled = true;
        clearTimeout($$timer);
        if ($$msg) $$errors.push($$msg);
        $$resolve($$val);
      }
      try {
        var $$code = '"use strict";var $$collect=' + $$srcText +
          ';try{postMessage({ok:1,r:$$collect()})}catch(e){postMessage({ok:0,m:String(e&&e.name)})}';
        $$blobUrl = URL.createObjectURL(new Blob([$$code], { type: "text/javascript" }));
        $$worker = new Worker($$blobUrl);
      } catch ($$e) {
        $$end(null, "worker: create " + $$reason($$e));
        return;
      }
      $$worker.onmessage = function ($$ev) {
        var $$d = $$ev && $$ev.data;
        if ($$d && $$d.ok && $$d.r && typeof $$d.r === "object") $$end($$d.r);
        else $$end(null, "worker: failed " + String(($$d && $$d.m) || "").slice(0, 40));
      };
      $$worker.onerror = function ($$ev) {
        try { $$ev.preventDefault(); } catch ($$e) { /* ignore */ }
        $$end(null, "worker: blocked");
      };
      $$timer = setTimeout(function () { $$end(null, "worker: timeout"); }, $$WORKER_MS);
    });
  }

  // Page level observations (main world only).
  function $$collectPage($$permState) {
    var $$p = {};
    // The observations below are independent of each other: one per line.
    /*@shuffle*/
    $$p.plugins = $$tryOr(function () { return $$u32(navigator.plugins.length); }, 0);
    $$p.screen = $$tryOr(function () { return [$$u32(screen.width), $$u32(screen.height), $$u32(screen.availWidth), $$u32(screen.availHeight)]; }, [0, 0, 0, 0]);
    $$p.window = $$tryOr(function () { return [$$u32(innerWidth), $$u32(innerHeight), $$u32(outerWidth), $$u32(outerHeight)]; }, [0, 0, 0, 0]);
    $$p.dpr_x100 = $$tryOr(function () { return $$u32(Math.round(devicePixelRatio * 100)); }, 0);
    $$p.touch_points = $$tryOr(function () { return $$u32(navigator.maxTouchPoints); }, 0);
    $$p.chrome_obj = $$tryOr(function () { return typeof window.chrome === "object" && window.chrome !== null; }, false);
    $$p.notif_permission = $$tryOr(function () { return typeof Notification === "undefined" ? null : String(Notification.permission); }, null);
    $$p.perm_query_notif = $$permState;
    $$p.tz = $$tryOr(function () { return String(Intl.DateTimeFormat().resolvedOptions().timeZone || ""); }, "");
    $$p.tz_offset_min = $$tryOr(function () { var $$o = new Date().getTimezoneOffset(); return isFinite($$o) && Math.abs($$o) <= 1440 ? Math.round($$o) : 0; }, 0);
    /*@end*/
    var $$gl = $$tryOr(function () {
      // Detached canvas, never inserted.
      var $$c = document.createElement("canvas");
      var $$ctx = $$c.getContext("webgl") || $$c.getContext("experimental-webgl");
      if (!$$ctx) return null;
      var $$vendor = null, $$renderer = null;
      var $$ext = $$tryOr(function () { return $$ctx.getExtension("WEBGL_debug_renderer_info"); }, null);
      if ($$ext) {
        $$vendor = $$tryOr(function () { return String($$ctx.getParameter($$ext.UNMASKED_VENDOR_WEBGL)); }, null);
        $$renderer = $$tryOr(function () { return String($$ctx.getParameter($$ext.UNMASKED_RENDERER_WEBGL)); }, null);
      }
      if ($$vendor === null) $$vendor = $$tryOr(function () { return String($$ctx.getParameter($$ctx.VENDOR)); }, null);
      if ($$renderer === null) $$renderer = $$tryOr(function () { return String($$ctx.getParameter($$ctx.RENDERER)); }, null);
      $$tryOr(function () { $$ctx.getExtension("WEBGL_lose_context").loseContext(); }, 0);
      return [$$vendor, $$renderer];
    }, null);
    $$p.webgl_vendor = $$gl ? $$gl[0] : null;
    $$p.webgl_renderer = $$gl ? $$gl[1] : null;
    // Automation framework leftovers among own property names of window/document.
    var $$re = /^(\$?cdc_|__playwright|__pw_|__puppeteer|__selenium|__webdriver|__driver|__fxdriver|__nightmare|_selenium|calledSelenium|\$chrome_asyncScriptInfo|__lastWatir|_WEBDRIVER_ELEM_CACHE|_Selenium_IDE_Recorder$|_phantom$|callPhantom$|domAutomation(Controller)?$)/;
    var $$found = [];
    [window, document].forEach(function ($$o) {
      $$tryOr(function () {
        Object.getOwnPropertyNames($$o).forEach(function ($$n) {
          if ($$re.test($$n) && $$found.indexOf($$n) < 0) $$found.push($$n);
        });
      }, 0);
    });
    $$p.globals = $$found;
    return $$p;
  }

  // Removes everything the script created. Safe to call more than once.
  function $$cleanup() {
    $$tryOr(function () { if ($$iframeEl && $$iframeEl.parentNode) $$iframeEl.parentNode.removeChild($$iframeEl); }, 0);
    $$iframeEl = null;
    $$tryOr(function () { if ($$worker) { $$worker.onmessage = null; $$worker.onerror = null; $$worker.terminate(); } }, 0);
    $$worker = null;
    $$tryOr(function () { if ($$blobUrl) URL.revokeObjectURL($$blobUrl); }, 0);
    $$blobUrl = null;
  }

  // Dispatches veritell:done exactly once.
  function $$finish($$ok) {
    if ($$finished) return;
    $$finished = true;
    clearTimeout($$hardTimer);
    $$tryOr(function () { if ($$ctl) $$ctl.abort(); }, 0);
    $$cleanup();
    try {
      document.dispatchEvent(new CustomEvent("veritell:done", { detail: { ok: !!$$ok } }));
    } catch ($$e) { /* ignore */ }
  }

  // ---- main flow ----
  async function $$run() {
    var $$errors = [];
    var $$srcText = "";
    try {
      $$srcText = Function.prototype.toString.call($$collect);
      if ($$srcText.indexOf("function $$collect(") !== 0) throw new Error("source");
    } catch ($$e) {
      $$srcText = "";
      $$errors.push("collector: source unavailable");
    }

    var $$workerP = $$srcText ? $$runWorker($$srcText, $$errors) : Promise.resolve(null);
    var $$permP = $$permQuery();

    var $$win = null, $$ref;
    try {
      $$iframeEl = document.createElement("iframe");
      $$iframeEl.setAttribute("aria-hidden", "true");
      $$iframeEl.tabIndex = -1;
      $$iframeEl.style.cssText = "position:absolute;left:-9999px;top:0;width:0;height:0;border:0;visibility:hidden";
      (document.documentElement || document.body).appendChild($$iframeEl);
      $$win = $$iframeEl.contentWindow;
      if (!$$win) throw new Error("window");
      $$ref = $$win.Function.prototype.toString;
    } catch ($$e) {
      $$win = null;
      $$errors.push("iframe: create " + $$reason($$e));
    }

    var $$mainRealm = $$tryOr(function () { return $$collect($$ref); }, null);
    if (!$$mainRealm) { $$mainRealm = $$emptyRealm(); $$errors.push("main: collector failed"); }

    var $$iframeRealm = null;
    if ($$win && $$srcText) {
      try {
        // Compiled by the iframe's own Function constructor: its globals are the iframe's.
        var $$fn = $$win.Function("return (" + $$srcText + ")")();
        // JSON round trip so nothing refers to the iframe once it is removed.
        $$iframeRealm = JSON.parse(JSON.stringify($$fn()));
      } catch ($$e) {
        $$iframeRealm = null;
        $$errors.push("iframe: " + $$reason($$e));
      }
    }
    $$tryOr(function () { if ($$iframeEl && $$iframeEl.parentNode) $$iframeEl.parentNode.removeChild($$iframeEl); }, 0);
    $$iframeEl = null;

    var $$workerRealm = await $$workerP;
    var $$permState = await $$permP;

    var $$report = {
      v: 1,
      nonce: String($$config.nonce),
      main: $$mainRealm,
      iframe: $$iframeRealm,
      worker: $$workerRealm,
      page: $$collectPage($$permState),
      errors: $$errors
    };
    $$report = $$clean($$report, 0);

    var $$body = JSON.stringify($$report);
    if ($$utf8Len($$body) > $$MAX_BODY) {
      // Too large: keep 16 tamper entries per realm, then drop errors.
      ["main", "iframe", "worker"].forEach(function ($$k) {
        if ($$report[$$k]) $$report[$$k].tamper = $$report[$$k].tamper.slice(0, 16);
      });
      $$body = JSON.stringify($$report);
      if ($$utf8Len($$body) > $$MAX_BODY) {
        $$report.errors = [];
        $$body = JSON.stringify($$report);
      }
    }
    // A built script never falls back to the plain report: if sealing is not
    // possible the promise rejects and nothing is sent.
    if (typeof $$build !== "string") $$body = await $$seal($$report, $$build);

    // The hard timer may have ended the run while this was being built:
    // then nothing is sent, so that veritell:done's `ok: false` is the truth.
    if ($$finished) return false;
    // A browser may run a copy of this script it already ran, nonce and all
    // (Safari does on back navigation). That nonce is spent, and the gateway
    // would refuse the report as a replay and count it against the client.
    // So each nonce is sent once per tab; without sessionStorage it is sent.
    var $$sentKey = "veritell-probe-sent";
    var $$nid = String($$config.nonce).slice(0, 24);
    var $$sent = $$tryOr(function () { return JSON.parse(sessionStorage.getItem($$sentKey) || "[]"); }, []);
    if (!Array.isArray($$sent)) $$sent = [];
    if ($$sent.indexOf($$nid) !== -1) return false;
    $$tryOr(function () { sessionStorage.setItem($$sentKey, JSON.stringify($$sent.concat([$$nid]).slice(-32))); }, 0);
    $$ctl = typeof AbortController === "function" ? new AbortController() : null;
    var $$res = await fetch($$config.endpoint, {
      method: "POST",
      credentials: "same-origin",
      keepalive: true,
      headers: { "content-type": "application/json" },
      body: $$body,
      signal: $$ctl ? $$ctl.signal : undefined
    });
    return $$res.status >= 200 && $$res.status < 300;
  }

  // Absolute deadline: whatever is still pending, finish now.
  $$hardTimer = setTimeout(function () { $$finish(false); }, $$HARD_MS);
  var $$p;
  try { $$p = $$run(); } catch ($$e) { $$p = Promise.reject($$e); }
  $$p.then(function ($$ok) { $$finish($$ok); }, function () { $$finish(false); });
})();
