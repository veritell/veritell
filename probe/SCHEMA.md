# Probe report schema, version 1

FIXED BY THE PROJECT LEAD. The Rust side of this contract is
`crates/veritell-probe/src/types.rs`. `probe/validate.mjs` checks a report
against it.

The probe reports raw observations only. It makes no judgement, contains no
expected values and no browser names, and never decides whether something is
"suspicious": the server does that.

## How the script is served and configured

The server sends `probe.js` with the literal token `"__VERITELL_CONFIG__"`
(including the double quotes) replaced by a JSON object:

```json
{ "nonce": "…", "endpoint": "/__veritell/probe" }
```

The token must appear exactly once in `probe.js`. When it has not been
replaced (the value is still a string), the script does nothing.

When finished, the script sends the report with one request:

```
POST <endpoint>
content-type: application/json
credentials: same-origin, keepalive: true
```

and then dispatches `new CustomEvent("veritell:done", { detail: { ok } })` on
`document`, where `ok` is true when the response status was 2xx. It dispatches
the event with `ok: false` if anything fails. It must finish within 3 seconds
even if the iframe or the worker never answers; if its hard timer (2.9 s)
ends the run first, nothing is sent at all.

The body shown below is the report as built. What the gateway serves is a
per-build copy of the script that seals the report before sending it (see
`SEALING.md`); the gateway refuses a plain report.

## Report

```json
{
  "v": 1,
  "nonce": "<config.nonce>",
  "main":   Realm,
  "iframe": Realm or null,
  "worker": Realm or null,
  "page":   Page,
  "errors": ["short message", "…"]
}
```

Limits: whole body at most 32768 bytes, every string at most 512 bytes of
UTF-8 (truncate longer ones), every array or object at most 64 entries
(drop the rest).

### Realm

Collected the same way, by the same function source, in three places: the
main world, a new same-origin iframe (`about:blank`, hidden, removed
afterwards), and a dedicated worker created from a Blob URL. `iframe` or
`worker` is null when it could not be created or did not answer in time, and
a short reason goes in `errors`.

| Field | Type | Source |
|---|---|---|
| `ua` | string | `navigator.userAgent` |
| `platform` | string | `navigator.platform` |
| `languages` | string[] | `navigator.languages` (empty array when missing) |
| `hc` | integer | `navigator.hardwareConcurrency`, 0 when missing |
| `webdriver` | boolean or null | `navigator.webdriver`; null when the property does not exist at all (workers) |
| `uad` | object or null | `navigator.userAgentData`: `{ "platform": string, "mobile": boolean, "brands": string[] }` (brand names only); null when unsupported |
| `engine` | object | below |
| `tamper` | array | below; empty when nothing was found |

`engine`:

| Field | Type | Source |
|---|---|---|
| `err_msg` | string | `var n = null; try { n.x } catch (e) { e.message }` |
| `eval_len` | integer | `eval.toString().length` |
| `stack_at` | boolean | the second line of `new Error("p").stack` matches `/^    at /` |
| `features` | object of booleans | exactly the keys below |
| `math` | string | `[Math.tan(-1e300), Math.sinh(1), Math.expm1(1), Math.cosh(10), Math.atanh(0.5)].join(",")` |

`features` keys (all are plain `typeof` or `in` tests that work in a worker):

| Key | Test |
|---|---|
| `error_capture_stack_trace` | `typeof Error.captureStackTrace === "function"` |
| `error_stack_trace_limit` | `"stackTraceLimit" in Error` |
| `intl_v8_break_iterator` | `typeof Intl === "object" && "v8BreakIterator" in Intl` |
| `fn_to_source` | `typeof Function.prototype.toSource === "function"` |
| `internal_error` | `typeof InternalError === "function"` |
| `error_line_number` | `"lineNumber" in new Error("p")` |
| `error_line` | `"line" in new Error("p")` |

`tamper` entries are `{ "target": string, "kinds": string[] }`. `target` is a
dotted path such as `Navigator.prototype.webdriver` or `Function.prototype.toString`.
`kinds` uses this vocabulary:

| Kind | Meaning |
|---|---|
| `to_string` | `Function.prototype.toString.call(fn)` is not a native-code string for that function's name |
| `to_string_self` | `Function.prototype.toString` itself is not native (checked with a `toString` taken from the fresh iframe where possible) |
| `own_property` | the property exists on the instance (`navigator`, `window`, `screen`) when it should come from the prototype |
| `descriptor` | the property descriptor has the wrong shape (a data property where an accessor is expected, or the reverse; unexpected `configurable`/`enumerable`) |
| `proxy` | the function behaves like a Proxy (for example it has no `prototype`/`name`/`length` in the native pattern, or throws an unexpected error type when called on the wrong receiver) |
| `prototype_chain` | the object's prototype is not the expected interface prototype |

The target list is the probe author's to choose. It must at least cover the
getters for `userAgent`, `platform`, `languages`, `hardwareConcurrency`,
`webdriver`, `plugins` and `userAgentData` on the navigator prototype,
`Function.prototype.toString`, `Permissions.prototype.query`,
`WebGLRenderingContext.prototype.getParameter`,
`HTMLCanvasElement.prototype.toDataURL`, `Date.prototype.getTimezoneOffset`
and `Intl.DateTimeFormat.prototype.resolvedOptions`, where they exist in the
realm. A check must produce nothing in an untouched Chromium, Firefox or
Safari: when unsure whether engines differ, do not report.

### Page (main world only)

| Field | Type | Source |
|---|---|---|
| `plugins` | integer | `navigator.plugins.length`, 0 when missing |
| `screen` | 4 integers | `screen.width`, `height`, `availWidth`, `availHeight` |
| `window` | 4 integers | `innerWidth`, `innerHeight`, `outerWidth`, `outerHeight` |
| `dpr_x100` | integer | `Math.round(devicePixelRatio * 100)` |
| `touch_points` | integer | `navigator.maxTouchPoints`, 0 when missing |
| `webgl_vendor`, `webgl_renderer` | string or null | `WEBGL_debug_renderer_info` unmasked values; fall back to `VENDOR`/`RENDERER`; null without WebGL |
| `chrome_obj` | boolean | `typeof window.chrome === "object" && window.chrome !== null` |
| `notif_permission` | string or null | `Notification.permission` |
| `perm_query_notif` | string or null | `(await navigator.permissions.query({ name: "notifications" })).state`; null on any failure |
| `globals` | string[] | names of automation-framework properties found on `window` or `document` (see below) |
| `tz` | string | `Intl.DateTimeFormat().resolvedOptions().timeZone`, `""` on failure |
| `tz_offset_min` | integer | `new Date().getTimezoneOffset()` |

`globals`: own property names of `window` and `document` that match the
patterns used by automation frameworks, such as names starting with `cdc_`,
`$cdc_`, `__playwright`, `__pw_`, `__puppeteer`, `__selenium`, `__webdriver`,
`__driver`, `__fxdriver`, `__nightmare`, and the exact names `_phantom`,
`callPhantom`, `domAutomation`, `domAutomationController`,
`_Selenium_IDE_Recorder`. The probe author may extend the list.

All integers are non-negative and fit in 32 bits, except `tz_offset_min`
which may be negative. Clamp anything else (NaN, negative, huge) to 0.
