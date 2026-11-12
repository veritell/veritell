// Validates a probe report against SCHEMA.md. FIXED BY THE PROJECT LEAD.
//
//   node probe/validate.mjs report.json      (or pipe the JSON on stdin)
//
// Exits 0 and prints "ok" plus a one-line summary, or exits 1 with the list
// of problems. Can also be imported: `import { validate } from "./validate.mjs"`.
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const MAX_BODY = 32768, MAX_STRING = 512, MAX_ITEMS = 64;
const FEATURES = ["error_capture_stack_trace", "error_stack_trace_limit", "intl_v8_break_iterator",
  "fn_to_source", "internal_error", "error_line_number", "error_line"];
const KINDS = ["to_string", "to_string_self", "own_property", "descriptor", "proxy", "prototype_chain"];
const enc = new TextEncoder();

export function validate(text) {
  const problems = [];
  const bad = (path, why) => problems.push(`${path}: ${why}`);
  if (enc.encode(text).length > MAX_BODY) bad("body", `longer than ${MAX_BODY} bytes`);
  let r;
  try { r = JSON.parse(text); } catch (e) { return [`body: not JSON (${e.message})`]; }
  const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
  const str = (v, p) => {
    if (typeof v !== "string") return bad(p, "not a string");
    if (enc.encode(v).length > MAX_STRING) bad(p, `longer than ${MAX_STRING} bytes`);
  };
  const strOrNull = (v, p) => { if (v !== null) str(v, p); };
  const uint = (v, p) => { if (!Number.isInteger(v) || v < 0 || v > 0xffffffff) bad(p, "not a u32"); };
  const bool = (v, p) => { if (typeof v !== "boolean") bad(p, "not a boolean"); };
  const arr = (v, p, each) => {
    if (!Array.isArray(v)) return bad(p, "not an array");
    if (v.length > MAX_ITEMS) bad(p, `more than ${MAX_ITEMS} entries`);
    v.forEach((x, i) => each(x, `${p}[${i}]`));
  };
  const keys = (v, p, required, optional = []) => {
    if (!isObj(v)) { bad(p, "not an object"); return false; }
    for (const k of required) if (!(k in v)) bad(`${p}.${k}`, "missing");
    for (const k of Object.keys(v)) if (!required.includes(k) && !optional.includes(k)) bad(`${p}.${k}`, "unknown field");
    return true;
  };
  const realm = (v, p) => {
    if (!keys(v, p, ["ua", "platform", "languages", "hc", "webdriver", "uad", "engine", "tamper"])) return;
    str(v.ua, `${p}.ua`); str(v.platform, `${p}.platform`);
    arr(v.languages, `${p}.languages`, str);
    uint(v.hc, `${p}.hc`);
    if (v.webdriver !== null) bool(v.webdriver, `${p}.webdriver`);
    if (v.uad !== null && keys(v.uad, `${p}.uad`, ["platform", "mobile", "brands"])) {
      str(v.uad.platform, `${p}.uad.platform`); bool(v.uad.mobile, `${p}.uad.mobile`);
      arr(v.uad.brands, `${p}.uad.brands`, str);
    }
    if (keys(v.engine, `${p}.engine`, ["err_msg", "eval_len", "stack_at", "features", "math"])) {
      str(v.engine.err_msg, `${p}.engine.err_msg`); uint(v.engine.eval_len, `${p}.engine.eval_len`);
      bool(v.engine.stack_at, `${p}.engine.stack_at`); str(v.engine.math, `${p}.engine.math`);
      if (keys(v.engine.features, `${p}.engine.features`, FEATURES))
        for (const k of FEATURES) bool(v.engine.features[k], `${p}.engine.features.${k}`);
    }
    arr(v.tamper, `${p}.tamper`, (t, tp) => {
      if (!keys(t, tp, ["target", "kinds"])) return;
      str(t.target, `${tp}.target`);
      arr(t.kinds, `${tp}.kinds`, (k, kp) => { if (!KINDS.includes(k)) bad(kp, `unknown kind ${JSON.stringify(k)}`); });
      if (Array.isArray(t.kinds) && t.kinds.length === 0) bad(`${tp}.kinds`, "empty");
    });
  };
  if (!keys(r, "report", ["v", "nonce", "main", "iframe", "worker", "page", "errors"])) return problems;
  if (r.v !== 1) bad("report.v", "must be 1");
  str(r.nonce, "report.nonce");
  realm(r.main, "main");
  if (r.iframe !== null) realm(r.iframe, "iframe");
  if (r.worker !== null) realm(r.worker, "worker");
  arr(r.errors, "errors", str);
  const P = ["plugins", "screen", "window", "dpr_x100", "touch_points", "webgl_vendor", "webgl_renderer",
    "chrome_obj", "notif_permission", "perm_query_notif", "globals", "tz", "tz_offset_min"];
  if (keys(r.page, "page", P)) {
    const g = r.page;
    uint(g.plugins, "page.plugins"); uint(g.dpr_x100, "page.dpr_x100"); uint(g.touch_points, "page.touch_points");
    for (const f of ["screen", "window"]) {
      if (!Array.isArray(g[f]) || g[f].length !== 4) bad(`page.${f}`, "not 4 integers");
      else g[f].forEach((x, i) => uint(x, `page.${f}[${i}]`));
    }
    strOrNull(g.webgl_vendor, "page.webgl_vendor"); strOrNull(g.webgl_renderer, "page.webgl_renderer");
    bool(g.chrome_obj, "page.chrome_obj");
    strOrNull(g.notif_permission, "page.notif_permission"); strOrNull(g.perm_query_notif, "page.perm_query_notif");
    arr(g.globals, "page.globals", str);
    str(g.tz, "page.tz");
    if (!Number.isInteger(g.tz_offset_min) || Math.abs(g.tz_offset_min) > 1440) bad("page.tz_offset_min", "not a plausible offset");
  }
  return problems;
}

export function summary(text) {
  const r = JSON.parse(text);
  const t = (x) => (x ? x.tamper.length : "-");
  return `realms main=${!!r.main} iframe=${!!r.iframe} worker=${!!r.worker} tamper=${t(r.main)}/${t(r.iframe)}/${t(r.worker)} globals=${r.page.globals.length} errors=${r.errors.length}`;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const text = readFileSync(process.argv[2] ?? 0, "utf8");
  const problems = validate(text);
  if (problems.length) { console.error(problems.join("\n")); process.exit(1); }
  console.log("ok", summary(text));
}
