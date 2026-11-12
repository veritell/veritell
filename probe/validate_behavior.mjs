// Checks a behaviour summary against probe/BEHAVIOR.md.
// FIXED BY THE PROJECT LEAD. DO NOT EDIT.
//
// Usage: node probe/validate_behavior.mjs summary.json   (or import validate)

import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const COUNT = 1_000_000;
const MS = 86_400_000;
const CV = 100_000;
const FIELDS = {
  v: 1, dur_ms: MS, hidden_ms: MS, moves: COUNT, strokes: COUNT, straight: COUNT,
  steady: COUNT, clicks: COUNT, sized: COUNT, centered: COUNT, teleport: COUNT,
  touches: COUNT, keys: COUNT, pastes: COUNT, scrolls: COUNT, submits: COUNT,
  untrusted: COUNT, actions: COUNT,
};
const NULLABLE = { key_gap_cv: CV, gap_cv: CV, gap_med_ms: MS };
const ORDER = [["straight", "strokes"], ["steady", "strokes"], ["sized", "clicks"],
  ["centered", "sized"], ["teleport", "clicks"], ["hidden_ms", "dur_ms"]];

/** Returns a list of problems; empty when the summary is valid. */
export function validate(text) {
  const problems = [];
  if (Buffer.byteLength(text, "utf8") > 1024) problems.push("body over 1024 bytes");
  let s;
  try { s = JSON.parse(text); } catch { return ["not JSON"]; }
  if (s === null || typeof s !== "object" || Array.isArray(s)) return ["not an object"];
  const isCount = (x, max) => Number.isInteger(x) && x >= 0 && x <= max;
  for (const [name, max] of Object.entries(FIELDS)) {
    if (!isCount(s[name], max)) problems.push(`${name}: not an integer in 0..${max}`);
  }
  for (const [name, max] of Object.entries(NULLABLE)) {
    if (s[name] !== null && !isCount(s[name], max)) problems.push(`${name}: not null or an integer in 0..${max}`);
  }
  if (s.v !== 1) problems.push("v is not 1");
  if (typeof s.nonce !== "string" || Buffer.byteLength(s.nonce, "utf8") > 256) problems.push("nonce");
  if (!["submit", "hide", "idle"].includes(s.trigger)) problems.push("trigger");
  for (const [small, big] of ORDER) {
    if (s[small] > s[big]) problems.push(`${small} exceeds ${big}`);
  }
  const known = new Set([...Object.keys(FIELDS), ...Object.keys(NULLABLE), "nonce", "trigger"]);
  for (const key of Object.keys(s)) if (!known.has(key)) problems.push(`unknown field ${key}`);
  for (const key of known) if (!(key in s)) problems.push(`missing ${key}`);
  return problems;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const problems = validate(readFileSync(process.argv[2], "utf8"));
  for (const p of problems) console.error(p);
  process.exit(problems.length ? 1 : 0);
}
