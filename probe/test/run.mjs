// Probe test harness: node probe/test/run.mjs <chromium|firefox|manual> [--page normal|tampered] [--out file] [--csp policy] [--sealed] [--port n]
// manual starts no browser: it prints the page's address and waits up to 3 minutes for a browser opened
// by hand (Safari, which cannot be started headless from here). 127.0.0.1 counts as a secure context.
// --sealed serves a per-build script from the Rust builder and opens the sealed report with it (run from anywhere; cargo runs in the workspace root).
import http from "node:http";
import { randomBytes } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir, homedir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { validate, summary } from "../validate.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
const browser = args[0];
const page = opt("--page") ?? "normal";
const outFile = opt("--out");
const sealed = args.includes("--sealed");
const csp = opt("--csp"); // optional Content-Security-Policy header for the HTML page
const manual = browser === "manual";
if (!["chromium", "firefox", "manual"].includes(browser) || !["normal", "tampered"].includes(page)) {
  console.error("usage: node probe/test/run.mjs <chromium|firefox|manual> [--page normal|tampered] [--out file] [--csp policy] [--sealed] [--port n]");
  process.exit(2);
}

const CHROME = process.env.CHROME_BIN ?? join(homedir(), "Library/Caches/ms-playwright/chromium-1228/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing");
const FIREFOX = process.env.FIREFOX_BIN ?? "/Applications/Firefox.app/Contents/MacOS/firefox";

const TOKEN = '"__VERITELL_CONFIG__"';
const root = join(here, "..", "..");
const templatePath = join(here, "..", "probe.js");
const SEAL_SECRET = randomBytes(24).toString("hex"); // per run; the build and the opener share it
const BUILD_TTL = 300;
const cargo = (example, exampleArgs, input) => spawnSync(
  "cargo", ["run", "-q", "-p", "veritell-probe-build", "--example", example, "--", ...exampleArgs],
  { cwd: root, input, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
const nowSecs = () => String(Math.floor(Date.now() / 1000));

let probeSrc = readFileSync(templatePath, "utf8");
if (sealed) {
  const made = cargo("make_build", [templatePath, SEAL_SECRET, nowSecs(), String(BUILD_TTL)]);
  if (made.status !== 0) { console.error("make_build failed:\n" + made.stderr); process.exit(2); }
  probeSrc = made.stdout;
  if (probeSrc.includes("$$")) { console.error("built script still contains an unrenamed identifier"); process.exit(2); }
}
if (probeSrc.split(TOKEN).length !== 2) { console.error("config token must appear exactly once in the served script"); process.exit(2); }
const served = probeSrc.split(TOKEN).join(JSON.stringify({ nonce: "test-nonce", endpoint: "/report" }));
const normalHtml = '<!doctype html><meta charset="utf-8"><title>normal</title><p>normal test page</p><script src="/probe.js"></script>';
const tamperedHtml = readFileSync(join(here, "tampered.html"), "utf8");

let resolveReport;
const reportP = new Promise((r) => { resolveReport = r; });
const server = http.createServer((req, res) => {
  const path = req.url.split("?")[0];
  if (req.method === "POST" && path === "/report") {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => { res.writeHead(204); res.end(); resolveReport(Buffer.concat(chunks).toString("utf8")); });
  } else if (path === "/probe.js") {
    res.writeHead(200, { "content-type": "text/javascript" }); res.end(served);
  } else if (path === "/" || path === "/normal") {
    res.writeHead(200, { "content-type": "text/html", ...(csp && { "content-security-policy": csp }) }); res.end(normalHtml);
  } else if (path === "/tampered") {
    res.writeHead(200, { "content-type": "text/html" }); res.end(tamperedHtml);
  } else { res.writeHead(404); res.end(); }
});
await new Promise((r) => server.listen(Number(opt("--port") ?? 0), "127.0.0.1", r));
const url = `http://127.0.0.1:${server.address().port}/${page === "tampered" ? "tampered" : ""}`;

let body = null;
if (manual) {
  console.log(`open ${url} in the browser to capture; waiting up to 3 minutes`);
  body = await Promise.race([reportP, new Promise((r) => setTimeout(() => r(null), 180000))]);
  server.close();
  if (body === null) { console.error("FAIL: no report received within 3 minutes"); process.exit(1); }
} else {
  const profile = mkdtempSync(join(tmpdir(), `probe-${browser}-`));
  const bin = browser === "chromium" ? CHROME : FIREFOX;
  if (!existsSync(bin)) { console.error(`browser binary not found: ${bin}`); rmSync(profile, { recursive: true, force: true }); process.exit(2); }
  const bargs = browser === "chromium"
    ? ["--headless=new", `--user-data-dir=${profile}`, "--no-first-run", "--no-default-browser-check", url]
    : ["--headless", "--no-remote", "--profile", profile, url];
  const child = spawn(bin, bargs, { stdio: "ignore", detached: true });
  const exited = new Promise((r) => child.on("exit", r));
  child.on("error", (e) => { console.error("launch failed:", e.message); resolveReport(null); });

  body = await Promise.race([reportP, new Promise((r) => setTimeout(() => r(null), 20000))]);

  // Kill the whole browser process group, then remove the temporary profile.
  const killGroup = (sig) => { try { process.kill(-child.pid, sig); } catch { /* already gone */ } };
  killGroup("SIGTERM");
  await Promise.race([exited, new Promise((r) => setTimeout(r, 3000))]);
  killGroup("SIGKILL");
  await new Promise((r) => setTimeout(r, 300));
  rmSync(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  server.close();

  if (body === null) { console.error(`FAIL: no report received from ${browser} within 20 s`); process.exit(1); }
}
let wire = null;
if (sealed) {
  wire = Buffer.byteLength(body);
  const opened = cargo("open_report", [templatePath, SEAL_SECRET, nowSecs()], body);
  if (opened.status !== 0) { console.error(`FAIL: sealed report did not open: ${opened.stderr.trim()}\nbody: ${body.slice(0, 200)}`); process.exit(1); }
  body = opened.stdout.trim();
  if (JSON.parse(body).nonce !== "test-nonce") { console.error("FAIL: opened report carries the wrong nonce"); process.exit(1); }
}
const problems = validate(body);
const pretty = JSON.stringify(JSON.parse(body), null, 2);
if (outFile) writeFileSync(outFile, pretty + "\n");
console.log(`mode: ${sealed ? "sealed" : "plain"}`);
console.log(`${browser} (${page}) body=${Buffer.byteLength(body)} bytes` + (sealed ? ` (wire ${wire} bytes)` : ""));
if (problems.length) { console.error("FAIL validation:\n" + problems.join("\n")); console.log(pretty); process.exit(1); }
console.log("ok " + summary(body));
console.log(pretty);
