// Shared helpers for the bot lab: process/temp-dir tracking, cleanup, gateway, origin, CDP.
import { randomBytes } from "node:crypto";
import http from "node:http";
import net from "node:net";
import { spawn, execFile, execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, openSync, closeSync, existsSync, readFileSync, copyFileSync, mkdirSync } from "node:fs";
import { tmpdir, homedir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

export const here = dirname(fileURLToPath(import.meta.url));
export const root = dirname(here);
export const GATEWAY = process.env.VERITELL_BIN ?? join(root, "target/release/veritell");
export const CHROME = process.env.CHROME_BIN ?? join(homedir(), "Library/Caches/ms-playwright/chromium-1228/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing");
export const FIREFOX = process.env.FIREFOX_BIN ?? "/Applications/Firefox.app/Contents/MacOS/firefox";

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---- tracking and cleanup -------------------------------------------------
const procs = new Set();   // detached children (each is its own process group)
const dirs = new Set();
const servers = new Set();

export function makeTmp(prefix) {
  const d = mkdtempSync(join(tmpdir(), `lab-${prefix}-`));
  dirs.add(d);
  return d;
}
export function removeDir(d) {
  try { rmSync(d, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 }); } catch { /* best effort */ }
  dirs.delete(d);
}
export function trackServer(s) { servers.add(s); }

/** Spawn a child in its own process group so the whole tree can be killed. */
export function spawnTracked(cmd, args, opts = {}) {
  const child = spawn(cmd, args, { detached: true, stdio: "ignore", ...opts });
  child.exited = new Promise((r) => child.on("exit", r));
  child.on("error", () => {});
  procs.add(child);
  return child;
}
const killGroup = (child, sig) => { try { process.kill(-child.pid, sig); } catch { /* gone */ } };

/** Stop a child's process group: first `sig`, then SIGKILL after `graceMs`. */
export async function stopProc(child, sig = "SIGTERM", graceMs = 1000) {
  killGroup(child, sig);
  await Promise.race([child.exited, sleep(graceMs)]);
  killGroup(child, "SIGKILL");
  await Promise.race([child.exited, sleep(500)]);
  procs.delete(child);
}

/** Synchronous last-resort cleanup (exit and signal handlers). */
export function cleanupSync() {
  for (const c of procs) killGroup(c, "SIGKILL");
  procs.clear();
  for (const s of servers) { try { s.close(); s.closeAllConnections?.(); } catch { /* ignore */ } }
  servers.clear();
  for (const d of dirs) { try { rmSync(d, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); } catch { /* ignore */ } }
  dirs.clear();
}

export function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.on("error", reject);
    s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

// ---- certificate ----------------------------------------------------------
export function makeCert(dir) {
  const key = join(dir, "key.pem"), cert = join(dir, "cert.pem");
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=localhost",
    "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-keyout", key, "-out", cert], { stdio: "ignore" });
  const out = execFileSync("openssl", ["x509", "-in", cert, "-noout", "-fingerprint", "-sha256"]).toString();
  const fingerprint = out.split("=")[1].trim(); // AA:BB:...
  return { key, cert, fingerprint };
}

// ---- origin ---------------------------------------------------------------
/** Tiny origin: every path returns the probe page, except /lab/after, /lab/done, /lab/form and /lab/submit. Records paths. */
export async function startOrigin(scenarioId) {
  const seen = [];
  const sid = JSON.stringify(scenarioId);
  const html = `<!doctype html><meta charset="utf-8"><title>lab</title><p>lab page</p>
<script src="/__veritell/probe.js" async></script>
<script>
(function () {
  var s = ${sid}, fired = false;
  function go() {
    if (fired) return; fired = true;
    fetch("/lab/after?s=" + s).catch(function () {}).then(function () { return fetch("/lab/done?s=" + s); }).catch(function () {});
  }
  document.addEventListener("veritell:done", go);
  setTimeout(go, 5000);
})();
</script>`;
  // /lab/form: a page a visitor acts on. It loads the behaviour script and
  // posts to /lab/submit, whose answer makes the follow-up requests.
  const formHtml = `<!doctype html><meta charset="utf-8"><title>lab form</title>
<style>button{width:160px;height:44px;margin:12px 0;display:block}input{display:block;margin:12px 0;width:240px;height:28px}</style>
<p>lab form</p>
<button type="button" id="agree">Agree</button>
<form method="post" action="/lab/submit?s=${encodeURIComponent(scenarioId)}">
<input id="name" name="name" autocomplete="off">
<button type="submit" id="send">Send</button>
</form>
<script src="/__veritell/probe.js" async></script>
<script src="/__veritell/behavior.js" async></script>`;
  const submittedHtml = `<!doctype html><meta charset="utf-8"><title>lab done</title><p>submitted</p>
<script>
setTimeout(function () {
  var s = ${sid};
  fetch("/lab/after?s=" + s).catch(function () {}).then(function () { return fetch("/lab/done?s=" + s); }).catch(function () {});
}, 800);
</script>`;
  const server = http.createServer((req, res) => {
    const path = req.url.split("?")[0];
    seen.push(path);
    if (path === "/lab/form") { res.writeHead(200, { "content-type": "text/html" }); res.end(formHtml); return; }
    if (path === "/lab/submit") { req.resume(); res.writeHead(200, { "content-type": "text/html" }); res.end(submittedHtml); return; }
    if (path === "/lab/after" || path === "/lab/done") { res.writeHead(200, { "content-type": "text/plain" }); res.end("ok"); return; }
    res.writeHead(200, { "content-type": "text/html" });
    res.end(html);
  });
  trackServer(server);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { port: server.address().port, seen, close: () => { server.close(); server.closeAllConnections?.(); servers.delete(server); } };
}

// ---- gateway --------------------------------------------------------------
export async function startGateway({ cert, key, originPort, policy, logPath }) {
  const port = await freePort();
  const adminPort = await freePort();
  const args = ["--cert", cert, "--key", key, "--listen", `127.0.0.1:${port}`, "--upstream", `127.0.0.1:${originPort}`,
    "--admin", `127.0.0.1:${adminPort}`];
  if (policy) args.push("--policy", policy);
  const fd = openSync(logPath, "w");
  const child = spawnTracked(GATEWAY, args, {
    // A fresh secret for every gateway the lab starts: nothing depends on its value.
    env: { ...process.env, VERITELL_SECRET: randomBytes(32).toString("hex") },
    stdio: ["ignore", fd, fd],
  });
  closeSync(fd);
  const gw = { port, adminPort, child,
    stop: () => stopProc(child, "SIGINT", 1000),
    events: async () => (await fetch(`http://127.0.0.1:${adminPort}/api/events?limit=500`, { signal: AbortSignal.timeout(5000) })).json(),
  };
  const deadline = Date.now() + 15000;
  for (;;) {
    if (child.exitCode !== null) throw new Error(`gateway exited early (code ${child.exitCode}); see its log`);
    try { await gw.events(); return gw; } catch { /* not up yet */ }
    if (Date.now() > deadline) { await gw.stop(); throw new Error("gateway did not become ready within 15 s"); }
    await sleep(100);
  }
}

// ---- browsers -------------------------------------------------------------
export function chromeMajor() {
  const out = execFileSync(CHROME, ["--version"]).toString();
  const m = out.match(/(\d+)\.\d+\.\d+\.\d+/);
  if (!m) throw new Error(`cannot read Chrome version from: ${out}`);
  return m[1];
}
export const normalUA = () => `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chromeMajor()}.0.0.0 Safari/537.36`;

/** Common Chromium flags. --use-mock-keychain keeps Chrome away from the user's macOS keychain. */
export const chromeBase = (profile) => [`--user-data-dir=${profile}`, "--no-first-run", "--no-default-browser-check",
  "--ignore-certificate-errors", "--use-mock-keychain"];

// ---- minimal CDP client over the global WebSocket ---------------------------
export class Cdp {
  constructor(ws) {
    this.ws = ws; this.id = 0; this.pending = new Map();
    ws.addEventListener("message", (ev) => {
      const msg = JSON.parse(ev.data);
      const p = msg.id && this.pending.get(msg.id);
      if (p) { this.pending.delete(msg.id); msg.error ? p.reject(new Error(`${p.method}: ${msg.error.message}`)) : p.resolve(msg.result); }
    });
    ws.addEventListener("close", () => { for (const p of this.pending.values()) p.reject(new Error("CDP socket closed")); this.pending.clear(); });
  }
  static async connect(url) {
    const ws = new WebSocket(url);
    await new Promise((res, rej) => {
      const t = setTimeout(() => rej(new Error("CDP connect timeout")), 10000);
      ws.addEventListener("open", () => { clearTimeout(t); res(); }, { once: true });
      ws.addEventListener("error", () => { clearTimeout(t); rej(new Error("CDP connect error")); }, { once: true });
    });
    return new Cdp(ws);
  }
  send(method, params = {}, sessionId) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => { this.pending.delete(id); reject(new Error(`CDP ${method} timed out`)); }, 10000);
      this.pending.set(id, { method, resolve: (v) => { clearTimeout(t); resolve(v); }, reject: (e) => { clearTimeout(t); reject(e); } });
      this.ws.send(JSON.stringify({ id, method, params, ...(sessionId && { sessionId }) }));
    });
  }
  close() { try { this.ws.close(); } catch { /* ignore */ } }
}

/** Read DevToolsActivePort from the profile: [port, browser websocket path]. */
export async function devtoolsEndpoint(profile, timeoutMs = 10000) {
  const f = join(profile, "DevToolsActivePort");
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (existsSync(f)) {
      const [port, path] = readFileSync(f, "utf8").split("\n");
      if (port && path) return `ws://127.0.0.1:${port}${path}`;
    }
    await sleep(100);
  }
  throw new Error("DevToolsActivePort never appeared");
}

export function saveLog(from, name, dir) {
  mkdirSync(dir, { recursive: true });
  try { copyFileSync(from, join(dir, `${name}.log`)); } catch { /* ignore */ }
}
export { execFile, existsSync };
