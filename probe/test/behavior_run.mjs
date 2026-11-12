// Behaviour probe harness: node probe/test/behavior_run.mjs <chromium|firefox>
// Serves probe/test/behavior.html and probe/behavior.js, records every POSTed summary,
// drives scenarios with trusted input through Playwright and validates the summaries.
import http from "node:http";
import { homedir } from "node:os";
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { validate } from "../validate_behavior.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..", "..");
const browserName = process.argv[2];
if (!["chromium", "firefox"].includes(browserName)) {
  console.error("usage: node probe/test/behavior_run.mjs <chromium|firefox>");
  process.exit(2);
}
const pwPath = join(root, "lab", "node_modules", "playwright-core", "index.mjs");
if (!existsSync(pwPath)) { console.error("run `npm install` inside lab/ first"); process.exit(2); }
const pw = await import(pathToFileURL(pwPath).href);

const CHROME = process.env.CHROME_BIN ?? join(homedir(), "Library/Caches/ms-playwright/chromium-1228/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing");
const FIREFOX = process.env.FIREFOX_BIN ?? "/Applications/Firefox.app/Contents/MacOS/firefox";

const TOKEN = '"__VERITELL_BEHAVIOR__"';
const ENDPOINT = "/__veritell/behavior";
const scriptSrc = readFileSync(join(root, "probe", "behavior.js"), "utf8");
const pageHtml = readFileSync(join(here, "behavior.html"), "utf8");

let current = "";
const summaries = []; // {scenario, text, json}
const strayPosts = [];
// Only what a nonce can contain is ever echoed into a page or the script.
const safeNonce = (u) => (u.searchParams.get("n") ?? "x").replace(/[^A-Za-z0-9_-]/g, "") || "x";
const server = http.createServer((req, res) => {
  const u = new URL(req.url, "http://x");
  if (req.method === "POST" && u.pathname === ENDPOINT) {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const text = Buffer.concat(chunks).toString("utf8");
      let json = null; try { json = JSON.parse(text); } catch { /* validated later */ }
      summaries.push({ scenario: current, text, json });
      res.writeHead(204); res.end();
    });
  } else if (u.pathname === "/behavior.js") {
    const body = u.searchParams.has("raw") ? scriptSrc
      : scriptSrc.split(TOKEN).join(JSON.stringify({ nonce: safeNonce(u), endpoint: ENDPOINT }));
    res.writeHead(200, { "content-type": "text/javascript", "cache-control": "no-store" }); res.end(body);
  } else if (u.pathname === "/") {
    const q = u.searchParams.has("raw") ? "?raw=1" : `?n=${safeNonce(u)}`;
    res.writeHead(200, { "content-type": "text/html", "cache-control": "no-store" });
    res.end(pageHtml.replace('"/behavior.js"', `"/behavior.js${q}"`));
  } else if (u.pathname === "/done" || u.pathname === "/blank") {
    res.writeHead(200, { "content-type": "text/html" }); res.end("<!doctype html><title>done</title><p>done</p>");
  } else { res.writeHead(404); res.end(); }
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${server.address().port}`;

let failures = 0;
const check = (name, ok, detail = "") => {
  if (!ok) failures++;
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${ok && !detail ? "" : detail ? " (" + detail + ")" : ""}`);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const mine = (name) => summaries.filter((s) => s.scenario === name);

// Browser launch: Chrome for Testing by path; Firefox: the system build cannot be driven by
// Playwright (it needs Playwright's patched build), so fall back to Playwright's own Firefox.
let used = "";
let browser;
if (browserName === "chromium") {
  browser = await pw.chromium.launch({ executablePath: CHROME, headless: true });
  used = `Chrome for Testing at ${CHROME}`;
} else {
  try {
    browser = await Promise.race([
      pw.firefox.launch({ executablePath: FIREFOX, headless: true, timeout: 15000 }),
      sleep(20000).then(() => { throw new Error("timeout"); }),
    ]);
    used = `system Firefox at ${FIREFOX}`;
  } catch {
    try { browser = await pw.firefox.launch({ headless: true }); } catch (e) {
      console.error("cannot drive system Firefox and Playwright's own Firefox is not installed (npx playwright-core install firefox): " + e.message.split("\n")[0]);
      process.exit(2);
    }
    used = `Playwright's own Firefox at ${pw.firefox.executablePath()}`;
  }
}
console.log(`browser: ${used}, version ${browser.version()}`);

async function scenario(name, fn, { url = `${base}/?n=${name}`, init } = {}) {
  current = name;
  const ctx = await browser.newContext({ viewport: { width: 1000, height: 700 } });
  const page = await ctx.newPage();
  if (init) await page.addInitScript(init);
  await page.goto(url);
  await sleep(150);
  const result = await fn(page);
  await ctx.close();
  await sleep(400);
  return result;
}
// Navigate away and wait for the summary beacon(s).
async function leave(page, name, want = 1) {
  await page.goto(`${base}/blank`);
  for (let i = 0; i < 30 && mine(name).length < want; i++) await sleep(100);
  await sleep(300);
  return mine(name);
}
const last = (name) => mine(name).at(-1)?.json ?? {};
const box = async (page, sel) => page.locator(sel).boundingBox();

// untouched
await scenario("untouched", async (page) => {
  const got = await leave(page, "untouched");
  const j = got[0]?.json ?? {};
  check("untouched: exactly one summary", got.length === 1, `got ${got.length}`);
  check("untouched: trigger hide", j.trigger === "hide");
  const zero = Object.entries(j).filter(([k, v]) => typeof v === "number" && !["v", "dur_ms", "hidden_ms"].includes(k)).every(([, v]) => v === 0);
  check("untouched: every count 0", zero);
  check("untouched: nullable fields null", j.key_gap_cv === null && j.gap_cv === null && j.gap_med_ms === null);
});

// scripted straight pointer
await scenario("straight", async (page) => {
  const pts = [[300, 100], [100, 100], [100, 400], [500, 400], [500, 150]];
  for (const [x, y] of pts) { await page.mouse.move(x, y, { steps: 25 }); await sleep(350); }
  await leave(page, "straight");
  const j = last("straight");
  check("straight: strokes 5", j.strokes === 5, `strokes ${j.strokes}`);
  check("straight: straight 5", j.straight === 5, `straight ${j.straight}`);
});

// curved pointer
await scenario("curved", async (page) => {
  for (let a = 0; a < 5; a++) {
    const cx = 300 + a * 40, cy = 300;
    for (let i = 0; i <= 30; i++) {
      const th = (Math.PI / 2) * (i / 30);
      await page.mouse.move(cx + 150 * Math.sin(th), cy - 150 * (1 - Math.cos(th)) + 150);
      await sleep(8);
    }
    await sleep(300);
  }
  await leave(page, "curved");
  const j = last("curved");
  check("curved: strokes >= 4", j.strokes >= 4, `strokes ${j.strokes}`);
  check("curved: straight 0", j.straight === 0, `straight ${j.straight}`);
});

// centred clicks
await scenario("centered", async (page) => {
  const b = page.locator("#btn");
  await b.click(); await sleep(400); await b.click();
  await leave(page, "centered");
  const j = last("centered");
  check("centered: clicks 2", j.clicks === 2, `clicks ${j.clicks}`);
  check("centered: sized 2", j.sized === 2, `sized ${j.sized}`);
  check("centered: centered 2", j.centered === 2, `centered ${j.centered}`);
  check("centered: teleport >= 1", j.teleport >= 1, `teleport ${j.teleport}`);
});

// off-centre clicks
await scenario("offcentre", async (page) => {
  const b = await box(page, "#btn");
  const x = b.x + 17, y = b.y + 9;
  await page.mouse.move(x, y, { steps: 8 });
  await page.mouse.click(x, y);
  await page.mouse.move(x + 70, y + 30, { steps: 6 });
  await page.mouse.move(x, y, { steps: 6 });
  await page.mouse.click(x, y);
  await leave(page, "offcentre");
  const j = last("offcentre");
  check("offcentre: clicks 2", j.clicks === 2, `clicks ${j.clicks}`);
  check("offcentre: sized 2", j.sized === 2, `sized ${j.sized}`);
  check("offcentre: centered 0", j.centered === 0, `centered ${j.centered}`);
  check("offcentre: teleport 0", j.teleport === 0, `teleport ${j.teleport}`);
});

// small target
await scenario("small", async (page) => {
  const c = page.locator("#cb");
  await c.click(); await sleep(400); await c.click();
  await leave(page, "small");
  const j = last("small");
  check("small: clicks 2", j.clicks === 2, `clicks ${j.clicks}`);
  check("small: sized 0", j.sized === 0, `sized ${j.sized}`);
});

// typing
await scenario("typing", async (page) => {
  await page.locator("#t").focus();
  await page.keyboard.type("abcdefghijkl", { delay: 90 });
  await leave(page, "typing");
  const j = last("typing");
  check("typing: keys 12", j.keys === 12, `keys ${j.keys}`);
  check("typing: key_gap_cv not null and < 300", j.key_gap_cv !== null && j.key_gap_cv < 300, `cv ${j.key_gap_cv}`);
});

// fixed cadence
await scenario("cadence", async (page) => {
  for (let i = 0; i < 8; i++) { if (i) await sleep(700); await page.mouse.click(700, 300); }
  await leave(page, "cadence");
  const j = last("cadence");
  check("cadence: actions 8", j.actions === 8, `actions ${j.actions}`);
  check("cadence: gap_med_ms in 600..800", j.gap_med_ms >= 600 && j.gap_med_ms <= 800, `med ${j.gap_med_ms}`);
  check("cadence: gap_cv < 150", j.gap_cv !== null && j.gap_cv < 150, `cv ${j.gap_cv}`);
});

// submit
await scenario("submit", async (page) => {
  await page.locator("#t").focus();
  await page.keyboard.type("hello", { delay: 40 });
  await Promise.all([page.waitForURL("**/done**"), page.locator("#sub").click()]);
  for (let i = 0; i < 30 && !mine("submit").some((s) => s.json?.trigger === "submit"); i++) await sleep(100);
  await sleep(300);
  const s = mine("submit").find((x) => x.json?.trigger === "submit");
  check("submit: summary with trigger submit", !!s);
  check("submit: submits 1", s?.json?.submits === 1, `submits ${s?.json?.submits}`);
});

// synthetic events
await scenario("synthetic", async (page) => {
  await page.evaluate(() => {
    const b = document.getElementById("btn");
    b.click(); b.click(); b.click();
    b.dispatchEvent(new MouseEvent("click", { detail: 1, bubbles: true }));
  });
  await leave(page, "synthetic");
  const j = last("synthetic");
  check("synthetic: untrusted >= 3", j.untrusted >= 3, `untrusted ${j.untrusted}`);
});

// limits
await scenario("limits", async (page) => {
  for (let i = 0; i < 5; i++) {
    await page.mouse.click(700, 300 + i);
    await page.evaluate(() => {
      const set = (v) => {
        Object.defineProperty(document, "visibilityState", { configurable: true, get: () => v });
        Object.defineProperty(document, "hidden", { configurable: true, get: () => v === "hidden" });
        document.dispatchEvent(new Event("visibilitychange"));
      };
      set("hidden"); set("visible");
    });
    await sleep(100);
  }
  await sleep(300);
  const during = mine("limits").length;
  await leave(page, "limits");
  const total = mine("limits").length;
  check("limits: at most 3 summaries", total >= 1 && total <= 3, `during ${during}, total ${total}`);
});

// unconfigured
await scenario("unconfigured", async (page) => {
  await sleep(500);
  const calls = await page.evaluate(() => window.__addCalls);
  await page.mouse.click(700, 300);
  await leave(page, "unconfigured", 99).catch(() => {});
  check("unconfigured: no addEventListener call", calls === 0, `calls ${calls}`);
  check("unconfigured: no request", mine("unconfigured").length === 0, `posts ${mine("unconfigured").length}`);
}, {
  url: `${base}/?raw=1`,
  init: () => {
    window.__addCalls = 0;
    for (const T of [EventTarget]) {
      const orig = T.prototype.addEventListener;
      T.prototype.addEventListener = function (...a) { window.__addCalls++; return orig.apply(this, a); };
    }
  },
});

// privacy
{
  const all = summaries.filter((s) => s.scenario !== "unconfigured");
  const sizeOk = all.every((s) => Buffer.byteLength(s.text) < 1024);
  const problems = all.flatMap((s) => validate(s.text).map((p) => `${s.scenario}: ${p}`));
  const keysOk = all.every((s) => s.json && Object.keys(s.json).length === 23);
  check("privacy: summaries recorded", all.length >= 10, `${all.length} summaries`);
  check("privacy: every body under 1024 bytes", sizeOk);
  check("privacy: validate reports no problem", problems.length === 0, problems.slice(0, 3).join("; "));
  check("privacy: exactly 23 keys", keysOk);
}

// size
{
  const bytes = Buffer.byteLength(scriptSrc);
  check("size: behavior.js at most 10240 bytes", bytes <= 10240, `${bytes} bytes`);
  check("size: token exactly once", scriptSrc.split(TOKEN).length === 2);
}

await browser.close();
server.close();
console.log(failures ? `FAILED: ${failures} assertion(s)` : "ALL PASSED");
process.exit(failures ? 1 : 0);
