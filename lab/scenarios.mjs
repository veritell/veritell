// Scenario data plus small launch functions. To add one, append an object to `scenarios`.
//
//   id        unique name (used by --only)
//   client    text for the table
//   policy    optional policy file path (relative to lab/); omitted = shadow mode
//   available async () => null | "reason it cannot run"
//   launch    async (ctx) => { stop() }   ctx: { url, profile, cert, port, chrome, firefox }
//   expect    { text, check(data) -> { ok, note? } }
//             data: { after, probe, originSaw, byLayer, ids }
//             A `measure` expectation never fails: check returns { ok: true, measured: "detected (ids)" | "not detected" }.
//   knownGap  optional text: a detection we know we miss. Still missed, it is reported, not failed.
//
// LAB_SOFTWARE_GPU=1 (CI machines have no GPU): the human expectations accept a
// gpu_software finding, and its penalty, as what that machine really is. Any
// other detection still fails them.
import { join, isAbsolute } from "node:path";
import { writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { here, CHROME, FIREFOX, existsSync, spawnTracked, stopProc, chromeBase, normalUA, devtoolsEndpoint, Cdp, sleep } from "./lib.mjs";

const SILENT = join(here, "policies", "silent.yaml");
const hasChrome = async () => (existsSync(CHROME) ? null : `Chromium not found at ${CHROME}`);
const hasFirefox = async () => (existsSync(FIREFOX) ? null : `Firefox not found at ${FIREFOX}`);

// ---- expectations ---------------------------------------------------------
const SOFTWARE_GPU = process.env.LAB_SOFTWARE_GPU === "1";
const isGpuSoftware = (d) => d.id === "gpu_software";
/** Detections a human browser may show on this machine: none, or gpu_software where there is no GPU. */
const unexpected = (dets) => (SOFTWARE_GPU ? dets.filter((d) => !isGpuSoftware(d)) : dets);
/** The score with an accepted gpu_software penalty given back. */
const humanScore = (after) => after.score + (SOFTWARE_GPU ? after.detections.filter(isGpuSoftware).reduce((s, d) => s + (d.penalty ?? 0), 0) : 0);
const clean = {
  text: "clean",
  check: ({ after, probe }) => {
    const bad = [];
    if (Math.min(99, humanScore(after)) !== 99) bad.push(`score ${after.score}, wanted 99`);
    const extra = unexpected(after.detections);
    if (extra.length) bad.push(`detections: ${extra.map((d) => `${d.layer}/${d.id}`).join(", ")}`);
    if (!probe) bad.push("no probe event");
    else if (probe.outcome !== "probe_clean" && !(SOFTWARE_GPU && probe.outcome === "probe_flagged" && !unexpected(probe.detections).length))
      bad.push(`probe outcome ${probe.outcome}`);
    return { ok: !bad.length, note: bad.join("; ") };
  },
};
const detected = (layer) => ({
  text: layer ? `detected (${layer})` : "detected",
  check: ({ after }) => {
    // Without a GPU, gpu_software is true of every browser: it never counts as a catch.
    const hit = unexpected(after.detections).some((d) => !layer || d.layer === layer);
    return { ok: hit, note: hit ? "" : `no ${layer ?? ""} detection on /lab/after` };
  },
});
const detectedAny = {
  text: "detected (any layer)",
  check: ({ after, byLayer }) => ({
    ok: unexpected(after.detections).length > 0,
    note: `client layer ${byLayer.client.length ? "saw: " + byLayer.client.join(",") : "saw nothing"}`,
  }),
};
const stealthIds = ["native_tampered", "realm_mismatch", "http_ua_mismatch", "uad_mismatch", "webdriver_true"];
const stealthExpect = {
  text: `detected: one of ${stealthIds.join("/")}`,
  check: ({ ids }) => ({ ok: stealthIds.some((i) => ids.includes(i)), note: `saw: ${ids.join(",") || "nothing"}` }),
};
const reachedValid = (needClient) => ({
  text: needClient ? "reached origin, token valid, client detection" : "reached origin, token valid, no detections",
  check: ({ after, originSaw, byLayer }) => {
    const bad = [];
    if (!originSaw.includes("/lab/after")) bad.push("origin never saw /lab/after");
    if (after.token !== "valid") bad.push(`token ${after.token}`);
    if (needClient && !unexpected(after.detections).some((d) => d.layer === "client")) bad.push("no client detection");
    if (!needClient && unexpected(after.detections).length) bad.push(`detections: ${unexpected(after.detections).map((d) => d.id).join(", ")}`);
    return { ok: !bad.length, note: bad.join("; ") };
  },
});

const measure = {
  text: "measure",
  check: ({ ids }) => ({ ok: true, measured: ids.length ? `detected (${ids.join(", ")})` : "not detected" }),
};
const blocked = {
  text: "blocked (origin never sees /lab/after)",
  check: ({ after, originSaw }) => {
    const seen = originSaw.includes("/lab/after");
    return { ok: !seen, note: `gateway logged outcome=${after.outcome} class=${after.class} token=${after.token}${seen ? "; origin saw /lab/after" : ""}` };
  },
};

// ---- launchers ------------------------------------------------------------
async function plainChrome(ctx, extra) {
  const child = spawnTracked(CHROME, [...chromeBase(ctx.profile), ...extra, ctx.url]);
  return { stop: () => stopProc(child) };
}

/** Headless Chromium with remote debugging, driven over CDP like an automation library. */
async function cdpChrome(ctx, { stealth }) {
  const args = [...chromeBase(ctx.profile), "--headless=new", "--remote-debugging-port=0", ...(stealth ? ["--enable-automation"] : []), "about:blank"];
  const child = spawnTracked(CHROME, args);
  let cdp;
  try {
    cdp = await Cdp.connect(await devtoolsEndpoint(ctx.profile));
    const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
    await cdp.send("Runtime.enable", {}, sessionId);
    await cdp.send("Page.enable", {}, sessionId);
    if (stealth) {
      await cdp.send("Emulation.setUserAgentOverride", { userAgent: normalUA() }, sessionId);
      await cdp.send("Page.addScriptToEvaluateOnNewDocument", {
        source: "Object.defineProperty(Navigator.prototype, 'webdriver', { get: function () { return false; }, configurable: true, enumerable: true });",
      }, sessionId);
    }
    await cdp.send("Page.navigate", { url: ctx.url }, sessionId);
  } catch (e) { cdp?.close(); await stopProc(child); throw e; }
  return { stop: async () => { cdp.close(); await stopProc(child); } };
}

/** Firefox cannot load a self-signed page, so trust it for this host:port with a cert_override.txt. */
async function firefox(ctx) {
  const line = `localhost:${ctx.port}:\tOID.2.16.840.1.101.3.4.2.1\t${ctx.cert.fingerprint}\tU\t\n`;
  writeFileSync(join(ctx.profile, "cert_override.txt"), "# PSM Certificate Override Settings file\n# This is a generated file!  Do not edit.\n" + line);
  writeFileSync(join(ctx.profile, "user.js"), 'user_pref("browser.shell.checkDefaultBrowser", false);\nuser_pref("datareporting.policy.dataSubmissionEnabled", false);\n');
  const child = spawnTracked(FIREFOX, ["--headless", "--no-remote", "--profile", ctx.profile, ctx.url]);
  return { stop: () => stopProc(child) };
}

/** Playwright / Puppeteer are optional: import them from lab/node_modules if present. */
async function optionalImport(name) {
  if (!existsSync(join(here, "node_modules", name, "package.json"))) return null;
  try { return await import(name); } catch { return null; }
}

const PYTHON = join(here, ".venv", "bin", "python");
function pythonHas(module) {
  if (!existsSync(PYTHON)) return `lab/.venv not created (python3 -m venv lab/.venv)`;
  try { execFileSync(PYTHON, ["-c", `import ${module}`], { stdio: "ignore", timeout: 20000 }); return null; }
  catch { return `python module ${module} not installed in lab/.venv`; }
}

/** A Python client script under lab/clients/, started with the URL and the profile directory. */
function pythonScenario(id, client, module, script, extra, expect, policy) {
  return { id, client, policy, expect,
    available: async () => (pythonHas(module) ?? (await hasChrome())),
    launch: async (ctx) => {
      const child = spawnTracked(PYTHON, [isAbsolute(script) ? script : join(here, "clients", script), ctx.url, ctx.profile, ...extra], { env: { ...process.env, CHROME_BIN: CHROME } });
      return { stop: () => stopProc(child) };
    } };
}

/** Patchright (npm, optional): clients/patchright_client.mjs, mode "best" or "headless". */
function patchrightScenario(id, client, mode, expect = measure) {
  return { id, client, expect,
    available: async () => ((await optionalImport("patchright")) ? await hasChrome() : "patchright not installed"),
    launch: async (ctx) => {
      const child = spawnTracked(process.execPath, [join(here, "clients", "patchright_client.mjs"), ctx.url, ctx.profile, mode], { env: { ...process.env, CHROME_BIN: CHROME } });
      return { stop: () => stopProc(child) };
    } };
}

export const scenarios = [
  { id: "chromium-headed", client: "Chromium headed", available: hasChrome, expect: clean,
    launch: (ctx) => plainChrome(ctx, []) },
  { id: "firefox", client: "Firefox (headless)", available: hasFirefox, expect: clean, launch: firefox },
  { id: "chromium-automation-flag", client: "Chromium headed --enable-automation", available: hasChrome, expect: detected(),
    launch: (ctx) => plainChrome(ctx, ["--enable-automation"]) },
  { id: "cdp-driven", client: "Chromium headless via CDP", available: hasChrome, expect: detectedAny,
    launch: (ctx) => cdpChrome(ctx, { stealth: false }) },
  { id: "cdp-stealth", client: "CDP + UA override + webdriver patch", available: hasChrome, expect: stealthExpect,
    launch: (ctx) => cdpChrome(ctx, { stealth: true }) },
  { id: "silent-challenge-human", client: "Chromium headed, silent challenge", policy: SILENT, available: hasChrome,
    expect: reachedValid(false), launch: (ctx) => plainChrome(ctx, []) },
  { id: "silent-challenge-cdp-stealth", client: "cdp-stealth, silent challenge", policy: SILENT, available: hasChrome,
    expect: reachedValid(true), launch: (ctx) => cdpChrome(ctx, { stealth: true }) },
  { id: "playwright", client: "playwright-core defaults", expect: detected(),
    available: async () => ((await optionalImport("playwright-core")) ? null : "playwright-core not installed"),
    launch: async (ctx) => {
      const { chromium } = await optionalImport("playwright-core");
      const browser = await chromium.launch({ executablePath: CHROME });
      const context = await browser.newContext({ ignoreHTTPSErrors: true });
      const page = await context.newPage();
      page.goto(ctx.url).catch(() => {});
      return { stop: () => browser.close() };
    } },
  { id: "puppeteer", client: "puppeteer-core defaults", expect: detected(),
    available: async () => ((await optionalImport("puppeteer-core")) ? null : "puppeteer-core not installed"),
    launch: async (ctx) => {
      const mod = await optionalImport("puppeteer-core");
      const puppeteer = mod.default ?? mod;
      const browser = await puppeteer.launch({ executablePath: CHROME, acceptInsecureCerts: true });
      const page = await browser.newPage();
      page.goto(ctx.url).catch(() => {});
      return { stop: () => browser.close() };
    } },

  // ---- optional tools: Patchright (npm), nodriver / Selenium / curl_cffi (venv), Camoufox (not approved) -------
  patchrightScenario("patchright", "Patchright, README best settings (persistent, headed)", "best"),
  patchrightScenario("patchright-headless", "Patchright headless, defaults", "headless"),
  // L15: the same undetected browser, now acting on a form with the library's default click and fill.
  patchrightScenario("patchright-form", "Patchright best settings, scripted form", "form", detected("behavior")),
  patchrightScenario("patchright-form-jitter", "Patchright, form, random click points and key delays", "form-jitter", detected("behavior")),
  patchrightScenario("patchright-form-careful", "Patchright, form, curved pointer paths and a random delay per key", "form-careful", measure),
  pythonScenario("nodriver-form", "nodriver, scripted form, library defaults", "nodriver", "nodriver_client.py", ["form"], detected("behavior")),
  pythonScenario("nodriver", "nodriver defaults, headed", "nodriver", "nodriver_client.py", [], measure),
  pythonScenario("nodriver-headless", "nodriver headless", "nodriver", "nodriver_client.py", ["headless"], measure),
  pythonScenario("selenium", "Selenium Chrome defaults, headed", "selenium", "selenium_client.py", [], detected()),
  pythonScenario("selenium-headless", "Selenium Chrome headless", "selenium", "selenium_client.py", ["headless"], detected()),
  pythonScenario("curl-cffi-challenge", "curl_cffi, silent challenge policy", "curl_cffi", "curl_cffi_client.py", ["plain"], blocked, SILENT),
  { id: "camoufox", client: "Camoufox", expect: measure, launch: async () => { throw new Error("not installed"); },
    available: async () => "camoufox not installed" },
];
void sleep;

// For scenario files kept outside this repository (run.mjs --extra FILE): the
// same building blocks the scenarios above use.
export { pythonScenario, patchrightScenario, plainChrome, cdpChrome, detected, detectedAny, measure, blocked, hasChrome, normalUA, SILENT };
