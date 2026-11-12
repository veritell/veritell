// Bot lab runner: node lab/run.mjs [--only id,id] [--json out.json] [--keep-logs] [--extra file.mjs,...]
//   --extra  more scenarios from files kept elsewhere, each exporting `scenarios`
//            (they can import their building blocks from ./scenarios.mjs)
import { writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { existsSync } from "node:fs";
import { scenarios as builtIn } from "./scenarios.mjs";
import { here, GATEWAY, makeTmp, removeDir, makeCert, startOrigin, startGateway, cleanupSync, sleep, saveLog } from "./lib.mjs";

const args = process.argv.slice(2);
const opt = (n) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : undefined; };
const only = opt("--only")?.split(",");
const jsonOut = opt("--json");
const keepLogs = args.includes("--keep-logs");
const scenarios = [...builtIn];
for (const file of opt("--extra")?.split(",") ?? []) {
  const mod = await import(pathToFileURL(resolve(file)).href);
  for (const s of mod.scenarios ?? []) {
    if (scenarios.some((t) => t.id === s.id)) { console.error(`duplicate scenario id: ${s.id} (${file})`); process.exit(2); }
    scenarios.push(s);
  }
}

// Always clean up, including Ctrl-C.
process.on("exit", cleanupSync);
for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(sig, () => { cleanupSync(); process.exit(130); });
process.on("uncaughtException", (e) => { console.error(e); cleanupSync(); process.exit(1); });

if (!existsSync(GATEWAY)) { console.error(`gateway binary not found: ${GATEWAY} (build it with cargo build --release -p veritell-proxy)`); process.exit(2); }
const selected = only ? scenarios.filter((s) => only.includes(s.id)) : scenarios;
if (only) for (const id of only) if (!scenarios.some((s) => s.id === id)) { console.error(`unknown scenario: ${id}`); process.exit(2); }

const workDir = makeTmp("work");
const cert = makeCert(workDir);
const pathOf = (e) => e.path.split("?")[0];
const group = (dets) => {
  const g = { identity: [], network: [], client: [] };
  for (const d of dets) (g[d.layer] ??= []).push(d.id);
  return g;
};

async function runScenario(sc) {
  const rec = { id: sc.id, client: sc.client, expectation: sc.expect.text, status: "fail", reason: "" };
  const skip = await sc.available();
  if (skip) return { ...rec, status: "not run", reason: skip };

  const dir = makeTmp(sc.id);
  const profile = join(dir, "profile");
  const { mkdirSync } = await import("node:fs");
  mkdirSync(profile);
  let origin, gw, client;
  try {
    origin = await startOrigin(sc.id);
    gw = await startGateway({ cert: cert.cert, key: cert.key, originPort: origin.port, logPath: join(dir, "gateway.log"),
      policy: sc.policy });
    const url = `https://localhost:${gw.port}/lab/start?s=${sc.id}`;
    client = await sc.launch({ url, profile, cert, port: gw.port });

    let after = null;
    const deadline = Date.now() + 30000;
    while (Date.now() < deadline && !after) {
      if (gw.child.exitCode !== null) throw new Error("gateway died during the scenario");
      try { after = (await gw.events()).find((e) => e.kind === "request" && pathOf(e) === "/lab/after") ?? null; } catch { /* retry */ }
      if (!after) await sleep(250);
    }
    if (after) { // let the page finish its follow-up request and the origin log it
      for (let i = 0; i < 20 && !origin.seen.includes("/lab/done"); i++) await sleep(150);
    }
    await client.stop(); client = null;
    if (!after) throw new Error("no request event for /lab/after within 30 s");

    const events = await gw.events();
    after = events.find((e) => e.kind === "request" && pathOf(e) === "/lab/after");
    const probe = events.find((e) => e.kind === "probe") ?? null;
    const byLayer = group(after.detections);
    const data = { after, probe, originSaw: [...origin.seen], byLayer, ids: after.detections.map((d) => d.id) };
    const verdict = sc.expect.check(data);
    Object.assign(rec, {
      status: verdict.measured ? "measured" : verdict.ok ? "pass" : "fail", reason: verdict.note ?? "", measured: verdict.measured,
      score: after.score, class: after.class, token: after.token, outcome: after.outcome,
      network: byLayer.network, clientLayer: byLayer.client, identity: byLayer.identity,
      later: [...(byLayer.behavior ?? []), ...(byLayer.population ?? [])],
      detections: after.detections.map((d) => ({ id: d.id, layer: d.layer, penalty: d.penalty, detail: d.detail })),
      probe: probe && { outcome: probe.outcome, detections: probe.detections.map((d) => ({ id: d.id, layer: d.layer, penalty: d.penalty, detail: d.detail })) },
      originSaw: data.originSaw,
    });
    // A known gap (scenario.knownGap) that is still missed is reported, not
    // failed, so the run stays useful in CI; one that is now caught is
    // flagged so the marker can be removed. A crash is never a known gap.
    if (sc.knownGap) {
      if (rec.status === "fail") { rec.status = "known gap"; rec.reason = sc.knownGap; }
      else if (rec.status === "pass") rec.reason = "gap closed: remove knownGap from this scenario";
    }
  } catch (e) {
    rec.status = "fail"; rec.reason = `error: ${e.message}`;
  } finally {
    try { await client?.stop(); } catch { /* ignore */ }
    try { await gw?.stop(); } catch { /* ignore */ }
    origin?.close();
    if (keepLogs && gw) saveLog(join(dir, "gateway.log"), sc.id, join(here, "logs"));
    removeDir(dir);
  }
  return rec;
}

const results = [];
for (const sc of selected) {
  process.stderr.write(`running ${sc.id} ...\n`);
  results.push(await runScenario(sc));
}
removeDir(workDir);

// ---- report ---------------------------------------------------------------
const cols = ["scenario", "client", "score", "class", "network", "client layer", "behaviour, population", "expectation", "result"];
const rows = results.map((r) => [r.id, r.client, r.score ?? "-", r.class ?? "-", r.network?.join(",") || "-", r.clientLayer?.join(",") || "-",
  r.later?.join(",") || "-",
  r.expectation, r.status === "pass" ? "PASS" : r.status === "measured" ? `MEASURED: ${r.measured}` : r.status === "not run" ? `not run: ${r.reason}`
    : r.status === "known gap" ? "KNOWN GAP" : "FAIL"]);
const w = cols.map((c, i) => Math.max(c.length, ...rows.map((r) => String(r[i]).length)));
const line = (r) => r.map((c, i) => String(c).padEnd(w[i])).join(" | ");
console.log("\n" + line(cols) + "\n" + w.map((n) => "-".repeat(n)).join("-+-"));
for (const r of rows) console.log(line(r));

console.log("");
for (const r of results) {
  if (r.status === "not run") continue;
  console.log(`[${r.id}] ${r.status.toUpperCase()}${r.reason ? " - " + r.reason : ""}`);
  if (r.token !== undefined) console.log(`  token=${r.token} outcome=${r.outcome} origin saw: ${r.originSaw.join(" ")}`);
  for (const d of r.detections ?? []) console.log(`  ${d.layer}/${d.id} (-${d.penalty}): ${d.detail}`);
  if (r.probe) {
    console.log(`  probe event: outcome=${r.probe.outcome}, ${r.probe.detections.length ? r.probe.detections.length + " detection(s)" : "no detections"}`);
    for (const d of r.probe.detections) console.log(`    probe ${d.layer}/${d.id} (-${d.penalty}): ${d.detail}`);
  } else console.log("  probe event: none (no report reached the gateway)");
  if (r.status === "measured" && r.measured === "not detected" && !r.id.startsWith("curl")) console.log("  raw probe report: not captured");
}
const failed = results.filter((r) => r.status === "fail").length;
const count = (st) => results.filter((r) => r.status === st).length;
console.log(`\n${count("pass")} passed, ${failed} failed, ${count("known gap")} known gaps, ${count("measured")} measured, ${count("not run")} not run`);
if (jsonOut) writeFileSync(jsonOut, JSON.stringify({ when: new Date().toISOString(), results }, null, 2) + "\n");
process.exit(failed ? 1 : 0);
