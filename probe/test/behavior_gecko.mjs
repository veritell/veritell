// Runs probe/behavior.js in the installed Firefox without a driver:
//   node probe/test/behavior_gecko.mjs
// Playwright cannot drive a stock Firefox, so the page drives itself with
// synthetic events (counted, and reported as untrusted) and then navigates
// away. This shows that the script loads, counts, measures a stroke and a
// click, and sends on hide in Gecko. It does not show trusted input.
import http from "node:http";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { validate } from "../validate_behavior.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const FIREFOX = process.env.FIREFOX_BIN ?? "/Applications/Firefox.app/Contents/MacOS/firefox";
if (!existsSync(FIREFOX)) { console.error(`Firefox not found at ${FIREFOX}`); process.exit(2); }

const script = readFileSync(join(here, "..", "behavior.js"), "utf8")
  .replace('"__VERITELL_BEHAVIOR__"', JSON.stringify({ nonce: "gecko-test", endpoint: "/__veritell/behavior" }));
const page = `<!doctype html><meta charset="utf-8"><title>gecko</title>
<button id="b" type="button" style="position:absolute;left:100px;top:200px;width:120px;height:40px">b</button>
<script src="/behavior.js"></script>
<script>
(async function () {
  var wait = function (ms) { return new Promise(function (r) { setTimeout(r, ms); }); };
  var ev = function (type, x, y, extra) {
    document.dispatchEvent(new PointerEvent(type, Object.assign({ pointerType: "mouse", clientX: x, clientY: y, bubbles: true }, extra)));
  };
  for (var i = 0; i < 8; i++) { ev("pointermove", 10 + i * 20, 50); await wait(12); }
  await wait(300);
  document.getElementById("b").dispatchEvent(new PointerEvent("click", { pointerType: "mouse", clientX: 160, clientY: 220, detail: 1, bubbles: true }));
  await wait(100);
  location.href = "/bye";
})();
</script>`;

const posts = [];
const server = http.createServer((req, res) => {
  const path = req.url.split("?")[0];
  if (req.method === "POST") {
    let body = "";
    req.on("data", (c) => { body += c; });
    req.on("end", () => { posts.push(body); res.writeHead(204); res.end(); });
    return;
  }
  const [type, text] = path === "/behavior.js" ? ["text/javascript", script] : path === "/bye" ? ["text/html", "<p>bye"] : ["text/html", page];
  res.writeHead(200, { "content-type": type }); res.end(text);
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const profile = mkdtempSync(join(tmpdir(), "veritell-gecko-"));
writeFileSync(join(profile, "user.js"), 'user_pref("browser.shell.checkDefaultBrowser", false);\nuser_pref("datareporting.policy.dataSubmissionEnabled", false);\n');
const child = spawn(FIREFOX, ["--headless", "--no-remote", "--profile", profile, `http://127.0.0.1:${server.address().port}/`], { stdio: "ignore" });

const deadline = Date.now() + 30000;
while (!posts.length && Date.now() < deadline) await new Promise((r) => setTimeout(r, 200));
await new Promise((r) => setTimeout(r, 500));
child.kill("SIGTERM");
server.close(); server.closeAllConnections?.();
await new Promise((r) => setTimeout(r, 500));
rmSync(profile, { recursive: true, force: true });

let fails = 0;
const check = (name, ok, got) => { console.log(`${ok ? "PASS" : "FAIL"} ${name} (${got})`); if (!ok) fails++; };
check("one summary arrived", posts.length === 1, posts.length);
if (posts.length) {
  const s = JSON.parse(posts[0]);
  check("valid against the schema", validate(posts[0]).length === 0, validate(posts[0]).join("; ") || "no problems");
  check("trigger hide", s.trigger === "hide", s.trigger);
  check("moves 8", s.moves === 8, s.moves);
  check("one straight stroke", s.strokes === 1 && s.straight === 1, `${s.strokes}/${s.straight}`);
  check("one sized, centred click", s.clicks === 1 && s.sized === 1 && s.centered === 1, `${s.clicks}/${s.sized}/${s.centered}`);
  check("all nine events untrusted", s.untrusted === 9, s.untrusted);
}
console.log(fails ? `${fails} FAILED` : "ALL PASSED");
process.exit(fails ? 1 : 0);
