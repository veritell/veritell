// Records how a person uses a form, as behaviour summaries (counts only).
//
//   node lab/record.mjs [--port 8765] [--host 127.0.0.1] [--out lab/recordings/local/human.jsonl]
//
// Open http://127.0.0.1:8765/ in any browser, say how you will use the form
// (mouse, trackpad, touch, keyboard only, autofill), then fill it in and submit. Each visit appends the
// summaries probe/behavior.js sent to the output file, one JSON object per
// line, with the browser's User-Agent family. Nothing typed into the form
// is read or stored: the form posts to this server, which discards the body.
import http from "node:http";
import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { validate } from "../probe/validate_behavior.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const opt = (n, d) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : d; };
const port = Number(opt("--port", "8765"));
// Loopback by default. `--host 0.0.0.0` lets a phone on the same network reach
// the recorder; anyone on that network can then open it, so stop it afterwards.
const host = opt("--host", "127.0.0.1");
// Real sessions stay out of git: `recordings/local/` is ignored.
const out = opt("--out", join(here, "recordings", "local", "human.jsonl"));
mkdirSync(dirname(out), { recursive: true });

const template = readFileSync(join(here, "..", "probe", "behavior.js"), "utf8");
const DEVICES = ["mouse", "trackpad", "touch", "keyboard", "autofill"];
const deviceOf = (url) => { const d = new URL(url, "http://x").searchParams.get("device"); return DEVICES.includes(d) ? d : "unknown"; };
const script = (device) => template.replace('"__VERITELL_BEHAVIOR__"',
  JSON.stringify({ nonce: "recording", endpoint: `/__veritell/behavior?device=${device}` }));

const style = `<style>
body{font:16px/1.5 system-ui,sans-serif;max-width:640px;margin:40px auto;padding:0 16px;color:#222}
label{display:block;margin:18px 0 4px}input[type=text],input[type=email],select,textarea{width:100%;padding:8px;font:inherit;box-sizing:border-box}
textarea{height:110px}button{font:inherit;padding:10px 22px;margin:24px 12px 0 0}.row{margin-top:18px}p.note{color:#666}
</style>`;
const start = `<!doctype html><meta charset="utf-8"><title>Recorder</title>${style}
<h1>Behaviour recorder</h1>
<p>Pick how you are going to fill in the form this time, then fill it in and press "Sign up".
Nothing on this page is recorded.</p>
<ul style="line-height:2.2">
<li><a href="/form?device=mouse">With a mouse</a></li>
<li><a href="/form?device=trackpad">With a trackpad</a></li>
<li><a href="/form?device=touch">On a touch screen</a></li>
<li><a href="/form?device=keyboard">Keyboard only (Tab, Space, Enter; no pointer)</a></li>
<li><a href="/form?device=autofill">Letting the browser or a password manager fill what it can</a></li>
</ul>`;
const form = (n, device) => `<!doctype html><meta charset="utf-8"><title>Recording ${n}</title>${style}
<h1>Workshop sign-up</h1>
<p class="note">Fill this in the way you would any form. What you type is not kept; only counts of
pointer movement, clicks, keys and timing are recorded.</p>
<form method="post" action="/submit?device=${device}">
<label for="name">Name</label><input type="text" id="name" name="name" autocomplete="${device === "autofill" ? "name" : "off"}">
<label for="email">Email</label><input type="email" id="email" name="email" autocomplete="${device === "autofill" ? "email" : "off"}">
<label for="day">Preferred day</label>
<select id="day" name="day"><option>Monday</option><option>Wednesday</option><option>Friday</option></select>
<div class="row"><input type="checkbox" id="lunch" name="lunch"> <label for="lunch" style="display:inline">I will stay for lunch</label></div>
<label for="notes">Anything we should know?</label><textarea id="notes" name="notes"></textarea>
<p style="margin-top:420px">Thank you. Sessions run from 9:30 to 16:00, with a break at noon.</p>
<button type="button" id="terms" onclick="this.textContent='Terms read'">Read the terms</button>
<button type="submit" id="send">Sign up</button>
</form>
<script src="/behavior.js?device=${device}"></script>`;
const done = (n) => `<!doctype html><meta charset="utf-8"><title>Recorded</title>${style}
<h1>Recorded</h1><p>${n} ${n === 1 ? "summary" : "summaries"} saved so far.</p>
<p><a href="/">Do it once more</a>, ideally a different way each time.</p>`;

let visits = 0, saved = 0;
const family = (ua = "") => (/Firefox\//.test(ua) ? "firefox" : /Edg\//.test(ua) ? "edge" : /Chrome\//.test(ua) ? "chromium" : /Safari\//.test(ua) ? "safari" : "other");
const server = http.createServer((req, res) => {
  const path = req.url.split("?")[0];
  const send = (type, body) => { res.writeHead(200, { "content-type": type, "cache-control": "no-store" }); res.end(body); };
  if (req.method === "POST" && path === "/__veritell/behavior") {
    let body = "";
    req.on("data", (c) => { if (body.length < 4096) body += c; });
    req.on("end", () => {
      const problems = validate(body);
      if (!problems.length) {
        const summary = JSON.parse(body);
        delete summary.nonce;
        const device = deviceOf(req.url);
        appendFileSync(out, JSON.stringify({ when: new Date().toISOString(), browser: family(req.headers["user-agent"]), device, summary }) + "\n");
        saved++;
        console.log(`saved summary ${saved} (${device}, ${summary.trigger})`);
      } else console.log(`rejected a summary: ${problems.join("; ")}`);
      res.writeHead(204); res.end();
    });
    return;
  }
  if (req.method === "POST" && path === "/submit") { req.resume(); req.on("end", () => send("text/html", done(saved))); return; }
  if (path === "/behavior.js") return send("text/javascript", script(deviceOf(req.url)));
  if (path === "/form") return send("text/html", form(++visits, deviceOf(req.url)));
  if (path === "/") return send("text/html", start);
  res.writeHead(404); res.end();
});
server.listen(port, host, () => console.log(`recorder on http://${host}:${port}/  ->  ${out}`));
