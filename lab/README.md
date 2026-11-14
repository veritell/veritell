# Veritell bot lab

The gateway's own regression suite. It starts a fresh gateway (shadow mode, or with a policy file) in front of a tiny
local origin, drives a real or automated browser at it, and records what the gateway detected on the page's follow-up
request `/lab/after`. Everything runs on localhost with a throwaway self-signed certificate. Only Node built-ins are used.

## Run

```
cargo build --release -p veritell-proxy      # once
node lab/run.mjs [--only id,id] [--json out.json] [--keep-logs]
```

Needs `openssl`, Chromium (`CHROME_BIN`, default the Playwright cache) and Firefox (`FIREFOX_BIN`). Headed Chromium
opens a window for a few seconds. `VERITELL_BIN` overrides the gateway binary. `--keep-logs` copies each gateway log to
`lab/logs/<id>.log`. Exit code is 0 unless a scenario failed; "not run" and a known gap (`knownGap` on a scenario: a
detection we know we miss) do not fail the run. A known gap that starts passing says so, so the marker can go.

## Optional tools

Scenarios whose tool is missing report "not run: reason". Nothing is installed globally; everything lives in `lab/`.

```
# Playwright, Puppeteer, Patchright (npm, into lab/node_modules). No browser is downloaded: all use the local Chromium.
PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 PUPPETEER_SKIP_DOWNLOAD=1 npm install --prefix lab

# nodriver, Selenium, curl_cffi (Python virtual environment in lab/.venv, versions pinned in lab/requirements.txt)
python3 -m venv lab/.venv
lab/.venv/bin/python -m pip install -r lab/requirements.txt
```

Selenium needs a chromedriver that matches the local Chromium (major 149). Selenium Manager downloads it into
`~/.cache/selenium` on first use. If it cannot, the scenario fails with the Selenium error. Python clients are small
scripts in `lab/clients/`, started with `lab/.venv/bin/python script URL PROFILE_DIR`, and killed by the runner like any
other client. `CHROME_BIN` is passed to them. Camoufox downloads its own browser and is not approved yet, so its
scenario always reports "not run: camoufox not installed".

## Against a live site

```
LAB_TARGET_HOSTS=www.example.org node lab/run.mjs --target https://www.example.org [--dwell 20] [--only id,id] [--json out.json]
```

Runs each client against a site you operate, behind its own gateway, instead of a local one: the client opens
`<target>/?s=<scenario id>`, stays `--dwell` seconds (default 20), and is stopped. Nothing is checked here; the site's
gateway records what it saw, and the JSON output gives each scenario's start and end time for matching. The host must
be listed in `LAB_TARGET_HOSTS`, so a typo cannot send the clients elsewhere, and only `https` is accepted. Scenarios
with a policy need the lab's own gateway and are skipped. Clients that go on to the local origin's `/lab/...` pages
request them on the site too, where they are not found. Only run it against a site you operate.

## Expectations

`clean`, `detected`, `blocked` and the other expectations decide PASS or FAIL. `measure` never fails: the result column
reads `MEASURED: detected (ids)` or `MEASURED: not detected`, and the summary counts measured scenarios separately.
It is used where the question is whether the gateway sees the tool at all (Patchright, nodriver).

## Scenarios kept elsewhere

`node lab/run.mjs --extra path/to/more.mjs` adds the scenarios a file exports as `scenarios`. Such a file can import its
building blocks (`pythonScenario`, `plainChrome`, `detected`, `measure` and the rest) from `lab/scenarios.mjs`. Gaps that
are still open are tracked that way, outside this repository, until they are closed: see CONTRIBUTING.md on reporting a
bypass.

## Reading the table

Columns: scenario, client, score and class of the `/lab/after` request, detection ids by layer (network = TLS/HTTP
fingerprint, client = probe findings), the expectation, and the result: PASS, FAIL, MEASURED or "not run: reason". The lines below
the table list every detection with its detail text, the token state, and the probe event (outcome and its detections with detail text). The JSON output has the same. A scenario that
expects `detected` but comes back clean is a FAIL: that is a real gap in the gateway, not a lab bug. Do not loosen the
expectation to make it pass.

Firefox cannot load the self-signed page unless it trusts it; the lab writes a `cert_override.txt` for `localhost:<port>`
into the throwaway profile (SHA-256 fingerprint of the generated certificate). No system or keychain trust is changed.
Chromium is started with `--use-mock-keychain` so it never touches the macOS keychain.

## Add a scenario

Append an object to `scenarios` in `scenarios.mjs`: `id`, `client`, optional `policy`, `available()` (returns a reason
string to skip), `launch(ctx)` returning `{ stop() }`, and `expect` (`text` plus `check(data)` returning `{ ok, note }`).
Spawn browsers with `spawnTracked` so they are killed on exit, and use `ctx.profile` as the fresh profile directory.

## Not covered yet

Camoufox (not installed), the raw probe report of measured scenarios that came back clean (not captured), commercial
scraping APIs, real mobile devices.

## Recording a person

```
node lab/record.mjs            # then open http://127.0.0.1:8765/ and use the form
cargo run -q -p veritell-behavior --example check_summaries < lab/recordings/local/human.jsonl
```

Only the counts in `probe/BEHAVIOR.md` are saved, with the browser family and the time, in `lab/recordings/local/`, which git ignores: a recording of a person stays on the machine that made it.

`lab/recordings/human.jsonl` is made up, not recorded: human-like sessions (mouse, trackpad, phone, keyboard only, a password manager) marked `"synthetic": true`. The behaviour crate's acceptance tests check that no rule fires on any of them.
