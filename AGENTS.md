# Agent guide: core (public, AGPL-3.0-only)

The open gateway. **This repo is public.** Everything committed here is
published: no visitor data, partner names, private notes, or values tuned on
a site's real traffic.

## Layout

| Path | What |
|---|---|
| `crates/veritell-proxy` | The gateway binary `veritell` (Pingora, BoringSSL) |
| `crates/veritell-*` | One crate per layer: `fp` network fingerprints, `ua`, `probe`, `behavior`, `agg` population, `policy`, `model`, `token`, `privacypass`, `wba`, `directory`, `events`, `dash`, `feed` (bundle format and verification only), `identity` crawler and network checks, `quota` per-identity rates, `probe-build` per-build sealed probes, `share` opt-in sharing between installs, `persist` state files, `core` shared types |
| `probe/` | `probe.js` and `behavior.js`, embedded into the binary at build time, and their schemas |
| `deploy/` | The rollout kit for a partner's server, see `deploy/README.md` |
| `lab/` | Real and stealth bot clients driven at a local gateway |
| `scripts/` | End-to-end, fuzz, soak and VM checks |
| `sidecar/` | Running beside nginx, Caddy, Envoy or Traefik |
| `fuzz/` | cargo-fuzz targets, run by `scripts/fuzz.sh` and CI |
| `docs/` | Media for the README |
| `tools/` | `known_link.py` (known-person links), `export/` (opening a partner's encrypted export) |

## Commands

```bash
./test.sh                                   # the fast suite: contracts, cargo test, deploy kit
cargo build --release -p veritell-proxy     # target/release/veritell
cargo clippy --workspace --all-targets
```

Slower or environment-bound:

```bash
mkdir -p certs && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout certs/key.pem -out certs/cert.pem -days 30 -subj /CN=localhost
scripts/e2e.sh                              # needs the release build and the certs above
node lab/run.mjs                            # see lab/README.md (Chrome, Firefox, optional tools)
scripts/fuzz.sh 120                         # cargo-fuzz, seconds per target
```

Checks outside `./test.sh` and `scripts/e2e.sh`; run them by hand when you change what they cover:

| Script | What it checks, and what it needs |
|---|---|
| `scripts/e2e_upstream_tls.sh` | The gateway in front of an HTTPS origin (`scripts/tls_origin.py`): certificate checks against a test CA, SNI, and the probe injected into compressed pages. Release build, curl, openssl, python3. Also run by the `e2e` workflow |
| `scripts/e2e_sni.sh` | Several sites behind one gateway: a certificate per name (`--sni-dir`) and an upstream per name (`--upstream-host`). Release build, curl, openssl, python3 |
| `scripts/clickhouse_check.sh` | The events sink against a real ClickHouse in a throwaway Docker container, and the table's TTL. Release build, Docker |
| `scripts/latency.sh [requests] [concurrency]` | The gateway's own handling time in shadow mode with no upstream; prints the latency distribution. Release build, `hey` |
| `node probe/test/behavior_run.mjs <chromium\|firefox>` | `probe/behavior.js` in a real browser driven with trusted input by Playwright; validates each summary it sends. `npm install` in `lab/` first; `CHROME_BIN` / `FIREFOX_BIN` override the browser paths |
| `node probe/test/behavior_gecko.mjs` | `probe/behavior.js` in a stock Firefox with no driver: the page sends itself synthetic events, so it shows the script loads, counts and sends on hide, not trusted input. Firefox (`FIREFOX_BIN`) |
| `sudo scripts/r3_vm_check.sh` | In a throwaway Debian VM: installs the kit behind nginx in redirect mode, sends traffic from a few clients (headless Chromium among them), and builds the weekly report. The kit in `/opt/veritell-src` and the test CA from `scripts/r1_vm_check.sh` |
| `sudo scripts/compose_vm_rehearsal.sh <old kit> <new kit>` | In a throwaway Debian VM: compose mode on a stand-in Docker Compose site, updating from an old kit to a new one, with IPv4 and IPv6 visitors. Both kits from `deploy/build.sh`, the test CA from `scripts/r1_vm_check.sh` |

## Rules

- Don't weaken, skip or delete a test to make a change pass. Changing what an
  acceptance test checks needs the lead's OK and its own commit.
- A crate's public API is used across the workspace; change it on purpose.
- The probe scripts are embedded at compile time. After changing `probe/*.js`, rebuild before running the e2e or lab tests.
- Default rules, truth tables (`crates/*/data/`) and `deploy/policy.yaml` are the open baseline. Values tuned on a site's real traffic stay with that site, not here.
- Don't cite private planning notes or copy text from them. Mentions of a phase by name ("Phase 3") are fine.
- New first-party code gets a Snyk code scan before it's committed.

## The name

The project was called Palisade until 2026-11-11. Nothing says `palisade`
any more, in code, on the wire or on hosts; don't bring the name back.
