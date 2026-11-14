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

## Rules

- Files in `.acceptance.sha256` are fixed contracts. Don't edit them.
- Public APIs marked "PUBLIC API IS FIXED" in a crate don't change without the lead.
- The probe scripts are embedded at compile time. After changing `probe/*.js`, rebuild before running the e2e or lab tests.
- Default rules, truth tables (`crates/*/data/`) and `deploy/policy.yaml` are the open baseline. Values tuned on a site's real traffic stay with that site, not here.
- Don't cite private planning notes or copy text from them. Mentions of a phase by name ("Phase 3") are fine.
- New first-party code gets a Snyk code scan before it's committed.

## The name

The project was called Palisade until 2026-11-11. Nothing says `palisade`
any more, in code, on the wire or on hosts; don't bring the name back.
