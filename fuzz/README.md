# Fuzz targets

The parsers that read what a client or a remote server sends, beyond the
TLS, HTTP/2 and HPACK ones in `crates/veritell-fp/fuzz`. Each target builds
only on public crate APIs.

| Target | What it feeds | What an attacker controls |
|---|---|---|
| `syn_parse` | `veritell_fp::syn::parse` | the TCP SYN (IP and TCP headers, options) |
| `wba_request` | `veritell_wba::verify`, `signature_info`, `signature_base`, `parse_directory`, `TrustedAgents::from_json` | method, authority, path, query, `Signature-Input`, `Signature`, `Signature-Agent`, one more header |
| `reports` | `veritell_probe::parse_report` and `analyze`, `veritell_behavior::parse_summary` and `analyze` | the POSTed probe report and behaviour summary |
| `ua_check` | `veritell_ua::parse_user_agent`, `TruthTable::check` | User-Agent, JA4, HTTP/2 fingerprint, header names |
| `tokens` | `veritell_token::issue`, `verify`, `pow::issue_challenge`, `verify_solution`, `issued_difficulty`, `sanitize_return_to`, `challenge_page`, `veritell_privacypass::token_from_authorization` and `verify` | the session cookie, a challenge answer, `Authorization: PrivateToken` |
| `directory_keys` | `veritell_directory::parse_keys`, `parse_url`, `ttl_from_cache_control`, `address_allowed` | a key directory's response, its URL, `Cache-Control`, the address it resolves to |

## What a crash means here

Safe Rust rules out memory corruption, so "does not crash" alone would say
little. Each target also checks the properties the gateway's security rests
on, and a broken property is reported as a crash. They are listed at the
top of each target. The main ones:

- **Forgery.** A session token, challenge or Privacy Pass token that
  verifies stops verifying after any one-byte change; one minted by the
  target and then edited is refused; session tokens and challenges are not
  interchangeable; expiry and client binding hold.
- **Web Bot Auth.** In signed mode (first byte 5 to 7 mod 8) the target signs
  the request with a trusted key, so mutations reach what comes after the
  signature check. Every `Verified` must cover `@authority`, be in its
  time window, cover a `Signature-Agent` header, and stop verifying when any
  covered part of the request changes.
- **Reference implementations.** `address_allowed` against a prefix table
  written from its documentation and against the standard library's
  address classes; the proof-of-work check against a separate one;
  `Cache-Control` parsing against a second parser; the return path after a
  challenge against a WHATWG URL parser (it must keep the site's origin).
- **Round trips and agreement.** A parsed probe report serialises and parses
  back to itself; a directory URL prints back to itself; the fetcher's and
  the Web Bot Auth crate's directory parsers read the same keys.
- **Privacy.** The SYN signature never keeps the TCP timestamp clock.

Build with overflow checks on: `cargo fuzz` does this by default, and
`-O` turns them off, so long runs use `-O -a`.

## Finding the gates

```bash
fuzz/gaps.sh wba_request          # lines of crates/ no corpus input reaches
```

lists, per file, the lines the corpus never reaches. A block of unreached
lines right after a check is a gate the fuzzer cannot pass: add a seed that
passes it (in `make_seeds.py`) or a dictionary word, and run again. It
needs `rustup component add llvm-tools-preview --toolchain nightly`.

## Input layout

Inputs with several fields separate them with the byte `0xFF`; targets that
cover several parsers pick one with the first byte. See each target's
comment.

## Running

```bash
python3 -I fuzz/make_seeds.py                  # seeds/ and dicts/
cargo +nightly fuzz run reports fuzz/corpus/reports fuzz/seeds/reports -- -dict=fuzz/dicts/reports.dict
scripts/fuzz.sh 60                             # every target in the repository, 60 s each
```

Seeds are valid inputs, so a run starts past the first rejection: RFC 9421 and
Web Bot Auth test vectors, the RFC 9578 Privacy Pass token, the probe's
captured reports, the lab's synthetic behaviour sessions, real User-Agent
strings, and SYNs built in `make_seeds.py`. The session token and solved
challenge in the `tokens` seeds are made under the target's fixed test key;
`make_seeds.py` says how to make them again.
