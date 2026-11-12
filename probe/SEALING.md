# Probe builds and sealed reports

FIXED BY THE PROJECT LEAD. The Rust side is `crates/veritell-probe-build`.

`probe.js` is both a working script and the template that the gateway turns
into per-build scripts. It must keep working unbuilt (the Phase 1 harness and
`validate.mjs` use it that way) and must build cleanly.

## Template rules

The builder works on text, not on a parse tree, so the template follows
these rules:

1. **Renamed identifiers.** Any identifier written with the prefix `$$`
   (for example `$$collect`, `$$tam`) is replaced everywhere by a random name
   per build. `$$` followed by `[A-Za-z0-9_]+` is a valid JavaScript
   identifier, so the template runs as it is. Use the prefix for the script's
   own variables and functions: locals, helpers, parameters. Never use it for
   property names that are part of the report, for browser APIs, or inside
   string literals that must keep their meaning. An identifier is renamed
   wherever its text occurs, including inside strings and regular
   expressions, so code that inspects the collector's own source (for
   example a check that the source starts with `function <name>`) must be
   written so that it still holds after renaming.
2. **Shuffle regions.** Lines between a line that is exactly `/*@shuffle*/`
   and a line that is exactly `/*@end*/` are reordered as whole lines. Every
   line in a region must be complete on its own and independent of the
   others' order: one statement per line, or one array or object entry per
   line with a trailing comma. Regions do not nest and are not empty.
3. **Comments.** Full-line `//` comments and block comments that begin at the
   start of a line are removed. Do not rely on a comment for behaviour.
   Do not start a line of code with `/*`.
4. **Whitespace.** Every line is trimmed and blank lines are dropped. Do not
   use template literals or any construct where leading whitespace or a line
   break carries meaning. Every statement ends with a semicolon.
5. **Tokens.** `"__VERITELL_CONFIG__"` and `"__VERITELL_BUILD__"` each occur
   exactly once, each as the whole right-hand side of a `var` declaration.

## Build configuration

The builder replaces `"__VERITELL_BUILD__"` with:

```json
{ "id": "<build id>", "k": "<base64, 32 bytes>", "map": { "<v1 key>": "<name>", "...": "..." } }
```

While the token is still a string (the template run unbuilt), the script
sends the plain version 1 report exactly as in Phase 1.

## Sealing (when the build configuration is an object)

1. Build the version 1 report as before, limits applied.
2. Replace every object key, at every depth, by `map[key]`. Arrays are
   walked; values are unchanged. Every key of a valid report is in the map.
   If a key is not, drop that entry.
3. Encrypt with WebCrypto:
   - key bytes = SHA-256(`k` decoded (32 bytes) followed by the nonce as UTF-8)
   - AES-GCM, 256-bit key, 12 random bytes of IV from `crypto.getRandomValues`,
     additional data = the build id as UTF-8, 128-bit tag
   - plaintext = the mapped report as UTF-8 JSON
4. POST, with the same headers as before:

```json
{ "b": "<build id>", "n": "<nonce>", "d": "<standard base64 of IV || ciphertext || tag>" }
```

   WebCrypto's AES-GCM output is already ciphertext followed by the tag.
5. If `crypto.subtle` is unavailable or any step fails, send nothing and
   dispatch `veritell:done` with `ok: false`. Never fall back to a plain
   report from a built script.

The whole body must stay under 65536 bytes.
