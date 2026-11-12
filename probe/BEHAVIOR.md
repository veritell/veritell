# Behaviour summary schema, version 1

FIXED BY THE PROJECT LEAD. The Rust side of this contract is
`crates/veritell-behavior/src/types.rs`. `probe/validate_behavior.mjs` checks
a summary against it.

`probe/behavior.js` watches how the page is used and sends a handful of
counts. It never sends, stores or logs a coordinate, a key value, a key code,
text, an element name or a URL. It makes no judgement: the server does that.

## How the script is served and configured

The server sends `behavior.js` with the literal token
`"__VERITELL_BEHAVIOR__"` (including the double quotes) replaced by

```json
{ "nonce": "…", "endpoint": "/__veritell/behavior" }
```

The token appears exactly once. When it has not been replaced (the value is
still a string) the script does nothing and adds no listener.

## When a summary is sent

Each summary is cumulative: it covers everything since the script started.

| `trigger` | When |
|---|---|
| `submit` | A `submit` event reaches `document` (capture phase). Sent before the navigation. |
| `hide` | `visibilitychange` to hidden, or `pagehide` |
| `idle` | 30 seconds after the script started, once, only if nothing was sent yet |

At most 3 summaries per page load. After the third, or after `pagehide`, every
listener and timer the script added is removed. A page with no interaction at
all still sends its summary on `hide`: every count is zero, and that is the
marker that the script ran and saw nothing.

Sending: `navigator.sendBeacon(endpoint, new Blob([json], { type: "application/json" }))`;
if `sendBeacon` is missing or returns false, `fetch` with `method: "POST"`,
`keepalive: true`, `credentials: "same-origin"`. Failures are ignored.

The script is at most 10,240 bytes, declares no global, and all listeners are
passive and on `document` or `window`.

## Summary

Every field is required. Every number is a non-negative integer. Unknown
fields are refused by the server. The body is at most 1024 bytes.

| Field | Max | Meaning |
|---|---|---|
| `v` | 1 | Always 1 |
| `nonce` | 256 bytes | `config.nonce` |
| `trigger` | | `"submit"`, `"hide"` or `"idle"` |
| `dur_ms` | 86,400,000 | Milliseconds since the script started |
| `hidden_ms` | 86,400,000 | Of those, milliseconds the page was hidden |
| `moves` | 1,000,000 | `pointermove` events with `pointerType` `"mouse"` |
| `strokes` | 1,000,000 | Strokes, defined below |
| `straight` | ≤ `strokes` | Strokes that are straight |
| `steady` | ≤ `strokes` | Strokes at constant speed |
| `clicks` | 1,000,000 | Mouse clicks: `click` events with no `touchstart` in the previous 700 ms, with `pointerType` `"mouse"` where `click` is a `PointerEvent`, and with `detail >= 1`. The touch check applies in every browser: Safari on iOS reports a tap as `pointerType` `"mouse"` (seen in a recorded session, 2026-11-10) |
| `sized` | ≤ `clicks` | Mouse clicks whose target's bounding box is at least 24 by 24 CSS pixels |
| `centered` | ≤ `sized` | Of those, clicks within 1 pixel of the box centre on both axes |
| `teleport` | ≤ `clicks` | Mouse clicks where the pointer jumped, defined below |
| `touches` | 1,000,000 | `touchstart` events |
| `keys` | 1,000,000 | `keydown` events, not counting repeats (`event.repeat`) |
| `key_gap_cv` | 100,000 or null | Coefficient of variation, times 1000, of the gaps between consecutive `keydown` times, over gaps under 2000 ms. Null with fewer than 5 such gaps |
| `pastes` | 1,000,000 | `paste` events |
| `scrolls` | 1,000,000 | Scroll bursts: `scroll` events more than 500 ms after the previous one |
| `submits` | 1,000,000 | `submit` events |
| `untrusted` | 1,000,000 | Events among all of the above whose `isTrusted` is false. They are counted here and also in their own field |
| `actions` | 1,000,000 | Actions, defined below |
| `gap_cv` | 100,000 or null | Coefficient of variation, times 1000, of the gaps between consecutive action times. Null with fewer than 3 gaps |
| `gap_med_ms` | 86,400,000 or null | Median of those gaps in milliseconds. Null with fewer than 3 gaps |

Counts stop at their maximum. Coefficient of variation is the population
standard deviation divided by the mean, times 1000, rounded, capped at
100,000; it is 0 when the mean is 0.

### Stroke

A stroke is a run of consecutive mouse `pointermove` events in which each
event follows the previous by at most 120 ms. A gap over 120 ms, a click or a
send ends the run. The run counts as a stroke only if it has at least 6
events and its end is at least 40 pixels from its start.

- **straight**: the summed length of its segments is at most 1.002 times the
  distance from its start to its end.
- **steady**: over its segments with a time difference above zero, the
  coefficient of variation of speed (pixels per millisecond) is at most 0.05.
  A stroke with fewer than 4 such segments is not steady.

Only running sums are kept per stroke. Positions are discarded when the
stroke ends.

### Teleport

A mouse click is a teleport when at most one mouse `pointermove` was seen in
the 500 ms before it and its position is more than 3 pixels from the last
pointer position known before those 500 ms, or no position was known.
A person who clicks twice without moving does not teleport: the position is
the same.

### Action

An action is a mouse click, a `touchstart`, the first `keydown` after at
least 500 ms without one, or a scroll burst. The time of each action is
kept (at most the most recent 64) to compute `gap_cv` and `gap_med_ms`.

## Example

```json
{"v":1,"nonce":"abc","trigger":"submit","dur_ms":18250,"hidden_ms":0,
 "moves":412,"strokes":9,"straight":0,"steady":0,
 "clicks":3,"sized":2,"centered":0,"teleport":0,"touches":0,
 "keys":24,"key_gap_cv":612,"pastes":0,"scrolls":2,"submits":1,"untrusted":0,
 "actions":8,"gap_cv":840,"gap_med_ms":1450}
```
