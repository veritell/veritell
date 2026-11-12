# Sidecar mode

Veritell can decide for a proxy you already run. The proxy asks one
endpoint before it serves a request and acts on the answer.

What is lost compared with running Veritell in front: the TLS and HTTP/2
fingerprints. The proxy terminates the client's connection, so Veritell sees
the proxy's handshake, not the client's, and leaves the network-fingerprint
checks out. Everything based on headers, identity and population still
applies. The probe and the behaviour script apply only if the site's pages
load them: in front, the gateway adds them to the pages itself
(`--inject-probe on`), but here it never sees the pages. Add
`<script src="/__veritell/probe.js" async></script>` and
`<script src="/__veritell/behavior.js" async></script>` to the pages, with
`/__veritell/` routed to the gateway (below).

## The endpoint (FIXED BY THE PROJECT LEAD)

Start the gateway with a plain-HTTP listener for the proxy, on loopback or a
private network, and name the proxy as a trusted peer:

```
veritell --cert cert.pem --key key.pem --policy policy.yaml \
  --sidecar-listen 127.0.0.1:9191 --trusted-proxy 127.0.0.1
```

The proxy sends, for each client request, a request to

```
GET http://127.0.0.1:9191/__veritell/authz
```

carrying the client's own request headers unchanged (`User-Agent`, `Cookie`,
`Accept-Language`, `Sec-CH-UA*`, `Sec-Fetch-*`, `Signature`,
`Signature-Input`, `Signature-Agent`) plus:

| Header | Meaning | Required |
|---|---|---|
| `X-Original-URI` or `X-Forwarded-Uri` | The client's path and query | yes |
| `X-Original-Method` or `X-Forwarded-Method` | The client's method | no, default `GET` |
| `X-Original-Host` or `X-Forwarded-Host` | The client's `Host` | no, default the `Host` header |
| `X-Forwarded-For` | The client's address; the last entry is used | yes, when the proxy is a trusted peer |

A proxy may send either family, or both. When both carry a value and the
values differ (a client adding `X-Original-*` behind a proxy that sets
`X-Forwarded-*`, say), the call is refused with 400: the endpoint does not
guess which one the proxy wrote.

A proxy that cannot add headers but can add a path prefix (Envoy's HTTP
`ext_authz`) may instead call `/__veritell/authz/<original path and query>`
with the client's method.

Answers:

| Status | Meaning | The proxy should |
|---|---|---|
| 200 | Pass | Serve the request. The answer carries `X-Veritell-Score`, `X-Veritell-Class`, `X-Veritell-Detections` and `X-Veritell-Action`; copy them to the upstream request if the application wants them |
| 403 | Block, decoy, charge, or a challenge is required | Refuse. With `X-Veritell-Action: challenge(...)`, send the client to `/__veritell/challenge?return_to=<uri>&c=<X-Veritell-Challenge>` if that path is routed to the gateway's main listener; otherwise answer 403. `X-Veritell-Challenge` is a signed challenge at the client's level: with it the page needs no second assessment (without `c` it scores the request again). With `X-Veritell-Action: charge`, the answer also carries the offer in `Veritell-Offer`; pass it to the client with a 402 if the proxy can, otherwise answer 403 |
| 429 | Throttled or tarpitted | Answer 429 (the nginx example cannot: `auth_request` turns any status but 2xx, 401 and 403 into 500, so there a throttled client sees 500; see its comments) |
| 400 | No original URI was given, or the `X-Original-*` and `X-Forwarded-*` values disagree | Treat as a misconfiguration and refuse |

A charge is answered with 403, not 402, because nginx's `auth_request`
turns any status but 2xx, 401 and 403 into a 500.

Rules the endpoint keeps:

- `X-Forwarded-For` and the `X-Original-*` / `X-Forwarded-*` headers are
  believed only when the peer is listed in `--trusted-proxy`. From any other
  peer the request is refused with 403: an untrusted client must not be
  able to ask what score an address would get, or to borrow one.
- The endpoint is answered only on the `--sidecar-listen` listener. On the
  main listener the path is an ordinary path.
- Client-supplied `X-Veritell-*` headers mean nothing.

The proxy must also route `/__veritell/` on the public site to the gateway's
main listener, so that the probe, the behaviour script and the challenge
page work.

## Example configurations

`nginx.conf`, `traefik.yml`, `Caddyfile` and `envoy.yaml` in this directory
each protect one upstream (`127.0.0.1:8080`) on port 8000. `envoy.yaml` needs
Envoy 1.27 or later (its `header_mutation` filter). `check.sh` starts
each proxy that is installed against a running gateway and checks the four
answers above; a proxy that is not installed is reported as not run.
