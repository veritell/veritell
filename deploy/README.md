# Rollout kit: the gateway in front of a site, in shadow

The gateway terminates TLS on the public HTTPS port and forwards to the
site's nginx over plain HTTP on the site's own Docker network. It scores and logs every request and acts on
none (`policy.yaml`, `mode: shadow`). It adds the probe and behaviour scripts
to the site's HTML pages (`--inject-probe on`). Events go to a ClickHouse
beside it, kept 30 days, with addresses stored as daily keyed hashes
(`--ip-mode keyed`).

```
before:  internet :443 -> nginx (web)                     -> app, /api
after:   internet :443 -> gateway :8443 -> nginx :8081 (web) -> app, /api
         nginx keeps :80 (ACME and the redirect); its own :443 moves to
         127.0.0.1:8444 on the host, for checks and for rolling back.
```

## Modes

`FRONT=` in `site.conf` picks how the gateway gets in front of the site. A
missing `FRONT` means `compose`. The rest of this file is written for
`compose`; the other two are described here and differ only where said.

| Mode | For | Cutover | Rollback |
|---|---|---|---|
| `redirect` | Most partners: Linux with iptables, a server they would rather not touch | Firewall rules send 443 to the gateway. No downtime | Delete the rules. No downtime |
| `port` | No iptables, or a firewall they manage themselves | `SITE_RELEASE_CMD` (yours) moves the site off 443, then the gateway takes it. A few seconds of downtime | The gateway goes back to 127.0.0.1:9443 and `SITE_RESTORE_CMD` (yours) puts the site back |
| `compose` | A Docker Compose site with an nginx container | nginx's 443 moves, the gateway takes it. A few seconds of downtime | The reverse |

In `redirect` and `port` mode the gateway runs on the host's network
(`compose.host.yml`), so it sees the real client address and reaches the site
on the host. It connects to the site at `UPSTREAM`, over TLS or plain HTTP as
`UPSTREAM_TLS` says, and presents the certificate at `CERT_FULLCHAIN` and
`CERT_KEY`. The dashboard is on `127.0.0.1:9090`, ClickHouse on
`127.0.0.1:18123`. Neither mode needs a change in the site's repository or
server; see `client-address.md` for making the site see the visitor's address.

```
redirect, after:  internet :443 -REDIRECT-> gateway :8443 (TLS) -TLS-> 127.0.0.1:443 their server -> app
port, after:      internet :443 -> gateway :443 (TLS) -TLS or HTTP-> UPSTREAM (their server, moved) -> app
```

Redirect mode adds three firewall rules per address family (IPv4, and IPv6
when `IPV6` allows), each commented `veritell`: nat PREROUTING (443 to the
gateway), nat OUTPUT (the same for the host's own connections to its own
address, so that checks made on the host take a visitor's path), and INPUT
(accept redirected connections only, so a default deny does not drop them and
`GATEWAY_PORT` stays closed to direct use). Connections already open finish
where they began. The rules do not survive a reboot: `veritell-front.service`
puts them back at boot if the gateway is in front and answers within 60 s, and
otherwise leaves them off and logs at err (`journalctl -t veritell-watch -p err`).

States in `redirect` and `port` mode are `site` (where `compose` says
`nginx`), `gateway`, `not-installed` and `inconsistent: <why>`. `VERITELL_FRONT`
in `kit.env` (site or gateway) is what the kit intends; `front_state` compares
it with the firewall rules (redirect) or with who listens on `PUBLIC_PORT`
(port, by `ss -ltnp`).

`install.sh` checks first and changes nothing if a check fails: something
answers on `UPSTREAM` and its certificate covers `SITE_HOST`; in redirect mode
`iptables` works and `GATEWAY_PORT` is free; ports 9090 and 18123 are free.
It then warns about an `Alt-Svc: h3` header (HTTP/3 uses UDP 443 and bypasses
the redirect) and lists the names on the certificate: every name this host
serves on 443 must be among them, because the gateway presents one certificate.

`watch.sh` copies the certificate again and restarts the gateway when the
checksums of `CERT_FULLCHAIN` and `CERT_KEY` change, which covers Caddy and
anything else that renews without a certbot hook.

Steps for `redirect`:

```
mkdir -p /opt/veritell && rsync -a ~me/veritell-kit/ /opt/veritell/
cd /opt/veritell
cp site.conf.example site.conf    # FRONT=redirect, fill it in
./install.sh                      # nothing public changes
./cutover.sh                      # the rules go in; checks a marker request
./status.sh                       # front: gateway
./rollback.sh                     # the rules come out
./uninstall.sh --yes              # when the run is over
```

Steps for `port`: the same, with `FRONT=port`, `UPSTREAM` set to where
`SITE_RELEASE_CMD` puts the site (for example `127.0.0.1:8444`, plain HTTP or
TLS) and your two commands in `site.conf` (an nginx example is in
`site.conf.example`). `cutover.sh` runs `SITE_RELEASE_CMD`, waits up to 15 s for
`PUBLIC_PORT` to be free, then starts the gateway on it. If anything fails it
rolls back, which runs `SITE_RESTORE_CMD`. The commands are run as root with
`eval` and their output is logged.

`uninstall.sh --yes` rolls back if needed, removes the firewall rules, the
containers and the ClickHouse volume (the stored events too), the check and
boot units, the weekly timer and its reports, the certbot hook, the secrets, the certificate copy and the state,
and prints each. It never touches `site.conf`, the kit's files or the site.

## Compose mode

## What the site needs first

Two changes in the site's own repository, deployed the usual way before
anything here runs:

1. **nginx: a server block on 8081**, plain HTTP, never published, serving
   the same app and `/api/` as the HTTPS server, that takes the client
   address from the last `X-Forwarded-For` entry (`set_real_ip_from` the
   network, `real_ip_header X-Forwarded-For`, not recursive). Without it the
   site's API would see every visitor as the gateway.
2. **Compose: nginx's HTTPS port from a variable**,
   `"${WEB_HTTPS_PUBLISH:-443}:443"`. The cutover sets it in the site's env
   file, so a later deploy keeps nginx off the public port instead of
   fighting the gateway for it. The site's `main` must have this change:
   a deploy without it, after a cutover, would leave `web` unable to start.

## The front's state

Who holds the public port is one of these, worked out by `front_state` in
`lib.sh` from both env files and from what Docker actually publishes:

| State | Meaning |
|---|---|
| `not-installed` | No `kit.env` yet |
| `nginx` | nginx holds the port; the gateway is beside it on 127.0.0.1:9443 |
| `gateway` | The gateway holds the port; nginx is on `NGINX_LOCAL_HTTPS` |
| `inconsistent: <why>` | Anything else, for example the settings say gateway but nothing publishes the port |

```
not-installed --install.sh--> nginx --cutover.sh--> gateway
                                ^                      |
                                +-----rollback.sh------+
inconsistent --rollback.sh--> nginx
```

`status.sh` prints it. `cutover.sh` only runs from `nginx` (from `gateway` it
says so and stops); `rollback.sh` runs from `gateway` or `inconsistent` (it
is the way back) and does nothing from `nginx`. `install.sh` may be run again
in any state but `inconsistent`. The 5-minute check reports `inconsistent`
as a problem.

## Steps

On the workstation:

```
deploy/build.sh
rsync -a --delete dist/veritell-kit/ host:veritell-kit/
```

On the host, as root, the first time:

```
mkdir -p /opt/veritell && rsync -a ~me/veritell-kit/ /opt/veritell/
cd /opt/veritell
cp site.conf.example site.conf    # and fill it in
./install.sh                      # nothing public changes
./cutover.sh                      # the gateway takes the HTTPS port
./status.sh                       # front: gateway
./rollback.sh                     # nginx takes it back
```

- **install.sh** writes the secrets (`gateway.env`, `kit.env`, mode 600),
  copies the certificate for the gateway's user (uid 10001), installs the
  certbot deploy hook (`renew-hook.sh`) and the 5-minute check, builds the
  image, starts the gateway and ClickHouse, and checks that the gateway
  reaches the site.
- **cutover.sh** moves nginx's HTTPS to `NGINX_LOCAL_HTTPS`, puts the gateway
  on `PUBLIC_PORT`, and checks that a request with a fresh marker in its path
  comes back 200, appears in the event store, and that the state is now
  `gateway`. If any step fails, or that check does, its exit trap runs
  `rollback.sh`.
- **rollback.sh** does the reverse, step by step even if one fails, and
  checks that the marker does not reach the gateway and the state is `nginx`.

Each swap leaves HTTPS unanswered for a few seconds (a few seconds in practice). Port 80 is never touched.

## Updating the gateway

```
deploy/build.sh && rsync -a --delete dist/veritell-kit/ host:veritell-kit/   # workstation
sudo /opt/veritell/update.sh /home/me/veritell-kit                          # host
```

`update.sh` runs in two stages. The copy on the host (from the running kit)
checks the new binary against its checksum, keeps the running kit in
`previous/` (binary, scripts, `compose.yml`), and copies the new kit over it,
comparing files by checksum. It then runs the new kit's own `update.sh` for
the rest, so what a new kit needs before its gateway starts (a new secret, a
column) is done by the script that knows about it. That one makes the
dashboard token if it is missing, runs `migrate.sh`, keeps the running image
as `veritell:previous`, restarts the gateway, and checks that it answers
within 20 s. If Compose refuses the new `compose.yml`, or the gateway does not
answer, the whole previous kit and image are put back and the gateway is
restarted on them; the script exits 1. A gateway that refuses to start costs
those 20 s and the restart.

Secrets, `site.conf`, the certificate, the state, the ASN database (`asn/`)
and the env-file backups are never copied, kept or put back, and their owners never change. Never copy
the kit over `/opt/veritell` by hand and never `chown -R` it: a gateway that
cannot read its certificate leaves HTTPS down until the file is readable again. `veritell.previous` and `veritell.sha256.previous`, left by
earlier versions of the script, are no longer used and can be deleted.

A restart gives requests in flight one second to finish (the gateway's
graceful shutdown), then cuts them: a download that takes longer is broken.
Compose's `stop_grace_period: 10s` is a different limit: the time Docker
waits for the gateway to save its state and exit before it kills it.

## The event store's schema

`clickhouse/events.sql` creates the table on an empty data folder.
`clickhouse/migrate.sql` adds any column the gateway writes that the table
lacks; both are generated from the gateway's DDL by `make_events_sql.py`.
`migrate.sh` runs it (and `update.sh` runs `migrate.sh` before the gateway
restarts), then compares the table with what the gateway writes. Columns are
only ever added: one the gateway no longer writes is listed and left, and a
changed type is not applied; both need a hand-written step. Rows the store
refuses are dropped by the gateway, which logs it; the 5-minute check
reports such lines.

## IPv6 visitors

In compose mode Docker publishes the gateway's ports. For IPv4 it forwards
each connection with the visitor's address. For IPv6 it can do the same only
when the container has an IPv6 address; without one, Docker's `docker-proxy`
accepts the connection on the host and opens a new one to the container, so
every IPv6 visitor reaches the gateway from the Docker bridge's address. Then
IPv6 visitors share one address in the events, the rules that count per
address and the visits, and get no ASN, no `net_hosting` and no crawler
check.

So the gateway has a network of its own, `front`, with IPv6 from Docker's
private pool (Docker 27 or later), and listens on `[::]:8443`, which takes
both families. The site's network is not changed. `IPV6` in `site.conf`:
`auto` (the default) does this when the host has IPv6, `on` always, `off`
never (IPv4-only network, `0.0.0.0:8443`). `kit.env` holds the result
(`VERITELL_FRONT_IPV6`, `VERITELL_INNER_LISTEN`), and `status.sh` shows it.
Docker turns on IPv6 forwarding on the host when it creates the network; a
host that takes its own IPv6 route from router advertisements, rather than a
static one, should set `accept_ra=2` on that interface first, or it can lose
that route.

Changing `IPV6` later, once `front` exists, needs the network made again:
stop the gateway, `docker network rm veritell_front`, run `update.sh`.

## Trusted Web Bot Auth agents

A request signed with Web Bot Auth (HTTP Message Signatures, Ed25519) by an
agent the operator trusts is classed `signed_agent`, whatever its other
detections. None is trusted by default. To trust one, put its public keys in
`agents/agents.json` in the kit's folder and run `update.sh` (the same short
restart as an update):

```json
{"agents": [{"name": "example-agent", "keys": [{"kty": "OKP", "crv": "Ed25519", "x": "<public key, base64url>"}]}]}
```

An agent can instead give `signature_agent`, the URL of its key directory,
and no `keys`: the gateway then fetches the keys from there and keeps them
current. Only public keys go in the file; it is mounted read-only. The kit's
`kit.env` has `VERITELL_WBA_AGENTS` set to its path in the gateway when the
file exists and is not empty, and empty otherwise. A file the gateway
refuses stops it from starting, so `update.sh` puts the previous kit back:
check the file first. `status.sh` says whether agents are trusted. Format
and limits: the top of `crates/veritell-proxy/src/main.rs` and
`crates/veritell-proxy/src/directories.rs`.

What a signature must cover:

- **Every request:** `@authority`, as Web Bot Auth requires.
- **A write** (any method but GET, HEAD and OPTIONS) counts as the agent's
  only when the signature also binds the method and the target: `@method`,
  the path (`@path`, `@request-target` or `@target-uri`) and, when the
  request has a query, the query (`@query`, or `@request-target` or
  `@target-uri`, which carry it). Otherwise the request is treated as
  unsigned and noted `wba_write_unbound` (0 points).
- **The body is not bound.** Someone who captures a bound write before the
  agent's own request arrives could send it once with another body. Each
  signature is accepted once: the gateway remembers used ones until they
  expire, in `state/wba-replays.state` across restarts (one gateway only; see
  "What it does not do").

## The ASN database

The gateway looks up which network (autonomous system) each visitor's
address belongs to: `asn` and `net_class` in the events and in the policy's
expressions, and the `net_hosting` detection (a cloud or hosting provider,
penalty 20). Without a database every event has `asn` 0 and `net_class`
`unknown`, and `net_hosting` never fires.

`asn.sh` downloads [iptoasn.com](https://iptoasn.com)'s `ip2asn-combined.tsv.gz`
(public domain, PDDL 1.0; about 11 MB, some 55 MB unpacked; about 720 000
rows, 580 000 of them routed ranges, the count `status.sh` and the gateway
show) into `asn/ip2asn.tsv`, which the compose files mount read-only;
`kit.env`'s `VERITELL_ASN_DB` holds its path in the container, or is empty
for none. It refuses a file that is not a gzip, has a row the gateway would
not read, or has fewer than 100 000 rows, and keeps the one in place.

- `install.sh` runs it before the gateway first starts. A failed download
  does not stop the install: the gateway starts without one.
- `update.sh` keeps `asn/` and downloads it only when there is none (an
  update from a kit without it).
- `veritell-asn.timer` runs it on Sundays around 04:00 UTC. When the file
  changed and the gateway runs, it restarts the gateway (the same short cut
  as an update) and checks that it answers within 20 s; if not, the previous
  file is put back and the gateway restarted on it.
- `ASN_DB=off` in `site.conf` runs the gateway without one; `ASN_DB_URL`
  points at another copy of the same file.

```
sudo /opt/veritell/asn.sh            # now, by hand
journalctl -u veritell-asn           # the weekly runs
./status.sh                          # ranges and when it was downloaded
```

## Day to day

```
./status.sh                                       # who holds the port, does it answer, the dashboard
journalctl -t veritell-watch -p err               # problems found by the check
docker logs -f veritell-gateway                   # start-up and problems only (--log-requests off);
                                                  # requests are in ClickHouse: report.sh, export.sh
```

Known-person links are made with `known_link.py`, which the kit includes.
Run it on the host: `VERITELL_KNOWN_KEY=... python3 /opt/veritell/known_link.py p01-phone`,
the key from `gateway.env`.

## Other sites on this host

One gateway can sit in front of several sites on the same server. Each site
gets its own certificate, chosen by the name the browser asks for (SNI), and
its own upstream:

```
# site.conf
EXTRA_CERT_NAMES="example.org"
HOST_UPSTREAMS="example.org=other-site:80,www.example.org=other-site:80"
```

`EXTRA_CERT_NAMES` lists Let's Encrypt names: the kit copies
`LETSENCRYPT_LIVE/<name>/` (default `/etc/letsencrypt/live`) into
`certs/sni/<name>/`, and the renewal hook copies them again. The gateway
serves each certificate for the DNS names it lists; every other name, and a
client that sends no name, keeps the site's own certificate, so the existing
site is unchanged. `HOST_UPSTREAMS` sends requests for a name to a plain-HTTP
upstream the gateway can reach (in compose mode, a container on
`SITE_NETWORK`); other names go to the site as before. Run `install.sh`
again after changing either, then restart the gateway. Without them the
gateway runs exactly as before (`--sni-dir` and `--upstream-host` empty).

## Weekly report

`report.sh` writes a page for the site's owner: who visited (people, crawlers,
automated tools), what the policy would have done, which rules fired, and a
false-positive alarm that lists any known person it would have challenged or
blocked. `veritell-report.timer` runs it Mondays at 06:00 UTC (a missed run is
made at the next boot); by hand, as root:

```
sudo /opt/veritell/report.sh [days]               # default 7, 1 to 31
```

The files are `/opt/veritell/reports/report-<date>.html` (to read or print)
and `.json` (the same numbers), the newest 8 of each, readable by root only.
No visitor address is in them, and nothing is sent anywhere. To read one on a
laptop, pull it through SSH (the folder is root-only):

```
ssh <host> 'sudo cat /opt/veritell/reports/report-2026-11-09.html' > report.html
```

or `sudo cp` it to your home folder on the host and `scp` it. Then open it in a
browser. If a visit looks wrong, quote its visit id. The host's `python3`
(3.9 or later) is used, else the `python:3.12-slim` image. `update.sh` leaves
`reports/` alone.

## Sending us your data

To review your traffic and set the gateway's thresholds we need your events.
There are two ways; the first is the default.

1. **Export (default).** You run one command; it writes one encrypted file
   that only we can open, and you send it however you like (email, a file
   share). We get no account on your server.
2. **SSH (if you prefer).** You give us a login with sudo for the kit only,
   and we read the events from your host ourselves.

```
sudo /opt/veritell/export.sh [days] [--no-paths]     # days: 1 to 30, default 30
```

It prints two files in `/opt/veritell/exports/`:

- `export-<date>.cms`: the encrypted data. **Send this one.**
- `export-<date>.txt`: plain text, to read before you send: the number of days
  and events, whether paths are included, the list of columns, the SHA-256 of
  the `.cms`, and a plain-English description of what the columns hold
  (time, request line, browser and TLS fingerprints, what the gateway decided
  and why, known-person labels, behaviour counts; no keystroke content). Visitor
  addresses are keyed hashes whose key changes daily and is not stored. **Keep
  this one.**

You cannot open the `.cms` yourself, and neither can anyone who intercepts it:
it is encrypted to our certificate (`recipient.pem` in the kit; `build.sh` refuses to build a kit without it unless `VERITELL_KIT_NO_EXPORT=1` is set) and only we
hold the private key. Nothing unencrypted is written to disk. If your paths
carry personal data (`/users/<name>`), add `--no-paths`: every path is then
replaced by an empty string. The newest 3 exports are kept; `update.sh` leaves
`exports/` alone and `uninstall.sh` removes it.

## The dashboard

The gateway serves its dashboard on port 9090 in the container, published on
the host's `127.0.0.1:9090` only. `VERITELL_ADMIN_PUBLISH` in `kit.env`
changes the address (keep it on loopback) but not the port: the gateway
checks `Host` against port 9090, so another port gets 421. From the workstation, through SSH:

```
ssh -L 9090:127.0.0.1:9090 <host>                 # leave it open
sudo grep ^VERITELL_ADMIN_TOKEN= /opt/veritell/gateway.env   # on the host
```

Then open `http://localhost:9090` and give the token as the password (any
user name). Keep the local port 9090: the gateway checks the port in `Host`,
and another one gets 421. `install.sh` and `update.sh` write the token into `gateway.env`
when it is missing; delete the line and run `update.sh` again to change it.
Anything else that reaches the port (the host's users, the site's
containers) needs the token too, and a `Host` other than `localhost`,
`127.0.0.1` or `[::1]` is refused.

The page shows the gateway's memory: the last 50,000 events of the past 30
days. They are saved in `state/events.state` once a minute and on shutdown,
so a restart or update keeps them; a crash loses up to the last minute.
Older events are in ClickHouse (query them directly).

## Tests

`deploy/test_front.sh` tests the redirect and port modes' `front_state`,
`rules_apply` and `rules_remove` with stub `iptables`, `ss` and `docker`.
`deploy/test_report.py` tests `report.py` against `fixtures/report_events.jsonl`
(`python3 deploy/test_report.py`); `report.sh` itself is checked in a VM.
`deploy/test_export.sh` tests `export.sh` and the key tools in `tools/export/` with a stub `docker` and a real `openssl` (3.0 or later).
`deploy/test_asn.sh` tests `asn.sh` and the ASN functions in `lib.sh`
(download, refusal, unchanged, restart and going back) with `file:` URLs and
a stub `docker` and `curl`.
`deploy/test_lib.sh` tests `set_kv`, `ensure_admin_token` and every case of
`front_state` with a stub `docker`; it runs anywhere. The scripts as a whole were rehearsed on a
workstation's Docker with a stand-in site: install, cutover,
rollback, a site deploy and a certificate renewal under cutover, a good and
a broken update.

The redirect and port modes are checked end to end by
`scripts/r1_vm_check.sh`, as root in a throwaway Debian 12 VM, with ufw set to
deny incoming connections by default. It covers nginx, Caddy, Apache, nginx in
a Docker container, and nginx in port mode. For each it runs install, cutover,
a request from outside through the gateway, the probe in a compressed page,
the visitor's address in the site's log, a Docker restart, a renewed
certificate picked up by `watch.sh`, rollback and uninstall. A load loop counts
failed requests during the cutover and the rollback.

## What it does not do

- **The dashboard is not on the internet.** Only through an SSH tunnel, and
  only the gateway's memory (above).
- **Alerts go to the journal only** (`watch.sh` every 5
  minutes). It reports the gateway down or crashed, ClickHouse unhealthy,
  dropped event batches, the front `inconsistent`, HTTPS or the site behind it
  not answering, the certificate under 14 days, the disk over 90%. It
  changes nothing itself; nothing restarts or rolls back on its own except
  Docker's restart policy.
- **No way to revoke one known-person mark.** Marks are signed with
  `VERITELL_KNOWN_KEY`; changing the key (and restarting) revokes them all.
- **Injection and a Content-Security-Policy.** The scripts are same-origin,
  which `script-src 'self'` allows; a policy based on nonces or hashes would
  block them silently. Check the site's policy before the cutover.
- **One instance.** State files (`state/`) are for this one gateway.
