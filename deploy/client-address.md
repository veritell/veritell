# The visitor's address behind the gateway

In `redirect` and `port` modes the gateway connects to your web server from the
same machine. Your server sees every request coming from `127.0.0.1` (or
`::1`) unless you tell it to trust the gateway's header. That matters for:

- your access logs (every line shows `127.0.0.1`)
- rate limits by address (`limit_req`, fail2ban, the app's own limits): all
  visitors would share one bucket
- anything your app does with the address (sign-in records, spam checks)

The gateway runs with `--forwarded-for replace`. Every request it passes on
carries exactly one address in `X-Forwarded-For` and `X-Real-IP`: the one it
saw. Anything a client wrote in those headers, or in `Forwarded`, is dropped.
So your server only has to trust these headers when the request comes from
loopback. It doesn't matter whether it reads the header from the left or the
right.

Change it **before** `cutover.sh`. It does nothing until requests come from
the gateway, and before then nobody connects from loopback with those
headers.

## nginx

In the `http { }` block, for example in `/etc/nginx/conf.d/veritell-realip.conf`:

```nginx
set_real_ip_from 127.0.0.1;
set_real_ip_from ::1;
real_ip_header   X-Forwarded-For;
```

Then `nginx -t && systemctl reload nginx`. `$remote_addr`, the logs and
`limit_req` all use the visitor's address from then on. If nginx proxies to an
app, the usual `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`
and `proxy_set_header X-Real-IP $remote_addr;` keep working.

## Caddy

In the global options block at the top of the Caddyfile:

```caddyfile
{
	servers {
		trusted_proxies static 127.0.0.1/32 ::1/128
	}
}
```

Then `systemctl reload caddy`. `reverse_proxy` passes the visitor's address
on to the app, and `{client_ip}` and the logs' `client_ip` show it.

**This needs a recent Caddy.** Caddy 2.6.2, the version Debian 12 ships,
rejects `trusted_proxies` and won't start. With it, the site and the app see
every visitor as `127.0.0.1`. Install Caddy from its own Debian repository
first (tested with 2.11.9).

## Apache

```
a2enmod remoteip
```

Then in `/etc/apache2/conf-available/veritell-remoteip.conf`, enabled with
`a2enconf veritell-remoteip`:

```apache
RemoteIPHeader X-Forwarded-For
RemoteIPInternalProxy 127.0.0.1 ::1
```

For the logs, use `%a` rather than `%h` in `LogFormat`. Debian's default
`combined` format uses `%h`. Then `apachectl configtest && systemctl reload apache2`.

## Traefik

On the entry point that serves 443:

```yaml
entryPoints:
  websecure:
    address: ":443"
    forwardedHeaders:
      trustedIPs: ["127.0.0.1/32", "::1/128"]
```

## A web server in a Docker container

The gateway reaches the container through Docker's published port. Depending
on Docker's settings, the container sees either the address of the Docker
network's gateway (for example `172.17.0.1` or `172.18.0.1`) or `127.0.0.1`.
Trust both. To find the network's gateway:

```bash
docker network inspect <network> -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}'
```

Then use that address in the settings above (`set_real_ip_from 172.18.0.1;` and so on).

## Apps behind your server

Most apps already trust a proxy on loopback or a private address, so they pick
the visitor's address up from your server once the server itself trusts the
gateway. Examples:

- Rails apps (Mastodon, Discourse)
- Forgejo and Gitea (`REVERSE_PROXY_TRUSTED_PROXIES`, default `127.0.0.0/8,::1/128`)
- Django with a proxy-headers middleware
- Express with `trust proxy` set to `loopback`

Check yours if it does its own rate limiting.

## How to check

After the cutover, load a page from a phone on mobile data. Then look at your
server's access log: the last line should show the phone's address, not
`127.0.0.1`.

## Port mode: example release and restore commands

In `port` mode your server answers on a local port (`UPSTREAM`) all the time,
next to 443. The gateway reaches it there before the cutover too, which is how
`install.sh` checks the path before anything public changes. `cutover.sh` runs
`SITE_RELEASE_CMD` to make your server let go of 443, and `rollback.sh` runs
`SITE_RESTORE_CMD` to take it back. With nginx, one way is a `listen` include
that a symlink points to:

```nginx
# in the HTTPS server block, instead of the listen lines for 443
listen 127.0.0.1:8444 ssl;
include /etc/nginx/veritell-listen.conf;
```

```
/etc/nginx/veritell-listen-public.conf:   listen 443 ssl; listen [::]:443 ssl;
/etc/nginx/veritell-listen-none.conf:     (empty)
```

```bash
ln -sfn /etc/nginx/veritell-listen-public.conf /etc/nginx/veritell-listen.conf   # as it is today
```

```bash
SITE_RELEASE_CMD="ln -sfn /etc/nginx/veritell-listen-none.conf /etc/nginx/veritell-listen.conf && nginx -t && systemctl reload nginx"
SITE_RESTORE_CMD="ln -sfn /etc/nginx/veritell-listen-public.conf /etc/nginx/veritell-listen.conf && nginx -t && systemctl reload nginx"
```

Set `UPSTREAM=127.0.0.1:8444` and `UPSTREAM_TLS=on`. nginx keeps its
certificate and the rest of its configuration.
