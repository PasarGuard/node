# PasarGuard-Node
<p align="center">
    <a href="#">
        <img src="https://img.shields.io/github/actions/workflow/status/PasarGuard/node/docker-build.yml?style=flat-square" />
    </a>
    <a href="https://hub.docker.com/r/pasarguard/node" target="_blank">
        <img src="https://img.shields.io/docker/pulls/pasarguard/node?style=flat-square&logo=docker" />
    </a>
    <a href="#">
        <img src="https://img.shields.io/github/license/PasarGuard/node?style=flat-square" />
    </a>
    <a href="#">
        <img src="https://img.shields.io/github/stars/PasarGuard/node?style=social" />
    </a>
</p>

# Documentation
You can find a full guide in docs https://docs.pasarguard.org/en/node/

# One-Click Installation (Recommended)
The easiest way to install PasarGuard Node is using our automated installation script:

```bash
sudo bash -c "$(curl -sL https://github.com/PasarGuard/scripts/raw/main/pg-node.sh)" @ install
```

# MTProto backend
Besides Xray and WireGuard, the node can serve Telegram MTProto proxy users. The panel picks the backend per core, and a node runs one backend at a time.

The MTProto backend runs [telemt](https://github.com/telemt/telemt) as a separate process:
- The node image ships telemt 3.5.14 at `/usr/local/bin/telemt` (amd64 and arm64). The node refuses telemt older than 3.5.14.
- Set `TELEMT_EXECUTABLE_PATH` to use another binary.
- Outside Docker, `make install_telemt` installs the pinned release after checking it against the SHA256 pinned in the `Makefile`.
- telemt needs outbound access to Telegram. On start it checks the Telegram data centers, which can take up to a minute.
- Start can take up to 90 s while telemt probes Telegram, and the panel's retry attaches to the backend that is starting or running.
- Above 4096 users with stats or configured users, telemt stops its per-user series and the node bills from telemt's API totals, reported as downlink (no uplink and downlink split).
- telemt refuses a config file above 8 MiB, which is about 196k users on one node without WEB mode (fewer with WEB, see below).

## WEB mode
WEB mode carries MTProxy over real HTTPS (long polling or WebSocket) to your own domain on port 443. Links look like `tg://webproxy?server=proxy.example.com&secret=dd...` and have no port.
- Clients: Telegram Desktop's `WEB` proxy type, and Telegram iOS with the `https` carrier only. Android is not covered by telemt's docs and is untested.
- Secrets are `plain` or `dd`. Fake TLS (`ee`) is not used by WEB.
- telemt does not terminate TLS. A front (Caddy, nginx or HAProxy) holds the certificate on 443 and forwards plain HTTP/1.1 to telemt's WEB listener on a private address, with exactly one `X-Forwarded-For` address. pg-node runs the node with `network_mode: host`, so a front on the same host reaches `127.0.0.1:<port>`.
- telemt's own guide is [`docs/WEB/WEB_PROXY.en.md`](https://github.com/telemt/telemt/blob/3.5.14/docs/WEB/WEB_PROXY.en.md).

```text
Telegram client --HTTPS :443--> front (TLS) --HTTP/1.1--> 127.0.0.1:18080 (telemt WEB listener) --> Telegram
```

### Core config
What the node accepts in the MTProto core JSON:
- A `server.listeners[]` entry with `"transport": "web"`:
  - `ip` is a loopback or private address (127/8, ::1, 10/8, 172.16/12, 192.168/16, fc00::/7). `0.0.0.0`, `::` and public addresses are refused.
  - `port` is set, and differs from `server.port` and from every native listener's port.
  - `web_trusted_proxy_cidrs` is required: the networks your front connects from, for example `["127.0.0.1/32"]`. telemt refuses a WEB listener with an empty list or a `/0` network.
  - telemt's other WEB listener keys pass through, for example `web_client_ip_source`.
- A `web` section with `"enabled": true` and at least one `vhosts[]` entry:
  - `host`: the public domain. `base_path` is optional: empty, or up to 128 ASCII bytes of `/`-separated segments that each start with a letter or digit and hold only letters, digits, `-` and `_`, with no leading or trailing `/` (for example `tg` or `dobry-cola/super_app`, not `/tg`).
  - `public_addr`: the server's public IP on port 443, for example `203.0.113.10:443`.
  - `decoy`: `{"mode": "http_upstream", "upstream": "http://<loopback or private IP>[:port]"}`. The upstream is a bare http origin: no `https`, path, query, fragment or credentials. Host names, `static_directory`, and a loopback upstream on the node's telemt API or metrics port are refused. The decoy is the site that ordinary visitors and probes see.
  - `user_profile` (PasarGuard only, optional): `secret_mode` is `"dd"` (default) or `"plain"`, plus optional `max_sessions`, `max_streams` and `max_streams_per_session`. It applies to every user on that vhost. telemt refuses at Start a limit of 0 and limits above its global WEB limits: `max_sessions` above `web.limits.max_sessions_global` (default 128), `max_streams` above `web.limits.max_streams_global` (default 4096), `max_streams_per_session` above `web.limits.max_streams_per_session` (default 128) or above `max_streams`. It also refuses more vhosts than `web.limits.max_vhosts` (default 8).
- Refused: `web.vhosts[].profiles`, `web.debug`, `web.limits.max_profiles` and `include` anywhere.

The node writes one telemt WEB profile per user per vhost and sets `web.limits.max_profiles` to 65536. With WEB on, every user change rewrites telemt's config and hot reloads it: open sessions of unchanged users stay, removed users are cut.

telemt creates its default native listener only when no listeners are listed. Adding a WEB listener therefore turns native MTProto off unless you also list native listeners. The panel form writes them when WEB is enabled. If you edit the JSON by hand, add `{"ip": "0.0.0.0"}` and `{"ip": "::"}` (or your own).

Minimal example: native MTProto on 8443, WEB on `127.0.0.1:18080`, a decoy site on `127.0.0.1:18081`:
```json
{
  "server": {
    "port": 8443,
    "listeners": [
      {"ip": "0.0.0.0"},
      {"ip": "::"},
      {
        "ip": "127.0.0.1",
        "port": 18080,
        "transport": "web",
        "web_client_ip_source": "x_forwarded_for",
        "web_trusted_proxy_cidrs": ["127.0.0.1/32"]
      }
    ]
  },
  "censorship": {"tls_domain": "www.microsoft.com"},
  "web": {
    "enabled": true,
    "carrier": "https",
    "vhosts": [
      {
        "host": "proxy.example.com",
        "public_addr": "203.0.113.10:443",
        "decoy": {"mode": "http_upstream", "upstream": "http://127.0.0.1:18081"},
        "user_profile": {"secret_mode": "dd"}
      }
    ]
  }
}
```
The panel requires `censorship.tls_domain` while fake TLS mode is on (telemt's default); it is the site that native fake TLS clients present. `"carrier": "https"` keeps iOS working. `https-lanes` needs public HTTP/2 and is not supported by iOS.

### Front examples
Both forward the whole domain to telemt, overwrite `X-Forwarded-For` with one address, and turn off response buffering. Timeouts must stay above telemt's 25 s long poll and twice the WebSocket liveness interval; 65 s covers the defaults. Do not enable upstream retries. Keep request URLs and the `Authorization` header out of access logs: they carry the users' WEB credentials.

Caddy (gets and renews the certificate itself):
```caddyfile
{
	servers {
		protocols h1 h2
	}
}

proxy.example.com {
	reverse_proxy 127.0.0.1:18080 {
		header_up X-Forwarded-For {remote_host}
		flush_interval -1
		stream_close_delay 5m
	}
}
```
Do not add `header_up Host`. `protocols h1 h2` keeps HTTP/3 off, and it applies to every site on that Caddy server.

nginx (the `map` goes in the `http` context):
```nginx
map $http_upgrade $telemt_connection_upgrade {
    default upgrade;
    ''      '';
}

upstream telemt_web {
    server 127.0.0.1:18080;
    keepalive 64;
}

server {
    listen 443 ssl;
    http2 on;
    server_name proxy.example.com;
    access_log off;

    ssl_certificate     /etc/letsencrypt/live/proxy.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/proxy.example.com/privkey.pem;

    client_max_body_size 2m;

    location / {
        proxy_pass http://telemt_web;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $telemt_connection_upgrade;

        proxy_connect_timeout 5s;
        proxy_send_timeout 65s;
        proxy_read_timeout 65s;
        proxy_request_buffering off;
        proxy_buffering off;
        proxy_next_upstream off;
    }
}
```
`http2 on;` needs nginx 1.25.1 or newer; older nginx fails `nginx -t` with an unknown directive, so drop that line and use `listen 443 ssl http2;` instead.

`client_max_body_size` must be at least telemt's `web.limits.max_body_bytes`.

Firewall the WEB listener port and the decoy port from outside, even on loopback.

### Port 443
The front needs public port 443, and native fake TLS usually wants 443 too. Either:
- move native MTProto to another port (8443 in the example above), or
- split 443 by host name in the front: nginx `stream` with `ssl_preread`, or HAProxy SNI routing. The WEB domain is terminated by the front and other names pass through to telemt's native listener. PasarGuard has not tested this split.

### Several nodes
A WEB domain points at one server, and `public_addr` is that server's IP. With several MTProto nodes, use one core per node.

### Capacity
- telemt holds at most 65536 WEB profiles (users times vhosts): 65536 users with one vhost, 32768 with two. Above that the node refuses the sync with an error and leaves telemt's config file unchanged.
- The 8 MiB config file limit allows about 69k users with one WEB vhost (about 121.6 bytes per user), and about 36k if every user has every optional limit set (about 232.9 bytes per user). Native only is about 196k (about 42.8 bytes per user). Each extra vhost adds an estimated 79 bytes per user (not measured).
- 65536 profiles fit telemt's default WEB memory envelope (1280 MiB, about 4 MiB free for profiles at 64 bytes each). If you raise other `web.limits` reservations or lower `web.limits.memory_envelope_bytes`, telemt refuses to start with `web.limits memory reservations must fit memory_envelope_bytes`.

## Xray and MTProto on one host
One node runs one backend, so serving Xray (or WireGuard) and MTProto from one server takes two node instances, each added to the panel as its own node:
- Each instance needs its own `SERVICE_PORT` and its own data directory (certificates and generated configs). With the installer, `--name` creates a separate instance, for example `... @ install --name pg-node-mtproto`.
- Both instances use the host network, so only one of them can listen on public port 443. Give the other one's inbound another port, for example 8443.

With Docker Compose (trimmed, see `docker-compose.yml` for the full service):
```yaml
services:
  node:          # Xray or WireGuard
    image: pasarguard/node:latest
    network_mode: host
    environment:
      SERVICE_PORT: 62050
    volumes:
      - /var/lib/pg-node:/var/lib/pg-node
  node-mtproto:  # MTProto
    image: pasarguard/node:latest
    network_mode: host
    environment:
      SERVICE_PORT: 62051
    volumes:
      - /var/lib/pg-node-mtproto:/var/lib/pg-node
```

## Third-party software
- telemt 3.5.14, TELEMT License 3.3, Copyright (c) 2026 Telemt. Source: https://github.com/telemt/telemt/tree/3.5.14
- The image contains the unmodified upstream release binary. The license text is in [`third_party/telemt/`](third_party/telemt/) and in the image at `/usr/share/licenses/telemt/`.
- The telemt license asks operators of a public service to credit telemt (for example in the service docs), without implying endorsement by the Telemt maintainers.

# Donation
You can help PasarGuard team with your donations, [Click Here](https://donate.pasarguard.org/)

# Contributors

We ❤️‍🔥 contributors! If you'd like to contribute, please check out our [Contributing Guidelines](CONTRIBUTING.md) and feel free to submit a pull request or open an issue. We also welcome you to join our [Telegram](https://t.me/Pasar_Guard) group for either support or contributing guidance.

Check [open issues](https://github.com/PasarGuard/node/issues) to help the progress of this project.

## Stargazers over time
[![Stargazers over time](https://starchart.cc/PasarGuard/node.svg?variant=adaptive)](https://starchart.cc/PasarGuard/node)
                    
<p align="center">
Thanks to the all contributors who have helped improve PasarGuard Node:
</p>
<p align="center">
<a href="https://github.com/PasarGuard/node/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=PasarGuard/node" />
</a>
</p>
<p align="center">
  Made with <a rel="noopener noreferrer" target="_blank" href="https://contrib.rocks">contrib.rocks</a>
</p>
