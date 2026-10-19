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
- telemt refuses a config file above 8 MiB, which is roughly 150k to 190k users on one node.

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
