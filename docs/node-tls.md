# Node TLS and certificate management

The panel connects to the node and maintenance service over TLS. Direct node
listeners retain TLS by default, including existing installations without a
`TLS_ENABLED` setting. Both listeners read `SSL_CERT_FILE` and `SSL_KEY_FILE`.
API-key authentication remains required with either listener configuration.

## Installation

The node installer in `PasarGuard/scripts` offers these certificate choices:

1. Let's Encrypt IP certificate (default).
2. Let's Encrypt domain certificate.
3. Custom certificate and private key paths.
4. Self-signed certificate.
5. External TLS termination by a web server.

For IP certificates, interactive installation proposes the detected public IPv4
and accepts a correction and optional IPv6. Unattended installation requires an
explicit IPv4 identifier:

```sh
pg-node install -y --ssl-ip YOUR_PUBLIC_IPV4
pg-node install -y --ssl-ip YOUR_PUBLIC_IPV4 --ssl-ipv6 YOUR_PUBLIC_IPV6
pg-node install -y --ssl-domain node.example.com
pg-node install -y --cert-path /path/fullchain.pem --key-path /path/privkey.pem
pg-node install -y --self-signed --san-entries DNS:node.example.com,IP:YOUR_PUBLIC_IPV4
pg-node install -y --no-ssl
```

Choose one certificate source. `--cert-path` and `--key-path` must be used
together. `--ssl-ipv6` requires `--ssl-ip`. Old unattended commands that relied
on implicit self-signed generation must add `--self-signed`.

ACME uses HTTP-01. Public TCP port 80 must reach the challenge listener. Use
`--ssl-http-port PORT` (alias `--ssl-port`) when forwarding public port 80 to
another local port. The installer reports occupied ports and does not stop other
services. Issuance failures stop installation; retry explicitly after correcting
the problem. There is no automatic certificate or transport fallback.

New managed files use `fullchain.pem` and `privkey.pem` under the instance's data
directory:

| Source | Directory |
| --- | --- |
| IP ACME | `certs/ip/` |
| Domain ACME | `certs/<domain>/` |
| Custom | `certs/custom/` |
| Self-signed | Existing `certs/ssl_cert.pem` and `certs/ssl_key.pem` paths |

`certs/source.json` records the installer certificate source and ACME identifiers.
It does not select the panel's verification policy. Certificates are validated
for parsing, matching keys, valid dates, SAN presence, and ACME identifier matches
before replacing active files. Full chains are preserved and private keys are
restricted to their owner. The node container mounts the same data path used by
the host maintenance service, so both read the same active pair.

Routine `update` commands preserve the existing certificate files and configured
paths. `pg-node show-cert` displays the source, identity, validity, leaf DER
SHA-256 fingerprint, and PEM for older panels.

## Panel verification and renewal

Use a panel and bridge release supporting the new verification fields before
clearing PEM or configuring fingerprints. Upgrade all panel workers first.

| Certificate | Recommended panel fields |
| --- | --- |
| Publicly trusted certificate | Empty `server_ca`, null `certificate_sha256` |
| Self-signed certificate | Empty `server_ca`, trusted leaf DER `certificate_sha256` |
| Older panel | Preserve its existing PEM verification configuration |

A pin takes precedence over PEM when both fields are populated. Clearing a pin
with PEM retained restores PEM verification; clear both to select system trust.
Pin verification also checks dates and SANs. Obtain the fingerprint through a
trusted channel and use an address included in the certificate SANs.

`pg-node renew-cert` follows the saved source:

- ACME: renew using acme.sh. Its scheduled renewal deploys to staging, validates
  against the saved identifiers, activates the files, and restarts the instance's
  Compose service and installed maintenance systemd unit. RSA and ECC deployments
  are supported. Restart failures are reported.
- Self-signed: regenerate explicitly and display the new fingerprint. Update the
  panel pin before reconnecting.
- Custom: validate the current replacement files and restart both services.
  Renew the files externally and preserve the full chain. Keep the previous pair
  in an operator backup before replacing them.
- External TLS: manage and renew the certificate on the web server.

Older installations without source metadata retain their configured paths.
Explicit renewal recognizes self-signed certificates; other legacy certificates
are validated and remain the operator's renewal responsibility. Validated
installer deployments retain the previous active pair in `.previous` files.

ACME's cron scheduling is required during setup. Short-lived IP certificates use
the Let's Encrypt `shortlived` profile. Normal system-trust verification allows
renewal without changing panel fields. Monitor renewal and restart failures;
mocked CI does not replace controlled ACME staging issuance on a reachable public
host before rollout.

## External TLS termination

Set up the web server and certificate before changing the panel endpoints. Use
one of the nginx snippets below inside its `http {}` configuration:

- [REST and maintenance](../examples/nginx/rest.conf).
- [gRPC and maintenance](../examples/nginx/grpc.conf).

The snippets keep separate public service and maintenance ports (62050 and 62051)
and forward to private ports 62150 and 62151. Configure the node environment:

```dotenv
TLS_ENABLED=false
NODE_HOST=127.0.0.1
SERVICE_PORT=62150
API_PORT=62151
SERVICE_PROTOCOL=grpc
# Keep the existing API_KEY. Use SERVICE_PROTOCOL=rest with rest.conf.
```

Set the frontend certificate paths and server name in the snippet, then validate
and reload nginx using your deployment's normal procedure. Its two TLS listeners
must present the same leaf certificate when the panel uses a pin. Configure the
panel with the TLS frontend's address, service port, and maintenance port. Keep
the existing endpoints at `/`; endpoint-specific hostnames and arbitrary base
paths are not supported.

The examples preserve API-key headers, long-running responses, HTTP/2 gRPC,
request streaming, and the node's 64 MiB gRPC limit. The maintenance body limit
is 1 MiB. No client certificate is required merely because the server's
certificate is CA-signed. The shell maintenance implementation requires `socat`
and `python3` for its private plaintext listener.

With TLS disabled, certificate files are not loaded. A missing `NODE_HOST`
defaults to `127.0.0.1`. Explicit values must be literal addresses from IPv4
loopback, `::1`, RFC1918 IPv4, or IPv6 unique-local ranges. IPv4-mapped IPv6 is
normalized first. Public, wildcard, link-local, multicast, scoped, malformed,
and other special-use addresses are rejected. Hostnames, including `localhost`,
are rejected in plaintext mode. Invalid `TLS_ENABLED` values fail startup.

The example Compose deployment uses host networking, so a web server on that
host can reach loopback. With separate containers, arrange private backend
networking and bind to an allowed private address reachable from the frontend.
Do not publish backend ports on public interfaces. Review firewall rules, NAT,
and container publishing: a private listener cannot prevent another component
from forwarding it publicly. Expose only the frontend TLS ports to panel clients.
Web-server installation and certificate provisioning are managed externally.

## Rollback and CI

Keep the old PEM and certificate pair in an operator backup before migrating.
Verify both normal and maintenance operations after each transition. Restore
usable PEM before using an older panel; restore node TLS before using older
node or maintenance binaries. The legacy `server_ca` field remains supported by
the migration design.

Node CI runs direct TLS/private listener tests and the actual nginx snippets,
including REST streaming and gRPC streaming. Installer CI uses mocked ACME
commands and real local certificates without contacting an ACME issuer. The
maintenance repositories test startup, strict bindings, and authenticated HTTP
and TLS connections. Live public ACME staging issuance remains a deployment
integration check because it needs operator-controlled identifiers and routing.

### Certificate hot reload

The node validates the configured certificate/key pair, including certificate dates,
 at startup. Send `SIGHUP` to the node process after replacing the configured files
with a consistent pair. REST and gRPC use the same in-memory certificate holder.
Reloads validate the full supplied chain and key before atomically publishing the
replacement. Failed reloads retain the active pair. Logs report the active leaf's
SHA-256 fingerprint and expiry on startup and after each reload attempt.

Listeners, established connections, and streams remain running during reload and
are not closed at certificate expiry. New connections validate the certificate
under the client's saved trust policy. With external TLS (`TLS_ENABLED=false`),
`SIGHUP` logs a no-op. Reload the external TLS server separately.

Node-serviced supports the same signal for its separate maintenance certificate.
This feature does not schedule renewals or regenerate self-signed certificates.
Installing this support requires an initial service restart.
