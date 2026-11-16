# Node TLS and certificate management migration


This replaces the previous plan. No file has been written while this session remains in Plan mode.

## 1. Goals and confirmed decisions

- The panel always uses TLS for node communication, including maintenance requests.
- New node installations default to a valid Let’s Encrypt IP certificate.
- Certificate installation follows the existing `pasarguard.sh` workflow.
- Existing PEM-based configurations continue working unchanged.
- Self-signed certificates support SHA-256 fingerprint verification, valid-date checks, and matching SANs.
- No `tls_mode` database column or API field is introduced.
- The panel/bridge determines verification from configured fields.
- Optional plaintext node listeners exist only as private backends behind a TLS-terminating web server.
- API-key authentication remains mandatory.

```text
Default:
Panel ── TLS ──> Node

Advanced:
Panel ── TLS ──> Web server ── private plaintext ──> Node
```

## 2. Automatic verification selection

Use this exact precedence:

| Saved configuration | Effective verification |
|---|---|
| Nonempty `certificate_sha256` | Pinned certificate |
| Otherwise, nonempty `server_ca` | Existing PEM-based verification |
| Neither present | System certificate trust |

This is configuration-based detection, not trial-and-error fallback.

A configured fingerprint must match even if the certificate is publicly trusted. A failed pin, PEM validation, or system-trust check must fail the connection without trying a weaker policy.

When both fields are populated, the fingerprint takes precedence. PEM remains inactive until the fingerprint is explicitly cleared.

### Certificate fingerprint

`certificate_sha256` contains SHA-256 of the complete leaf certificate’s DER encoding—not the public key or PEM file.

Accept contiguous hexadecimal or colon-separated byte pairs, case-insensitively. Normalize to 64 lowercase hexadecimal characters.

Use one fingerprint per node. Main and maintenance endpoints must present the same leaf certificate when pinned, including reverse-proxy deployments.

## 3. Database and API changes

### Database

Add only:

```text
certificate_sha256: nullable string, length 64
```

Keep the existing `server_ca` column and stored values unchanged.

Do not add a mode column, contact nodes during migration, or automatically convert PEM certificates into pins.

### API fields and validation

- Make `server_ca` optional on creation, defaulting to an empty string.
- Add optional `certificate_sha256`, defaulting to null.
- Keep response `server_ca` values as strings.
- Reject malformed nonempty fingerprints and invalid nonempty PEM.
- Normalize whitespace-only PEM to an empty string.
- Permit both fields together, with documented fingerprint precedence.
- Creating a node without either field selects system trust.
- Existing create requests with PEM preserve legacy behavior.

For updates:

- Omitted fields retain their saved values.
- `certificate_sha256: null` or an empty string explicitly clears the pin.
- `server_ca: ""` explicitly clears PEM.
- Preserve existing `server_ca: null` update behavior as a no-op for compatibility.
- Validate the resulting merged configuration.
- Process fingerprint clearing explicitly rather than discarding it through `exclude_none=True`.

Examples:

| Desired transition | Update |
|---|---|
| Legacy → pinned | Set fingerprint; dashboard also clears PEM |
| Pinned → system trust | Clear fingerprint and PEM |
| Legacy → system trust | Clear PEM and any pin |
| System trust → legacy | Set PEM; clear any pin |
| Update unrelated settings | Omit both fields |

Because verification depends on fields, retaining PEM while clearing a pin intentionally returns to legacy verification. The dashboard must clear both fields when selecting system trust.

### Propagation

Update CRUD, responses, bulk operations, cloning, imports/exports, bridge construction, worker synchronization, OpenAPI, and generated dashboard types.

Add the fingerprint to the connection signature. Changes to either verification field must recreate connections and pools.

## 4. Bridge implementation

Preserve existing positional constructor compatibility. Add `certificate_sha256` as an optional keyword-only argument, and allow absent/empty PEM.

Implement one shared policy resolver using the precedence above. The bridge independently validates configuration so direct library consumers receive the same behavior as panel users.

All REST and maintenance URLs remain HTTPS. All panel gRPC connections remain TLS-enabled.

Apply verification consistently to:

- gRPC.
- REST.
- Maintenance operations.
- Streaming and reconnects.
- Supported proxy connections.

### Pinned verification

On the actual connection carrying application traffic:

1. Obtain the peer leaf certificate.
2. Compare its DER SHA-256 fingerprint.
3. Check validity dates.
4. Match the configured domain/IP against SANs.
5. Only then allow API keys, metadata, and request bodies to be sent.

Do not use Common Name fallback in this new verification path.

Do not verify a separate probe connection and then send application traffic through another unverified connection.

### Other verification

- Nonempty PEM without a pin preserves current trust-store and hostname behavior.
- Empty PEM without a pin uses the runtime system trust store and standard certificate identity verification.
- Preserve separate HTTP/2 and HTTP/1.1 ALPN handling.
- Disable automatic node-request redirects.
- Close failed connections.
- Invalidate pools after verification changes.
- Prevent pinned connections from remaining reusable beyond certificate expiry.

Report distinct failures for fingerprint mismatch, invalid dates, identity mismatch, and untrusted issuer. Never downgrade verification or transport.

## 5. Dashboard behavior

A UI-only verification selector may remain for usability:

- Trusted certificate — default.
- SHA-256 fingerprint.
- Legacy PEM certificate.

It is not stored or submitted as a mode field.

Infer its initial selection using the same field precedence as the bridge.

On save:

| UI selection | Submitted fields |
|---|---|
| Trusted certificate | Empty PEM, null fingerprint |
| SHA-256 fingerprint | Fingerprint, empty PEM |
| Legacy PEM certificate | PEM, null fingerprint |

If an existing API-created record contains both fields, display fingerprint verification and explain that the saved PEM is inactive. Saving through the fingerprint form normalizes the record by clearing PEM.

Preserve effective verification during cloning, bulk actions, and form resets.

Do not offer plaintext panel connections or “ignore certificate errors.”

For reverse-proxy deployments, explain that the address and ports identify the TLS frontend.

## 6. Node-only TLS termination setting

Introduce:

```text
TLS_ENABLED=true
```

Missing settings preserve current TLS operation. Invalid values fail startup.

### TLS enabled

- Load configured certificate/key files.
- Keep TLS REST and gRPC listeners.
- Use the same active certificate pair for maintenance.

### TLS disabled

This is exclusively an external-web-server backend option:

- Skip certificate loading.
- Serve REST and maintenance over HTTP.
- Serve gRPC over cleartext HTTP/2.
- Preserve API-key authentication.
- Default binding to `127.0.0.1`.

Allow explicit bindings only to:

- IPv4 loopback and `::1`.
- RFC1918 IPv4.
- IPv6 unique-local addresses.

Normalize IPv4-mapped IPv6 before checking. Reject public, wildcard, link-local, multicast, malformed, and other special-use addresses.

Use `NODE_HOST` consistently for main and maintenance listeners. Reject `0.0.0.0` and `::` in plaintext backend mode.

The bridge receives no plaintext option.

## 7. Certificate installation and renewal

### Installation menu

Model the flow on `pasarguard.sh`:

1. **Let’s Encrypt IP certificate — default.**
2. Let’s Encrypt domain certificate.
3. Custom certificate/key paths.
4. Self-signed certificate.
5. External web server terminates TLS — advanced.

For interactive IP issuance, propose detected public IPv4 and permit correction; support optional IPv6.

For unattended default IP issuance, require an explicit IP identifier. Fail with instructions when absent; do not silently generate self-signed certificates.

Preserve explicit `--self-signed`, `--cert-path`, and `--key-path` options.

Add:

- `--ssl-ip IPV4`
- `--ssl-ipv6 IPV6`, requiring `--ssl-ip`
- `--ssl-domain DOMAIN`
- `--ssl-http-port PORT`, with `--ssl-port` alias
- `--no-ssl`, documented as external TLS termination only

Reject conflicting selections. Document that old unattended commands relying on implicit self-signed generation must add `--self-signed`.

### ACME workflow

Adapt the panel installer’s existing helpers for dependencies, `acme.sh`, domain/IP issuance, short-lived IP certificates, RSA/ECC deployment, renewal scheduling, and restart hooks.

Keep node-specific helpers in the node installer; do not source the executable panel installer or refactor it in this task.

Report challenge-port conflicts without stopping unrelated services. Explain external challenge routing when a nondefault local port is selected.

### Paths and certificate source

Preserve existing paths on upgrade.

For new managed certificates:

- IP: `$DATA_DIR/certs/ip/`
- Domain: `$DATA_DIR/certs/<domain>/`
- Custom: `$DATA_DIR/certs/custom/`
- Self-signed: existing node paths

Use `fullchain.pem` and `privkey.pem` in new managed directories.

Update `SSL_CERT_FILE`, `SSL_KEY_FILE`, and container mappings so both listeners use the active pair.

Persist installer-side certificate source metadata: `acme_ip`, `acme_domain`, `custom`, `self_signed`, or `external_tls`. This metadata belongs to node certificate management, not the panel database or verification policy.

### Validation and failure behavior

Before activation, validate certificate parsing, matching key, dates, and expected SANs. Preserve full chains and restrictive key permissions.

Stage replacements and retain working files on failure.

Issuance failure stops or offers an explicit retry. Never silently switch to self-signed or plaintext operation.

### Renewal

Make `renew-cert` source-aware:

- ACME: renew, validate, deploy, restart both listeners.
- Self-signed: explicitly regenerate and display the new fingerprint.
- Custom: validate replacements and document external renewal responsibility.
- External TLS: direct certificate management to the web server.

Use deployment-specific restart targets and report failures.

ACME certificates should normally use system trust—both panel verification fields empty—so renewal requires no panel changes.

Retain PEM-display commands for older panels. Print certificate identity, expiry, source, fingerprint, and recommended panel fields after installation.

Routine upgrades must not regenerate certificates.

## 8. Maintenance and reverse-proxy deployment

Make the maintenance script honor `TLS_ENABLED` and the same binding restrictions.

Use its existing HTTP handler behind a bound plaintext TCP listener when externally terminated; require `socat` for that path.

Separate client-certificate authentication from server certificate issuer classification. Keep API-key authentication.

Provide tested web-server examples for:

- HTTPS to private REST.
- TLS gRPC to private cleartext gRPC.
- HTTPS to private maintenance HTTP.

Preserve credentials, streaming, HTTP/2, timeouts, and message limits.

Retain the existing panel address and separate service/maintenance ports; do not introduce arbitrary base paths or endpoint-specific hostnames.

The panel verifies the frontend certificate. Pinned frontends must present the same leaf certificate on both ports.

Document firewall, NAT, and container publishing requirements. Private binding alone cannot prevent another component from exposing the backend.

Automatic web-server installation is outside scope.

## 9. Migration and rollback

Release:

1. Backward-compatible bridge.
2. Node and maintenance listener support.
3. Installer and renewal changes.
4. Panel additive migration, dependency update, API, and dashboard.
5. Tested deployment documentation.

Upgrade all panel workers before configuring fingerprints.

Existing PEM records continue selecting legacy verification automatically.

Migration is explicit:

- To pinned: obtain a trusted fingerprint and set it.
- To system trust: clear both certificate fields after confirming the server’s trusted certificate and identity.
- To external termination: configure the web server first, then point the panel at its TLS endpoints.

Verify main and maintenance operations after each transition.

A field-based design cannot retain PEM in the same active record while selecting system trust. Preserve old PEM in an operator backup if rollback is needed.

Before running older panel versions, restore usable PEM and remove reliance on fingerprint-only or system-trust-only configuration. Restore node TLS before running older node/scripts when necessary.

Retain `server_ca`; removal requires a later breaking release.

## 10. Tests and acceptance criteria

### Automatic selection

- Pin only selects pinned verification.
- PEM only preserves legacy verification.
- Neither selects system trust.
- Both select pinned verification.
- Wrong pin fails even with a trusted certificate or valid PEM.
- Clearing a pin with PEM retained restores legacy verification.
- Clearing both selects system trust.
- Omitted fields do not alter policy.
- No mode column or API field is introduced.

### Transport and panel

Test real TLS connections for fingerprint, date, SAN, and trust-chain success/failure across all transports, reconnects, and supported proxies.

Verify credentials are withheld until verification succeeds, policy changes close old pools, and TLS never falls back to plaintext.

Cover partial updates, explicit clearing, cloning, bulk operations, dashboard normalization, and legacy constructors.

### Node and reverse proxy

Verify TLS defaults, strict private backend bindings, authentication, operation without backend certificate files, and TLS frontend connections for REST, gRPC, maintenance, and streaming.

### Installer and renewal

Test the IP-certificate default, explicit legacy flags, unattended identifiers, ACME scheduling, RSA/ECC deployment, failure preservation, source-aware renewal, both listener restart targets, and unchanged upgrade paths.

Use mocked ACME calls for automated tests and controlled staging issuance for integration validation.

Acceptance requires unchanged legacy operation, deterministic field-based verification, reliable valid-IP issuance and renewal, TLS on every panel connection, and plaintext restricted to explicitly configured private web-server backends.