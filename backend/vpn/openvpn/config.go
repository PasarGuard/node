package openvpn

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// Config is the panel-authored core config — the JSON `to_str()` sends
// (panel/app/core/openvpn.py, agreed with panel-ui-subscription in batch 5a-1):
//
//	{"port": int, "protocol": "udp"|"tcp", "server": "<IPv4 CIDR>",
//	 "dns": [...], "ca": PEM, "cert": PEM, "key": PEM, "tls_crypt": keyfile}
//
// The four PEM/key fields are optional: without them the node generates the
// PKI so the core can boot, but there is no RPC to read a generated CA back
// (CONTRACT 6.4), so an operator who wants self-contained .ovpn downloads must
// paste CA + tls-crypt into the core config. docs/multi/openvpn.md says so.
//
// Every field except port has a default, and unknown fields are ignored: a
// panel that renders a subset still produces a core that starts.
type Config struct {
	// Port is the single listener port. One OpenVPN process serves one
	// proto/port pair (upstream has no multi-listener mode), so a node that
	// wants UDP and TCP at once runs two openvpn cores — CONTRACT 1.2 keys a
	// handle on core_id, not BackendType, so two cores of one type are legal.
	Port int `json:"port"`
	// Protocol is "udp" (default) or "tcp".
	Protocol string `json:"protocol"`
	// Server is the tunnel pool as a CIDR: "10.8.0.0/24".
	Server string `json:"server"`
	// DNS entries become `push "dhcp-option DNS …"` lines, in order.
	DNS []string `json:"dns"`

	// Operator-supplied PKI. All three certificate fields travel together — a
	// CA certificate without its private key cannot sign the server cert this
	// package would otherwise generate, so a partial set is an error rather
	// than a config that starts and then fails every handshake.
	CA       string `json:"ca"`
	Cert     string `json:"cert"`
	Key      string `json:"key"`
	TLSCrypt string `json:"tls_crypt"`

	network  string // Server split into its parts, derived in applyDefaults
	netmask  string
	excluded map[string]bool
}

const (
	defaultServerCIDR = "10.8.0.0/24"
	defaultProtocol   = "udp"
)

// NewConfig parses the panel's JSON, applies defaults and validates. An empty
// string is treated as `{}` so a Factory call with an unset config fails on a
// *named* problem (missing port, no generated config path) rather than on a
// JSON syntax error.
func NewConfig(config string, exclude []string) (*Config, error) {
	if strings.TrimSpace(config) == "" {
		config = "{}"
	}
	c := &Config{}
	if err := json.Unmarshal([]byte(config), c); err != nil {
		return nil, fmt.Errorf("invalid openvpn config JSON: %w", err)
	}
	c.excluded = make(map[string]bool, len(exclude))
	for _, tag := range exclude {
		c.excluded[tag] = true
	}
	if err := c.applyDefaults(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) applyDefaults() error {
	if c.Protocol == "" {
		c.Protocol = defaultProtocol
	}
	c.Protocol = strings.ToLower(c.Protocol)
	if c.Protocol == "tcp" {
		c.Protocol = "tcp-server" // server-side spelling of `proto tcp`
	}
	if c.Protocol != "udp" && c.Protocol != "tcp-server" {
		return fmt.Errorf("openvpn: protocol must be \"udp\" or \"tcp\", got %q", c.Protocol)
	}
	if c.Port == 0 {
		return fmt.Errorf("openvpn: port is required (1-65535)")
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("openvpn: port %d is out of range", c.Port)
	}
	if c.Server == "" {
		c.Server = defaultServerCIDR
	}
	prefix, err := netip.ParsePrefix(c.Server)
	if err != nil || !prefix.Addr().Is4() {
		return fmt.Errorf("openvpn: server %q is not an IPv4 CIDR", c.Server)
	}
	if prefix.Addr() != prefix.Masked().Addr() {
		return fmt.Errorf("openvpn: server %q has host bits set", c.Server)
	}
	if prefix.Bits() < 1 || prefix.Bits() > 30 {
		return fmt.Errorf("openvpn: server %q leaves no client addresses", c.Server)
	}
	c.network = prefix.Addr().String()
	// net.IPMask.String renders 255.255.255.0 as "ffffff00", which is not
	// what the `server` directive wants; go through net.IP instead.
	c.netmask = net.IP(net.CIDRMask(prefix.Bits(), 32)).String()

	for _, d := range c.DNS {
		if net.ParseIP(d) == nil {
			return fmt.Errorf("openvpn: dns entry %q is not an IP address", d)
		}
	}
	return c.validatePKI()
}

// validatePKI refuses a partial certificate set: a CA with no signing key
// cannot produce the server certificate, so the core would start and then fail
// every client handshake with a TLS error nobody can read.
func (c *Config) validatePKI() error {
	// Checked unconditionally: tls_crypt is independent of the certificate set,
	// and a paste that is not a static key would otherwise reach openvpn as a
	// config it cannot parse.
	if c.TLSCrypt != "" && !strings.Contains(c.TLSCrypt, "-----BEGIN OpenVPN Static key V1-----") {
		return fmt.Errorf("openvpn: tls_crypt is not an OpenVPN static key (no BEGIN OpenVPN Static key V1 marker)")
	}
	got := map[string]string{"ca": c.CA, "cert": c.Cert, "key": c.Key}
	missing := []string{}
	for _, name := range []string{"ca", "cert", "key"} {
		if strings.TrimSpace(got[name]) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) == 3 {
		return nil // none supplied: the node generates the lot
	}
	if len(missing) > 0 {
		return fmt.Errorf(
			"openvpn: PKI must be supplied as a set — %s missing. A CA certificate without its "+
				"private key cannot sign the server certificate, so a partial set would start the "+
				"core and then fail every handshake", strings.Join(missing, ", "))
	}
	return nil
}

// Network and Netmask are the pool split out of Server, for the `server`
// directive and the IP allocator.
func (c *Config) Network() string { return c.network }
func (c *Config) Netmask() string { return c.netmask }

// SuppliedPKI reports whether the operator pasted a certificate set.
func (c *Config) SuppliedPKI() bool {
	return strings.TrimSpace(c.CA) != ""
}

// RenderOptions are the absolute paths only the node knows when it starts the
// child: everything else in the config is a relative name resolved against
// `openvpn --cd`, which is what keeps the rendered file byte-stable.
type RenderOptions struct {
	AuthExecutable         string
	ManagementSocket       string
	ManagementPasswordFile string
	ClientConfigDir        string
}

// Render writes the OpenVPN server configuration.
//
// What is deliberately here, and what is deliberately not:
//   - tls-version-min 1.2, data-ciphers AES-256-GCM:CHACHA20-POLY1305, and
//     `allow-compression no` with no compress/comp-lzo line anywhere: the
//     VORBLEACH-class attacks are compression, and 2.6 refuses to negotiate a
//     cipher outside data-ciphers anyway.
//   - `verify-client-cert none` + `username-as-common-name`: the OpenVPN common
//     name IS the panel's user id, which is what CCD, status 3 and `kill` key on
//     (LEGACY-VPN.md 4a).
//   - `ccd-exclusive`: no CCD file, no session. The static IP is what the
//     accounting rules bind to (4b), so a client that authenticated without one
//     must not get a tunnel.
//   - `dh none` + an ECDHE-only tls-cipher list: Go cannot generate DH
//     parameters, and ECDHE needs none. The two are a pair — `dh none` without
//     restricting tls-cipher would offer DHE suites with no group to run them on.
//   - The management password is *never* a line here: only the 0600 file path
//     that openvpn reads itself.
//
// What is NOT here: a `push "redirect-gateway"`. The agreed panel schema has no
// key for it, so this core routes nothing by default; adding it is a new config
// field, not a node-side default (docs/multi/openvpn.md).
func (c *Config) Render(o RenderOptions) string {
	var b strings.Builder
	w := func(format string, args ...any) {
		fmt.Fprintf(&b, format+"\n", args...)
	}

	w("# PasarGuard OpenVPN core — generated by the node, do not edit.")
	w("# Secrets live in 0600 files next to this one, never in this file.")
	w("")
	w("dev tun")
	w("topology subnet")
	w("port %d", c.Port)
	w("proto %s", c.Protocol)
	w("server %s %s", c.network, c.netmask)
	w("")
	w("ca ca.crt")
	w("cert server.crt")
	w("key server.key")
	w("dh none")
	w("tls-crypt tls-crypt.key")
	w("tls-version-min 1.2")
	w("tls-cipher TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256:TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256:TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384")
	w("tls-ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256")
	w("data-ciphers AES-256-GCM:CHACHA20-POLY1305")
	w("data-ciphers-fallback AES-256-GCM")
	w("auth SHA256")
	w("allow-compression no")
	w("")
	w("verify-client-cert none")
	w("username-as-common-name")
	w("script-security 2")
	w("auth-user-pass-verify %s via-file", o.AuthExecutable)
	w("client-config-dir %s", o.ClientConfigDir)
	w("ccd-exclusive")
	w("")
	w("management %s unix %s", o.ManagementSocket, o.ManagementPasswordFile)
	w("")
	for _, d := range c.DNS {
		w("push \"dhcp-option DNS %s\"", d)
	}
	w("")
	w("keepalive 10 120")
	w("persist-key")
	w("persist-tun")
	if c.Protocol == "udp" {
		w("explicit-exit-notify 1")
	}
	w("status status.log 10")
	w("verb 3")
	return b.String()
}

// writeServerConfig writes server.conf 0600. It carries no secret — the
// management password and every key are separate files — but it names them,
// and the same mode keeps the auth-executable path and pool private for free.
func writeServerConfig(dir, text string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("openvpn: creating config directory: %w", err)
	}
	return os.WriteFile(filepath.Join(dir, "server.conf"), []byte(text), 0o600)
}

// assignedToThisCore reports whether the panel placed this user on one of the
// core's non-excluded inbounds. Same rule hysteria uses
// (backend/hysteria/config.go:251-262): an empty list means "no specific tag",
// which xray reads as "all inbounds".
func assignedToThisCore(user interface{ GetInbounds() []string }, excluded map[string]bool) bool {
	inbounds := user.GetInbounds()
	if len(inbounds) == 0 {
		return true
	}
	for _, tag := range inbounds {
		if !excluded[tag] {
			return true
		}
	}
	return false
}
