package openvpn

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// Config is the panel-authored core config — the JSON in Backend.Config, the
// same relationship hysteria.Config has to panel/app/core/hysteria.py.
//
// Every field has a default so a panel that renders a subset still produces a
// core that starts. The schema is published in docs/multi/openvpn.md because it
// is the one shape the panel's ConfigClass and this package must agree on, and
// neither side may edit CONTRACT.md to say it.
type Config struct {
	// Port is the single listener port. One OpenVPN process serves one
	// proto/port pair (upstream has no multi-listener mode), so a node that
	// wants UDP and TCP at once runs two openvpn cores — CONTRACT §1.2 keys a
	// handle on core_id, not BackendType, so two cores of one type are legal.
	Port int `json:"port"`
	// Protocol is "udp" (default) or "tcp".
	Protocol string `json:"protocol"`
	// Network/Netmask are the tunnel pool: `server <network> <netmask>`.
	Network string `json:"network"`
	Netmask string `json:"netmask"`
	// DNS entries become `push "dhcp-option DNS …"` lines, in order.
	DNS []string `json:"dns"`
	// RedirectGateway pushes `redirect-gateway def1 bypass-dhcp`.
	RedirectGateway bool `json:"redirect_gateway"`

	excluded map[string]bool
}

const (
	defaultPort     = 1194
	defaultNetwork  = "10.8.0.0"
	defaultNetmask  = "255.255.255.0"
	defaultProtocol = "udp"
)

// NewConfig parses the panel's JSON and applies defaults. An empty string is
// treated as `{}`: a Factory call with an unset config must fail on a *named*
// problem (no generated config path, no binary), not on a JSON syntax error.
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
		c.Port = defaultPort
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("openvpn: port %d is out of range", c.Port)
	}
	if c.Network == "" {
		c.Network = defaultNetwork
	}
	if c.Netmask == "" {
		c.Netmask = defaultNetmask
	}
	ip := net.ParseIP(c.Network).To4()
	mask := net.IPMask(net.ParseIP(c.Netmask).To4())
	if ip == nil || len(mask) != net.IPv4len {
		return fmt.Errorf("openvpn: network %q / netmask %q is not an IPv4 pool", c.Network, c.Netmask)
	}
	if binaryIP(ip)&^binaryIP(net.IP(mask)) != 0 {
		return fmt.Errorf("openvpn: network %q has host bits set under netmask %q", c.Network, c.Netmask)
	}
	ones, bits := mask.Size()
	if bits != 32 || ones > 30 {
		return fmt.Errorf("openvpn: netmask %q leaves no client addresses", c.Netmask)
	}
	for _, d := range c.DNS {
		if net.ParseIP(d) == nil {
			return fmt.Errorf("openvpn: dns entry %q is not an IP address", d)
		}
	}
	return nil
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
//     (LEGACY-VPN.md §4a).
//   - `ccd-exclusive`: no CCD file, no session. The static IP is what the
//     accounting rules bind to (§4b), so a client that authenticated without one
//     must not get a tunnel.
//   - `dh none` + an ECDHE-only tls-cipher list: Go cannot generate DH
//     parameters, and ECDHE needs none. The two are a pair — `dh none` without
//     restricting tls-cipher would offer DHE suites with no group to run them on.
//   - The management password is *never* a line here: only the 0600 file path
//     that openvpn reads itself.
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
	w("server %s %s", c.Network, c.Netmask)
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
	if c.RedirectGateway {
		w("push \"redirect-gateway def1 bypass-dhcp\"")
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
