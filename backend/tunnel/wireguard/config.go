package wireguard

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/pasarguard/node/backend/tunnel"
)

// The row's params dict reaches both sides unchanged (CONTRACT §2.4's row
// encoding), so every site-specific key exists twice, prefixed by side. This
// side reads only its own prefix; the other side's keys are named in the
// refusal, never silently ignored.
const (
	paramAddress          = "address"
	paramLanCIDR          = "lan_cidr"
	paramPeerEndpoint     = "peer_endpoint"
	paramPeerPublicKey    = "peer_public_key"
	paramPeerAllowedCIDRs = "peer_allowed_cidrs"
	paramNetns            = "netns"
)

var siteParams = []string{
	paramAddress,
	paramLanCIDR,
	paramPeerEndpoint,
	paramPeerPublicKey,
	paramPeerAllowedCIDRs,
	paramNetns,
}

func sidePrefix(s tunnel.Side) string {
	if s == tunnel.SideB {
		return "b_"
	}
	return "a_"
}

// modeOf is the Spec's mode with the contract's default filled in (§2.0).
func modeOf(spec tunnel.Spec) string {
	if spec.Mode == "" {
		return tunnel.ModeRelay
	}
	return spec.Mode
}

// Render is pure and deterministic (CONTRACT §2.1): same Spec, byte-identical
// output. It describes this side's site parameters; the private key never
// enters it — a determinism failure prints both renders, and that must never
// put a secret in a log line (§2.3 rule 3). Start writes the key to its own
// 0600 file under the per-tunnel directory.
func (Adapter) Render(spec tunnel.Spec) (string, error) {
	if err := spec.Validate(); err != nil {
		return "", err
	}
	mode := modeOf(spec)
	if mode != tunnel.ModeRelay {
		return "", fmt.Errorf("%w: wireguard site-to-site has only a passing subnet-to-subnet run in mode=%s, not %q (CONTRACT §2.4)",
			tunnel.ErrModeUnsupported, tunnel.ModeRelay, spec.Mode)
	}
	sp, err := loadParams(spec)
	if err != nil {
		return "", err
	}
	if err := sp.validate(); err != nil {
		return "", err
	}
	listen := strings.TrimSpace(spec.Params[tunnel.ParamListenPort])
	if listen == "" {
		listen = "(allocated at Start)"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# wireguard site-to-site — PasarGuard node, tunnel %s side %s (mode %s)\n", spec.TunnelID, spec.Side, mode)
	fmt.Fprintf(&b, "tunnel_id = %s\n", spec.TunnelID)
	fmt.Fprintf(&b, "tool_version = %s\n", spec.ToolVersion)
	fmt.Fprintf(&b, "side = %s\n", spec.Side)
	fmt.Fprintf(&b, "mode = %s\n", mode)
	fmt.Fprintf(&b, "interface = %s\n", IfName(spec))
	fmt.Fprintf(&b, "listen_port = %s\n", listen)
	fmt.Fprintf(&b, "netns = %s\n", sp.Netns)
	fmt.Fprintf(&b, "address = %s\n", sp.Address)
	fmt.Fprintf(&b, "lan_cidr = %s\n", sp.LanCIDR)
	fmt.Fprintf(&b, "peer_public_key = %s\n", sp.PeerPublicKey)
	fmt.Fprintf(&b, "peer_endpoint = %s\n", sp.PeerEndpoint)
	fmt.Fprintf(&b, "peer_allowed_cidrs = %s\n", sp.PeerAllowedCIDRs)
	fmt.Fprintf(&b, "private_key = (secret %s: resolved from the node environment at Start, written 0600 under the per-tunnel directory; never rendered)\n", SecretPrivateKey)
	return b.String(), nil
}

// IfName is this side's kernel interface name, derived from tunnel_id and the
// side (CONTRACT §2.4: never a bare shared wg0). 13 chars, always inside the
// kernel's 15-byte IFNAMSIZ, stable across restarts so a re-Render lands on
// the same interface.
func IfName(spec tunnel.Spec) string {
	sum := sha256.Sum256([]byte(spec.TunnelID + "/" + spec.Side.String()))
	return "wg-" + hex.EncodeToString(sum[:5]) + spec.Side.String()
}

// sideParams is one side's resolved view of the row's params.
type sideParams struct {
	// Prefix is the row-key prefix this side reads ("a_" / "b_"), kept for
	// refusal messages that must name the key the operator wrote.
	Prefix           string
	Netns            string
	Address          string
	LanCIDR          string
	PeerEndpoint     string
	PeerPublicKey    string
	PeerAllowedCIDRs string
	// Allowed is PeerAllowedCIDRs split and parsed: routes and the peer's
	// allowed-ips are both driven from it.
	Allowed []string
}

// loadParams reads this side's prefixed keys out of Spec.Params. The row's
// dict reaches both sides unchanged and carries both prefixes (CONTRACT §2.4
// row encoding), so the other side's keys are expected here and ignored —
// this side reads only its own. Keys that are neither framework keys nor a
// site key under either prefix are refusals: the adapter is the authority on
// its own surface (§2.1). Missing required keys are named one by one.
func loadParams(spec tunnel.Spec) (sideParams, error) {
	prefix := sidePrefix(spec.Side)
	other := sidePrefix(opposite(spec.Side))
	sp := sideParams{Prefix: prefix}

	for _, k := range tunnel.SortedParams(spec.Params) {
		switch k {
		case tunnel.ParamListenPort, tunnel.ParamConfigDir, tunnel.ParamBinaryPath:
			continue // framework keys, not site keys
		}
		known := false
		for _, p := range siteParams {
			if k == prefix+p || k == other+p {
				known = true
			}
		}
		if !known {
			return sp, fmt.Errorf("wireguard: params key %q is not a wireguard parameter (site keys are %saddress, %speer_endpoint, …)",
				k, prefix, prefix)
		}
	}

	missing := func(key, what string) error {
		return fmt.Errorf("wireguard: side %s needs params.%s%s (%s)", spec.Side, prefix, key, what)
	}
	get := func(key, what string) (string, error) {
		v := strings.TrimSpace(spec.Params[prefix+key])
		if v == "" {
			return "", missing(key, what)
		}
		return v, nil
	}

	var err error
	if sp.Address, err = get(paramAddress, "this side's tunnel CIDR, e.g. 10.67.0.1/24"); err != nil {
		return sp, err
	}
	if sp.LanCIDR, err = get(paramLanCIDR, "the LAN this side serves, e.g. 192.168.10.0/24"); err != nil {
		return sp, err
	}
	if sp.PeerEndpoint, err = get(paramPeerEndpoint, "the peer's underlay host:port"); err != nil {
		return sp, err
	}
	if sp.PeerPublicKey, err = get(paramPeerPublicKey, "the peer's public key (not secret)"); err != nil {
		return sp, err
	}
	if sp.PeerAllowedCIDRs, err = get(paramPeerAllowedCIDRs, "comma-separated CIDRs routed into the tunnel"); err != nil {
		return sp, err
	}
	sp.Netns = strings.TrimSpace(spec.Params[prefix+paramNetns]) // optional
	return sp, nil
}

func opposite(s tunnel.Side) tunnel.Side {
	if s == tunnel.SideB {
		return tunnel.SideA
	}
	return tunnel.SideB
}

// validate is the value-level check: every field is one the kernel tools will
// accept, refused here with the key named instead of at exec time.
func (sp *sideParams) validate() error {
	if _, _, err := net.ParseCIDR(sp.Address); err != nil {
		return fmt.Errorf("wireguard: params.%saddress %q is not a CIDR (want e.g. 10.67.0.1/24)", sp.Prefix, sp.Address)
	}
	if _, _, err := net.ParseCIDR(sp.LanCIDR); err != nil {
		return fmt.Errorf("wireguard: params.%slan_cidr %q is not a CIDR (want e.g. 192.168.10.0/24)", sp.Prefix, sp.LanCIDR)
	}
	host, port, err := net.SplitHostPort(sp.PeerEndpoint)
	if err != nil || host == "" || port == "" {
		return fmt.Errorf("wireguard: params.peer_endpoint %q is not host:port (the peer's underlay address and its listen port)", sp.PeerEndpoint)
	}
	if err := validPort(port); err != nil {
		return fmt.Errorf("wireguard: params.peer_endpoint %q: %v", sp.PeerEndpoint, err)
	}
	key, err := base64.StdEncoding.DecodeString(sp.PeerPublicKey)
	if err != nil || len(key) != 32 {
		return fmt.Errorf("wireguard: params.peer_public_key is not a base64 Curve25519 key (32 bytes after decoding)")
	}
	for _, cidr := range strings.Split(sp.PeerAllowedCIDRs, ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("wireguard: params.peer_allowed_cidrs entry %q is not a CIDR", cidr)
		}
		sp.Allowed = append(sp.Allowed, cidr)
	}
	if len(sp.Allowed) == 0 {
		return fmt.Errorf("wireguard: params.peer_allowed_cidrs is empty — nothing would be routed into the tunnel")
	}
	return nil
}

func validPort(p string) error {
	var n int
	if _, err := fmt.Sscanf(p, "%d", &n); err != nil || n < 1 || n > 65535 || fmt.Sprintf("%d", n) != p {
		return fmt.Errorf("port %q is not 1-65535", p)
	}
	return nil
}
