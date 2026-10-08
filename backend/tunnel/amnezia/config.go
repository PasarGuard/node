package amnezia

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/pasarguard/node/backend/tunnel"
)

// The row's params dict reaches both sides unchanged (CONTRACT §2.4's row
// encoding), so every site-specific key exists twice, prefixed by side. This
// side reads only its own prefix; the other side's keys are named in the
// refusal, never silently ignored. Obfuscation keys follow the same prefix
// rule (brief: a_jc / b_jc, a_jmin … b_h4).
const (
	paramAddress          = "address"
	paramLanCIDR          = "lan_cidr"
	paramPeerEndpoint     = "peer_endpoint"
	paramPeerPublicKey    = "peer_public_key"
	paramPeerAllowedCIDRs = "peer_allowed_cidrs"
	paramNetns            = "netns"
)

// AmneziaWG obfuscation knobs (CONTRACT §2.4's prefix rule applied to the
// magic-header parameters). All optional: absent means "leave the daemon's
// default", which is what a plain pair does.
const (
	paramJc   = "jc"   // junk packet count
	paramJmin = "jmin" // junk packet minimum size
	paramJmax = "jmax" // junk packet maximum size
	paramS1   = "s1"   // init packet padding
	paramS2   = "s2"   // response packet padding
	paramH1   = "h1"   // init packet header magic
	paramH2   = "h2"   // response packet header magic
	paramH3   = "h3"   // cookie packet header magic
	paramH4   = "h4"   // transport packet header magic
)

// obfsOrder is the order Render writes them in, so two renders of one Spec
// are byte-identical.
var obfsOrder = []string{paramJc, paramJmin, paramJmax, paramS1, paramS2, paramH1, paramH2, paramH3, paramH4}

// obfsUint are the plain unsigned-int knobs; the rest (h1..h4) also accept
// the daemon's range form "lo-hi".
var obfsUint = map[string]bool{
	paramJc: true, paramJmin: true, paramJmax: true, paramS1: true, paramS2: true,
}

var siteParams = []string{
	paramAddress,
	paramLanCIDR,
	paramPeerEndpoint,
	paramPeerPublicKey,
	paramPeerAllowedCIDRs,
	paramNetns,
}

var allParams = append(append([]string{}, siteParams...), obfsOrder...)

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
// output. It describes this side's site parameters and its obfuscation
// parameters; the private key never enters it — a determinism failure prints
// both renders, and that must never put a secret in a log line (§2.3 rule 3).
func (Adapter) Render(spec tunnel.Spec) (string, error) {
	if err := spec.Validate(); err != nil {
		return "", err
	}
	mode := modeOf(spec)
	if mode != tunnel.ModeRelay {
		return "", fmt.Errorf("%w: amnezia site-to-site has only a passing subnet-to-subnet run in mode=%s, not %q (CONTRACT §2.4)",
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
	fmt.Fprintf(&b, "# amnezia (amneziawg-go, userspace) site-to-site — PasarGuard node, tunnel %s side %s (mode %s)\n", spec.TunnelID, spec.Side, mode)
	fmt.Fprintf(&b, "tunnel_id = %s\n", spec.TunnelID)
	fmt.Fprintf(&b, "tool_version = %s\n", spec.ToolVersion)
	fmt.Fprintf(&b, "side = %s\n", spec.Side)
	fmt.Fprintf(&b, "mode = %s\n", mode)
	fmt.Fprintf(&b, "interface = %s\n", IfName(spec))
	fmt.Fprintf(&b, "uapi_socket = %s\n", sockPath(IfName(spec)))
	fmt.Fprintf(&b, "listen_port = %s\n", listen)
	fmt.Fprintf(&b, "netns = %s\n", sp.Netns)
	fmt.Fprintf(&b, "address = %s\n", sp.Address)
	fmt.Fprintf(&b, "lan_cidr = %s\n", sp.LanCIDR)
	fmt.Fprintf(&b, "peer_public_key = %s\n", sp.PeerPublicKey)
	fmt.Fprintf(&b, "peer_endpoint = %s\n", sp.PeerEndpoint)
	fmt.Fprintf(&b, "peer_allowed_cidrs = %s\n", sp.PeerAllowedCIDRs)
	for _, k := range obfsOrder {
		if v, ok := sp.Obfs[k]; ok {
			fmt.Fprintf(&b, "%s = %s\n", k, v)
		}
	}
	if len(sp.Obfs) == 0 {
		b.WriteString("# obfuscation = (not set: both heads keep the daemon defaults, Jc/Jmin/Jmax/S1/S2/H1..H4)\n")
	}
	b.WriteString("private_key = (secret " + SecretPrivateKey + ": resolved from the node environment at Start, sent over this side's uapi socket; never rendered)\n")
	return b.String(), nil
}

// IfName is this side's TUN interface name, derived from tunnel_id and the
// side (CONTRACT §2.4: never a bare shared wg0). 15 chars, exactly IFNAMSIZ-1,
// stable across restarts so a re-Render lands on the same interface — and the
// uapi socket is named after it.
func IfName(spec tunnel.Spec) string {
	sum := sha256.Sum256([]byte(spec.TunnelID + "/" + spec.Side.String()))
	return "awg-" + hex.EncodeToString(sum[:5]) + spec.Side.String()
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
	// Obfs holds the obfuscation knobs this side was given, keyed by their
	// unprefixed name in obfsOrder. Absent key = leave the daemon default.
	Obfs map[string]string
	// Allowed is PeerAllowedCIDRs split and parsed: routes and the peer's
	// allowed-ips are both driven from it.
	Allowed []string
}

// loadParams reads this side's prefixed keys out of Spec.Params. The row's
// dict reaches both sides unchanged and carries both prefixes (CONTRACT §2.4
// row encoding), so the other side's keys are expected here and ignored —
// this side reads only its own. Keys that are neither framework keys nor a
// site/obfuscation key under either prefix are refusals: the adapter is the
// authority on its own surface (§2.1). Missing required keys are named one
// by one.
func loadParams(spec tunnel.Spec) (sideParams, error) {
	prefix := sidePrefix(spec.Side)
	other := sidePrefix(opposite(spec.Side))
	sp := sideParams{Prefix: prefix, Obfs: map[string]string{}}

	for _, k := range tunnel.SortedParams(spec.Params) {
		switch k {
		case tunnel.ParamListenPort, tunnel.ParamConfigDir, tunnel.ParamBinaryPath:
			continue // framework keys, not site keys
		}
		known := false
		for _, p := range allParams {
			if k == prefix+p || k == other+p {
				known = true
			}
		}
		if !known {
			return sp, fmt.Errorf("amnezia: params key %q is not an amnezia parameter (site keys are %saddress, %speer_endpoint, …; obfuscation keys are %sjc, %sh1, …)",
				k, prefix, prefix, prefix, prefix)
		}
	}

	missing := func(key, what string) error {
		return fmt.Errorf("amnezia: side %s needs params.%s%s (%s)", spec.Side, prefix, key, what)
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

	for _, k := range obfsOrder {
		if v := strings.TrimSpace(spec.Params[prefix+k]); v != "" {
			sp.Obfs[k] = v
		}
	}
	return sp, nil
}

func opposite(s tunnel.Side) tunnel.Side {
	if s == tunnel.SideB {
		return tunnel.SideA
	}
	return tunnel.SideB
}

// validate is the value-level check: every field is one the daemon or iproute2
// will accept, refused here with the key named instead of at exec time.
func (sp *sideParams) validate() error {
	if _, _, err := net.ParseCIDR(sp.Address); err != nil {
		return fmt.Errorf("amnezia: params.%saddress %q is not a CIDR (want e.g. 10.67.0.1/24)", sp.Prefix, sp.Address)
	}
	if _, _, err := net.ParseCIDR(sp.LanCIDR); err != nil {
		return fmt.Errorf("amnezia: params.%slan_cidr %q is not a CIDR (want e.g. 192.168.10.0/24)", sp.Prefix, sp.LanCIDR)
	}
	host, port, err := net.SplitHostPort(sp.PeerEndpoint)
	if err != nil || host == "" || port == "" {
		return fmt.Errorf("amnezia: params.%speer_endpoint %q is not host:port (the peer's underlay address and its listen port)", sp.Prefix, sp.PeerEndpoint)
	}
	if err := validPort(port); err != nil {
		return fmt.Errorf("amnezia: params.%speer_endpoint %q: %v", sp.Prefix, sp.PeerEndpoint, err)
	}
	key, err := base64.StdEncoding.DecodeString(sp.PeerPublicKey)
	if err != nil || len(key) != 32 {
		return fmt.Errorf("amnezia: params.%speer_public_key is not a base64 Curve25519 key (32 bytes after decoding)", sp.Prefix)
	}
	for _, cidr := range strings.Split(sp.PeerAllowedCIDRs, ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("amnezia: params.%speer_allowed_cidrs entry %q is not a CIDR", sp.Prefix, cidr)
		}
		sp.Allowed = append(sp.Allowed, cidr)
	}
	if len(sp.Allowed) == 0 {
		return fmt.Errorf("amnezia: params.%speer_allowed_cidrs is empty — nothing would be routed into the tunnel", sp.Prefix)
	}
	for _, k := range obfsOrder {
		v, ok := sp.Obfs[k]
		if !ok {
			continue
		}
		if err := validObfs(k, v); err != nil {
			return fmt.Errorf("amnezia: params.%s%s: %v", sp.Prefix, k, err)
		}
	}
	return nil
}

// validObfs accepts what the daemon's uapi parser accepts: a plain unsigned
// int for Jc/Jmin/Jmax/S1/S2, and the UintRange grammar ("N" or "lo-hi") for
// H1..H4. The daemon stays the final authority; this only turns a typo into a
// named refusal instead of a start-time errno.
func validObfs(key, v string) error {
	if obfsUint[key] {
		if _, err := parseUint32(v); err != nil {
			return fmt.Errorf("%q is not an unsigned integer", v)
		}
		return nil
	}
	if _, err := parseUintRange(v); err != nil {
		return fmt.Errorf("%q is not a number or a range like 100-255", v)
	}
	return nil
}

func parseUint32(v string) (uint32, error) {
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(n), nil
}

// parseUintRange mirrors the daemon's UintRange.FromString (device/noise-types.go).
func parseUintRange(v string) (uint32, error) {
	parts := strings.Split(v, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return 0, fmt.Errorf("wrong format")
	}
	lo, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return 0, err
	}
	hi := lo
	if len(parts) > 1 {
		hi, err = strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return 0, err
		}
	}
	if hi < lo {
		return 0, fmt.Errorf("wrong range specified")
	}
	return uint32(lo), nil
}

func validPort(p string) error {
	var n int
	if _, err := fmt.Sscanf(p, "%d", &n); err != nil || n < 1 || n > 65535 || fmt.Sprintf("%d", n) != p {
		return fmt.Errorf("port %q is not 1-65535", p)
	}
	return nil
}
