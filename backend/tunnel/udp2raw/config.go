package udp2raw

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/pasarguard/node/backend/tunnel"
)

// Parameters travel as ONE map shared by both sides — the panel sends the same
// `params` to side a and side b (app/operation/tunnel.py), so each side reads
// the keys it needs and refuses the rest by name.
const (
	// ParamListenHost is the bind address for this side's own port: the raw
	// listener on side b, the local UDP listener on side a. Default 0.0.0.0 —
	// udp2raw's own README binds the world; 127.0.0.1 restricts it.
	ParamListenHost = "listen_host"
	// ParamPeer is side a's dial target: side b's raw-facing address
	// ("host:port" = side b's listen_host:listen_port).
	ParamPeer = "peer"
	// ParamTarget is side b's destination: the UDP service the tunnel
	// delivers to ("host:port").
	ParamTarget = "target"
	// ParamRawMode is the faking mode. The pinned build (20230206.0) offers
	// faketcp (default), udp, icmp and easy-faketcp — see its own --help.
	ParamRawMode = "raw_mode"
	// ParamCipherMode / ParamAuthMode must match on both ends.
	ParamCipherMode = "cipher_mode"
	ParamAuthMode   = "auth_mode"
	// ParamAutoRule toggles `-a`: udp2raw's own iptables rules, added and
	// removed by the process. Defaults per raw_mode — see autoRule().
	ParamAutoRule = "auto_rule"
)

// SecretKey is the shared password both ends derive their cipher and MAC from
// (udp2raw's `-k`). The name travels on the wire; the value comes from the
// environment at Start, and Start refuses to run without it: udp2raw's own
// default is the public string "secret key".
const SecretKey = "UDP2RAW_KEY"

// toolParams are the keys this tool understands; everything else is refused.
var toolParams = map[string]bool{
	ParamListenHost:        true,
	ParamPeer:              true,
	ParamTarget:            true,
	ParamRawMode:           true,
	ParamCipherMode:        true,
	ParamAuthMode:          true,
	ParamAutoRule:          true,
	tunnel.ParamListenPort: true, // framework: the caller's pinned port
}

// requiredParams is what each (mode, side) cannot work without (CONTRACT §2.0:
// only relay is implemented, so only relay appears here).
var requiredParams = map[string]map[tunnel.Side][]string{
	tunnel.ModeRelay: {
		tunnel.SideA: {ParamPeer},
		tunnel.SideB: {ParamTarget},
	},
}

// Value tables, copied from the pinned build's own --help. A value outside the
// list is refused by name instead of being passed through to a tool that would
// exit on it.
var (
	rawModes    = []string{"faketcp", "udp", "icmp", "easy-faketcp"}
	cipherModes = []string{"aes128cfb", "aes128cbc", "xor", "none"}
	authModes   = []string{"hmac_sha1", "md5", "crc32", "simple", "none"}
)

// effectiveMode is the mode this spec runs in. "" is udp2raw's default,
// documented as relay — a mode whose run passed (CONTRACT §2.0).
func effectiveMode(spec tunnel.Spec) string {
	if spec.Mode == "" {
		return tunnel.ModeRelay
	}
	return spec.Mode
}

// checkParams is the schema: unknown keys refused by name, missing required
// keys refused by name, out-of-range values refused by name. Called from
// Render, Start and Preflight so the panel, the test and the operator all see
// the same refusal.
func checkParams(spec tunnel.Spec) error {
	mode := effectiveMode(spec)
	if mode == tunnel.ModeReverse {
		return fmt.Errorf("%w: udp2raw implements relay only (raw client/server pair); reverse was never tested",
			tunnel.ErrModeUnsupported)
	}
	for _, key := range tunnel.SortedParams(spec.Params) {
		if !toolParams[key] && !strings.HasPrefix(key, "pg_") {
			return fmt.Errorf("%w: udp2raw has no param %q (allowed: listen_host, peer, target, raw_mode, cipher_mode, auth_mode, auto_rule)",
				tunnel.ErrInvalidSpec, key)
		}
	}
	for _, key := range requiredParams[mode][spec.Side] {
		if strings.TrimSpace(spec.Params[key]) == "" {
			return fmt.Errorf("%w: mode=%s side=%s requires params.%s", tunnel.ErrInvalidSpec, mode, spec.Side, key)
		}
	}
	if err := checkAddress("peer", spec.Params[ParamPeer], requiredParams[mode][spec.Side]); err != nil {
		return err
	}
	if err := checkAddress("target", spec.Params[ParamTarget], requiredParams[mode][spec.Side]); err != nil {
		return err
	}
	if lp := listenPort(spec); spec.Params[tunnel.ParamListenPort] != "" && lp == 0 {
		return fmt.Errorf("%w: params.listen_port %q is not a port number", tunnel.ErrInvalidSpec, spec.Params[tunnel.ParamListenPort])
	}
	if host := strings.TrimSpace(spec.Params[ParamListenHost]); host != "" {
		if strings.ContainsAny(host, " \t\r\n:") {
			// udp2raw parses an IPv4 address and a port as two fields; a
			// colon in the host would swallow the port.
			return fmt.Errorf("%w: params.listen_host %q must be an IPv4 address without a port", tunnel.ErrInvalidSpec, host)
		}
	}
	if err := checkEnum(ParamRawMode, spec.Params[ParamRawMode], rawModes, "faketcp"); err != nil {
		return err
	}
	if err := checkEnum(ParamCipherMode, spec.Params[ParamCipherMode], cipherModes, "aes128cbc"); err != nil {
		return err
	}
	if err := checkEnum(ParamAuthMode, spec.Params[ParamAuthMode], authModes, "md5"); err != nil {
		return err
	}
	if v := strings.TrimSpace(spec.Params[ParamAutoRule]); v != "" {
		if _, err := strconv.ParseBool(v); err != nil {
			return fmt.Errorf("%w: params.auto_rule %q must be true or false", tunnel.ErrInvalidSpec, v)
		}
	}
	return nil
}

// checkAddress validates a "host:port" param when the side needs it; a value
// on a key the side does not use is still syntax-checked so a typo cannot sit
// unnoticed until the other side starts.
func checkAddress(name, value string, required []string) error {
	if strings.TrimSpace(value) == "" {
		if contains(required, name) {
			return fmt.Errorf("%w: params.%s is required", tunnel.ErrInvalidSpec, name)
		}
		return nil
	}
	host, port, err := net.SplitHostPort(strings.TrimSpace(value))
	if err != nil || host == "" {
		return fmt.Errorf("%w: params.%s %q must be host:port", tunnel.ErrInvalidSpec, name, value)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("%w: params.%s %q has no usable port", tunnel.ErrInvalidSpec, name, value)
	}
	return nil
}

func checkEnum(name, value string, allowed []string, fallback string) error {
	v := strings.TrimSpace(value)
	if v == "" {
		v = fallback
	}
	for _, a := range allowed {
		if v == a {
			return nil
		}
	}
	return fmt.Errorf("%w: params.%s %q is not supported (available: %s)",
		tunnel.ErrInvalidSpec, name, value, strings.Join(allowed, ", "))
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func param(spec tunnel.Spec, key, fallback string) string {
	if v := strings.TrimSpace(spec.Params[key]); v != "" {
		return v
	}
	return fallback
}

// listenPort is the port this side binds. The framework always hands
// Control = Listen+1 (CONTRACT §1.4), so one number is enough.
func listenPort(spec tunnel.Spec) int {
	p, err := strconv.Atoi(strings.TrimSpace(spec.Params[tunnel.ParamListenPort]))
	if err != nil || p < 0 || p > 65535 {
		return 0
	}
	return p
}

// rawMode is the effective faking mode ("" = faketcp, udp2raw's default).
func rawMode(spec tunnel.Spec) string {
	return param(spec, ParamRawMode, "faketcp")
}

// autoRule is the effective `-a` decision. Measured on the pinned build
// (20230206.0), two netns + veth:
//
//	faketcp / icmp      the kernel would answer udp2raw's forged packets itself,
//	                    so its DROP rules are required (and they work)
//	easy-faketcp        udp2raw prints "-a ... not supposed be used with
//	                    easyfaketcp mode" and the handshake then never
//	                    completes — no -a
//	udp                 plain UDP, no forging, nothing to suppress — no -a
//
// The explicit param wins over the default either way.
func autoRule(spec tunnel.Spec) bool {
	if v := strings.TrimSpace(spec.Params[ParamAutoRule]); v != "" {
		b, err := strconv.ParseBool(v)
		if err == nil {
			return b
		}
	}
	switch rawMode(spec) {
	case "faketcp", "icmp":
		return true
	default:
		return false
	}
}

// buildLines renders one side's udp2raw configuration file. Deterministic by
// construction: fixed line order, values from the Spec only, no clock, no
// I/O. The SAME spec — including Mode — is byte-identical every time, which is
// what makes a restart from config alone meaningful.
//
// The key IS part of the output: udp2raw cannot derive its cipher without it.
// Start is the only thing that writes the file, under the per-tunnel
// directory, mode 0600 (CONTRACT §2.1).
func buildLines(spec tunnel.Spec) ([]string, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if err := checkParams(spec); err != nil {
		return nil, err
	}
	key := strings.TrimSpace(spec.Secrets[SecretKey])
	if key == "" {
		return nil, fmt.Errorf("%w: udp2raw requires the %s secret (declare it and set the environment variable on the node)",
			tunnel.ErrSecretUnresolved, SecretKey)
	}
	if strings.ContainsAny(key, " \t\r\n") {
		// The configuration file is one option per line; a key with a space
		// would be read as a second token and silently truncated.
		return nil, fmt.Errorf("%w: %s must not contain whitespace", tunnel.ErrInvalidSpec, SecretKey)
	}

	host := param(spec, ParamListenHost, "0.0.0.0")
	lp := listenPort(spec)
	if lp == 0 {
		return nil, fmt.Errorf("%w: params.listen_port is required to render udp2raw's -l", tunnel.ErrInvalidSpec)
	}
	local := net.JoinHostPort(host, strconv.Itoa(lp))

	lines := []string{}
	switch spec.Side {
	case tunnel.SideA:
		// client: a local UDP listener applications send to, dialing side b's
		// raw-facing address.
		lines = append(lines, "-c", "-l "+local, "-r "+strings.TrimSpace(spec.Params[ParamPeer]))
	default:
		// server: a raw listener on -l, delivering to the UDP service at -r.
		lines = append(lines, "-s", "-l "+local, "-r "+strings.TrimSpace(spec.Params[ParamTarget]))
	}
	lines = append(lines,
		"-k "+key,
		"--raw-mode "+rawMode(spec),
		"--cipher-mode "+param(spec, ParamCipherMode, "aes128cbc"),
		"--auth-mode "+param(spec, ParamAuthMode, "md5"),
	)
	if autoRule(spec) {
		// --wait-lock: two sides of one tunnel may add their rules at the
		// same moment, and xtables holds one lock (iptables v1.4.20+).
		lines = append(lines, "-a", "--wait-lock")
	}
	lines = append(lines,
		// Level 4 (INFO) is udp2raw's default; --disable-color keeps the log
		// stream parseable. Never raise it here: DEBUG prints the key.
		"--log-level 4",
		"--disable-color",
	)
	return lines, nil
}
