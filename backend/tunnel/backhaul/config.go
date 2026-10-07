// config.go — backhaul's parameter vocabulary, its validation, and the
// deterministic TOML render. Nothing here does I/O: Render is pure
// (CONTRACT §2.1), and the port tokens it leaves behind are filled in by
// Start, which is the first point at which the allocated ports exist.
package backhaul

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/pasarguard/node/backend/tunnel"
	"github.com/pasarguard/node/pkg/netutil"
)

// Params this adapter understands. Anything else in Spec.Params is refused by
// name rather than dropped: a typo that is silently ignored is a tunnel that
// comes up with the wrong knobs.
const (
	paramTarget     = "target"      // side a: what side b dials (host:port)
	paramPeer       = "peer"        // side b: side a's listen address (host:port)
	paramListenHost = "listen_host" // side a: bind address, default 127.0.0.1
	paramTransport  = "transport"   // both: tcp | tcpmux | ws | wsmux
	paramLogLevel   = "log_level"   // both: backhaul's own log level
	paramSkipOptz   = "skip_optz"   // both: default true, see skipOptz below
)

// knownParams is the refusal message's vocabulary, sorted.
var knownParams = []string{paramListenHost, paramLogLevel, paramPeer, paramSkipOptz, paramTarget, paramTransport}

// transports backhaul accepts without extra material. wss / wssmux need a TLS
// certificate pair on disk and are deliberately not offered: this adapter
// would have to own cert paths it has no way to provision. Only `tcp` has a
// passing loopback run; the rest are configuration, not claims.
var transports = []string{"tcp", "tcpmux", "ws", "wsmux"}

// logLevels is backhaul's own scale, verbatim from its README.
var logLevels = []string{"panic", "fatal", "error", "warn", "info", "debug", "trace"}

// Tokens Render leaves for Start. They are replaced with decimal port numbers
// only, so nothing a caller supplies can reach the file through them.
const (
	tokControl = "{{control_port}}"
	tokIngress = "{{ingress_port}}"
	tokShim    = "{{shim_port}}"
)

// knobs is Spec.Params after validation: every value checked against its
// vocabulary, every default already applied.
type knobs struct {
	target     string
	peer       string
	listenHost string
	transport  string
	logLevel   string
	skipOptz   string // "true" | "false", rendered unquoted as a TOML bool
}

// validate is everything Render needs and Preflight reports: the spec's own
// fields, then the mode, then this tool's parameters. It never looks at the
// host, so it behaves the same on every platform.
func validate(spec tunnel.Spec) (string, knobs, error) {
	if err := spec.Validate(); err != nil {
		return "", knobs{}, err
	}
	mode, err := resolveMode(spec.Mode)
	if err != nil {
		return "", knobs{}, err
	}
	k, err := knobsOf(spec)
	if err != nil {
		return "", knobs{}, err
	}
	return mode, k, nil
}

// prepare runs every check Start makes that does not depend on the host: the
// spec, the ports it was given, and the secret it was handed. A caller hears
// about its own mistake before this node's platform is even asked — that is
// what lets a malformed spec report itself on a Windows node instead of
// coming back as "no Windows asset".
func prepare(spec tunnel.Spec, ports tunnel.Ports) (string, knobs, error) {
	mode, k, err := validate(spec)
	if err != nil {
		return "", knobs{}, err
	}
	if ports.Listen < 1 || ports.Listen > 65535 {
		return "", knobs{}, fmt.Errorf("%w: backhaul needs a listen port, got %d", tunnel.ErrInvalidSpec, ports.Listen)
	}
	// Side b derives side a's transport address as peer+1 (Ports.Control is
	// always Listen+1, CONTRACT §2.1), so a Ports that breaks that invariant
	// would silently point the client at the wrong port.
	if ports.Control != ports.Listen+1 {
		return "", knobs{}, fmt.Errorf("%w: backhaul expects Control == Listen+1, got listen=%d control=%d",
			tunnel.ErrInvalidSpec, ports.Listen, ports.Control)
	}
	if err := checkToken(spec); err != nil {
		return "", knobs{}, err
	}
	return mode, k, nil
}

// errNoWindows is the platform refusal. Backhaul publishes no Windows asset
// at all (UPSTREAM.md), so there is nothing to pin, hash or exec — the
// message says that rather than leaving an operator to decode "not found".
func errNoWindows() error {
	return fmt.Errorf("%w: backhaul ships no Windows asset — Musixal/Backhaul %s publishes linux builds only, so a Windows node cannot run this tunnel (run it on a Linux node)",
		tunnel.ErrBinaryNotFound, Version)
}

// windowsProblem is the same fact as a Preflight entry, so the panel can show
// it before a start is attempted.
func windowsProblem() tunnel.Problem {
	return tunnel.Problem{
		Check:  "platform",
		Detail: fmt.Sprintf("backhaul %s has no Windows asset (Musixal/Backhaul publishes linux builds only)", Version),
		Fix:    "run this tunnel on a Linux node",
	}
}

// resolveMode maps Spec.Mode onto a mode this adapter implements. An empty
// value is the tool's default, which is `relay` — both modes have a passing
// loopback run, so neither is a guess (docs/multi/tunnels/backhaul.md).
func resolveMode(v string) (string, error) {
	switch v {
	case "":
		return tunnel.ModeRelay, nil
	case tunnel.ModeRelay, tunnel.ModeReverse:
		return v, nil
	}
	return "", fmt.Errorf("%w: backhaul implements %q and %q, got %q",
		tunnel.ErrModeUnsupported, tunnel.ModeRelay, tunnel.ModeReverse, v)
}

// checkToken: the transport token authenticates the tunnel, so Start refuses
// to bring one up without it rather than opening an unauthenticated relay.
// A value is only ever present after the Manager resolved it from the
// environment (CONTRACT §2.1), so this is where "no secret declared" lands.
func checkToken(spec tunnel.Spec) error {
	token := spec.Secrets[SecretToken]
	if token == "" {
		return fmt.Errorf("%w: declare %s in the tunnel's secret_names — backhaul refuses an unauthenticated tunnel",
			tunnel.ErrSecretUnresolved, SecretToken)
	}
	if strings.ContainsAny(token, "\r\n") {
		return fmt.Errorf("%w: %s must not contain a line break", tunnel.ErrSecretUnresolved, SecretToken)
	}
	return nil
}

// knobsOf validates Spec.Params and applies defaults.
func knobsOf(spec tunnel.Spec) (knobs, error) {
	k := knobs{
		listenHost: "127.0.0.1",
		transport:  "tcp",
		logLevel:   "info",
		// skip_optz defaults to true: backhaul's own default runs
		// sysctl writes (rmem_max / wmem_max) as root on the node, which is
		// a host-wide change no tunnel adapter should make silently. An
		// operator who wants the tuning sets params.skip_optz = "false".
		skipOptz: "true",
	}
	for _, key := range tunnel.SortedParams(spec.Params) {
		value := spec.Params[key]
		switch key {
		case tunnel.ParamConfigDir, tunnel.ParamBinaryPath, tunnel.ParamListenPort:
			continue // framework-owned, not a backhaul knob
		case paramTarget:
			k.target = value
		case paramPeer:
			k.peer = value
		case paramListenHost:
			if value != "" {
				k.listenHost = value
			}
		case paramTransport:
			if value != "" {
				k.transport = value
			}
		case paramLogLevel:
			if value != "" {
				k.logLevel = value
			}
		case paramSkipOptz:
			if value != "" {
				k.skipOptz = value
			}
		default:
			return k, paramErr(key, fmt.Sprintf("not a backhaul parameter (known: %s)", strings.Join(knownParams, ", ")))
		}
	}

	if err := checkOne(paramTransport, k.transport, transports); err != nil {
		return k, err
	}
	if err := checkOne(paramLogLevel, k.logLevel, logLevels); err != nil {
		return k, err
	}
	if _, err := strconv.ParseBool(k.skipOptz); err != nil {
		return k, paramErr(paramSkipOptz, fmt.Sprintf("%q is not a boolean (true|false)", k.skipOptz))
	} else if k.skipOptz == "1" || k.skipOptz == "t" || k.skipOptz == "T" {
		k.skipOptz = "true"
	} else if k.skipOptz == "0" || k.skipOptz == "f" || k.skipOptz == "F" {
		k.skipOptz = "false"
	}
	if err := checkHost(k.listenHost); err != nil {
		return k, paramErr(paramListenHost, err.Error())
	}
	// Normalise to the bare form: net.JoinHostPort adds the brackets an IPv6
	// literal needs, and would double them if they arrived already present.
	k.listenHost = strings.TrimSuffix(strings.TrimPrefix(k.listenHost, "["), "]")
	if k.listenHost == "" {
		return k, paramErr(paramListenHost, "must not be empty")
	}

	// Side a cannot render a published port without a destination; side b
	// cannot dial the tunnel without side a's address. Both are refused here
	// so Preflight says it too.
	if k.target == "" && spec.Side == tunnel.SideA {
		return k, paramErr(paramTarget, "side a needs the address side b dials (host:port)")
	}
	if k.peer == "" && spec.Side == tunnel.SideB {
		return k, paramErr(paramPeer, "side b needs side a's listen address (host:port)")
	}
	if k.target != "" {
		if err := checkAddr(k.target); err != nil {
			return k, paramErr(paramTarget, err.Error())
		}
	}
	if k.peer != "" {
		if err := checkAddr(k.peer); err != nil {
			return k, paramErr(paramPeer, err.Error())
		}
	}
	return k, nil
}

// paramErr keeps every parameter refusal on one shape — an ErrInvalidSpec the
// RPC layer maps to InvalidArgument, naming the key an operator has to fix.
func paramErr(key, why string) error {
	return fmt.Errorf("%w: backhaul params.%s: %s", tunnel.ErrInvalidSpec, key, why)
}

func checkOne(key, value string, allowed []string) error {
	for _, a := range allowed {
		if value == a {
			return nil
		}
	}
	return paramErr(key, fmt.Sprintf("%q is not supported (want one of: %s)", value, strings.Join(allowed, ", ")))
}

// addrChars is the address charset. It is a trust-boundary check: these
// values are written into a TOML string, so a quote, a brace or a newline has
// no business being here — `net.SplitHostPort` alone would happily accept
// `a"b:80`.
const addrChars = "0123456789abcdefABCDEF.:%-_[]"

func checkAddr(v string) error {
	host, port, err := net.SplitHostPort(v)
	if err != nil {
		return fmt.Errorf("%q must be host:port", v)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("%q has no valid port", v)
	}
	if err := checkCharset(host); err != nil {
		return err
	}
	return nil
}

// checkHost allows the same charset as an address without the port: a host
// name, an IPv4 literal, or an IPv6 literal (bare or bracketed — knobsOf
// normalises the brackets before net.JoinHostPort sees it).
func checkHost(v string) error {
	return checkCharset(v)
}

func checkCharset(v string) error {
	for _, r := range v {
		if !strings.ContainsRune(addrChars, r) {
			return fmt.Errorf("%q contains %q, which an address cannot", v, string(r))
		}
	}
	return nil
}

// transportAddr is side b's dial target: side a's transport, which the
// framework always keeps at Listen+1 (Ports.Control) and the panel writes
// into `peer` as side a's listen address.
func transportAddr(peer string) (string, error) {
	host, port, err := net.SplitHostPort(peer)
	if err != nil {
		return "", fmt.Errorf("params.%s: %q must be host:port", paramPeer, peer)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65534 {
		return "", fmt.Errorf("params.%s: %q has no port whose successor is one", paramPeer, peer)
	}
	return net.JoinHostPort(host, strconv.Itoa(n+1)), nil
}

// pickPort returns a free port for backhaul's own ingress listener, which the
// framework does not allocate: side a owns Ports.Listen (its published
// ingress, fronted by the counting proxy) and Ports.Control (the transport),
// so backhaul's raw listener needs a third port that only side a knows about.
//
// ponytail: netutil.FindFreePort bind-tests but does not reserve, the same
// rule CONTRACT §1.4 gives every core. Manager.startMu serialises Starts, and
// the port is held by backhaul itself a moment after this returns; an
// operator running two nodes on one host should give each its own allocator.
func pickPort(skip ...int) (int, error) {
	for tries := 0; tries < 64; tries++ {
		p := netutil.FindFreePort()
		if p < 1024 || p > 65535 {
			continue
		}
		taken := false
		for _, s := range skip {
			if p == s {
				taken = true
				break
			}
		}
		if !taken {
			return p, nil
		}
	}
	return 0, fmt.Errorf("backhaul: no free port left for the ingress listener")
}

// renderConfig builds this side's TOML. Deterministic by construction: fixed
// key order, values in a fixed order, no map iteration (CONTRACT §2.1).
func renderConfig(spec tunnel.Spec, mode string, k knobs, token string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# PasarGuard backhaul config — tunnel=%s side=%s mode=%s\n", spec.TunnelID, spec.Side, mode)
	b.WriteString("# TOML, for `backhaul -c`. Render is pure (CONTRACT §2.1): the {{*_port}}\n")
	b.WriteString("# tokens are replaced by Start with this side's allocated ports.\n")

	if spec.Side == tunnel.SideA {
		b.WriteString("\n[server]\n")
		fmt.Fprintf(&b, "bind_addr = %s\n", tomlString(net.JoinHostPort(k.listenHost, tokControl)))
		fmt.Fprintf(&b, "transport = %s\n", tomlString(k.transport))
		fmt.Fprintf(&b, "token = %s\n", tomlString(token))
		// Bound on loopback: only side a's own proxy reaches it, so the
		// published ingress is the only public listener backhaul opens.
		fmt.Fprintf(&b, "ports = [%s]\n", tomlString("127.0.0.1:"+tokIngress+"="+k.target))
	} else {
		b.WriteString("\n[client]\n")
		fmt.Fprintf(&b, "remote_addr = %s\n", tomlString(net.JoinHostPort("127.0.0.1", tokShim)))
		fmt.Fprintf(&b, "transport = %s\n", tomlString(k.transport))
		fmt.Fprintf(&b, "token = %s\n", tomlString(token))
	}

	fmt.Fprintf(&b, "log_level = %s\n", tomlString(k.logLevel))
	// web_port is set explicitly rather than left to the default: the
	// monitoring UI is a second listener this adapter never asked for, and
	// two sides of one tunnel would fight over a fixed default port.
	b.WriteString("web_port = 0\n")
	b.WriteString("sniffer = false\n")
	fmt.Fprintf(&b, "skip_optz = %s\n", k.skipOptz)
	return b.String()
}

// tomlString quotes s as a TOML basic string. Go's strconv.Quote is close but
// emits \xNN escapes, which TOML does not have, so the handful of escapes
// TOML does define are written out here. This is the last line of defence
// for the one value in the file that is not validated against a vocabulary —
// the token, which comes from the environment.
func tomlString(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\u%04X`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// substPorts replaces the render's port tokens. Only decimal digits are ever
// written, and only for tokens that are present.
func substPorts(config string, ports map[string]int) string {
	for tok, value := range ports {
		config = strings.ReplaceAll(config, tok, strconv.Itoa(value))
	}
	return config
}

// ansiRe strips the colour codes backhaul writes even when stdout is not a
// terminal — the log ring and the panel are text, not a shell.
var ansiRe = regexp.MustCompile("\x1b\\[[0-9;]*m")

func stripANSI(s string) string { return ansiRe.ReplaceAllString(s, "") }

// classify maps backhaul's own level tags onto the node's vocabulary
// (node/logger/logger.go). It reports what the tool said, never an upgrade of
// a WARNING into an Error.
func classify(line string) string {
	switch {
	case strings.Contains(line, "[FATAL]"), strings.Contains(line, "[CRITICAL]"):
		return "Critical"
	case strings.Contains(line, "[ERROR]"):
		return "Error"
	case strings.Contains(line, "[WARNING]"):
		return "Warning"
	case strings.Contains(line, "[DEBUG]"), strings.Contains(line, "[TRACE]"):
		return "Debug"
	}
	return "Info"
}
