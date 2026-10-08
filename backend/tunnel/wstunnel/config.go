// Package wstunnel runs erebe/wstunnel v11 as a Phase 3 tunnel adapter
// (CONTRACT §2). Upstream is BSD-3-Clause, so it stays a separate pinned
// binary and is never vendored: the licence boundary is the process edge.
//
// wstunnel v11 is a two-subcommand tool (`client` / `server`), so one tunnel
// is two different command lines:
//
//	mode=relay   side a = client (binds the ingress locally, dials the server)
//	             side b = server (accepts the WebSocket, dials the destination)
//	mode=reverse side a = server (the service is published here)
//	             side b = client (dials out from behind NAT with -R)
//
// Every side also runs the counting proxy in wstunnel.go: it binds the side's
// Ports.Listen and forwards to the port wstunnel itself binds, because
// Handle.Stats must report real up/down bytes and a subprocess reports none.
package wstunnel

import (
	_ "embed"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/pasarguard/node/backend/tunnel"
)

//go:embed pins.json
var pinsJSON []byte

const (
	// Tool is the registered adapter name.
	Tool = "wstunnel"
	// Version is the pin's version. The binary is hash-verified against that
	// same pin before it is exec'd, so pin version == running version.
	Version = "11.0.0"
	// SecretToken is the shared WebSocket upgrade path prefix — wstunnel v11's
	// built-in client credential (`client -P` / `server -r`). It is required,
	// not optional: a plain-ws server with no prefix restriction is an open
	// relay, and the adapter refuses to start without it (the same standard as
	// ErrSecretUnresolved — never run unauthenticated).
	SecretToken = "WSTUNNEL_TOKEN"

	paramListenHost = "listen_host" // bind address, default 127.0.0.1
	paramPeer       = "peer"        // host:port (role-dependent, see newPlan)
	paramTarget     = "target"      // host:port the payload is delivered to
	paramRestrictTo = "restrict_to" // relay server: comma-separated dest allowlist
	paramTransport  = "transport"   // ws (default) | wss
	paramTLSCert    = "tls_cert"    // server: PEM certificate for wss
	paramTLSKey     = "tls_key"     // server: PEM private key for wss

	// extraInner is the allocator Extra name reverse side a needs: the port
	// wstunnel's own WebSocket listener binds while Ports.Control stays the
	// public entry (the counting proxy sits in front of it).
	extraInner = "inner"

	// secretPlaceholder is what Render prints instead of the token: the value
	// is read from the environment at Start and never reaches disk.
	secretPlaceholder = "${" + SecretToken + "}"
)

// init registers the adapter and its pin (CONTRACT §2.1).
func init() {
	tunnel.Register(Tool, Adapter{})
	if err := tunnel.RegisterPinJSON(pinsJSON, "pins.json"); err != nil {
		panic("wstunnel: pins.json: " + err.Error())
	}
}

// role is which wstunnel subcommand a (mode, side) pair runs.
func role(mode string, side tunnel.Side) (string, error) {
	switch mode {
	case tunnel.ModeRelay:
		if side == tunnel.SideA {
			return "client", nil
		}
		return "server", nil
	case tunnel.ModeReverse:
		if side == tunnel.SideA {
			return "server", nil
		}
		return "client", nil
	}
	return "", fmt.Errorf("%w: wstunnel has a loopback test for relay and reverse only, not %q",
		tunnel.ErrModeUnsupported, mode)
}

// plan is one side, fully resolved: what binds where, which subcommand runs,
// and every argument it will be given. Render and Start build it through the
// same constructor, so the config an operator reads is the config that runs.
type plan struct {
	mode string
	side tunnel.Side
	role string
	host string
	// Ports stay 0 until Start hands Ports over; a 0 renders as {{name}}.
	listen  int
	control int
	inner   int

	peerHost  string   // relay a / reverse b: the far side's host
	peerPort  int      // its port; in reverse, +1 is its WebSocket entry
	peer      string   // peerHost:peerPort, as the operator wrote it
	target    string   // relay a (resolved by the server) / reverse b (dialled)
	restrict  []string // relay server: destinations it will dial for a client
	transport string   // ws | wss
	cert      string
	key       string
}

// newPlan validates a Spec and resolves it into one side's runtime shape.
//
// Render, Start and Preflight all call it, so a knob refused here is refused
// in all three places. It does I/O in exactly one spot — os.Stat on the TLS
// material — because a missing certificate has to fail at Render rather than
// at the first connection.
func newPlan(spec tunnel.Spec, ports tunnel.Ports) (*plan, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	mode := spec.Mode
	if mode == "" {
		mode = tunnel.ModeRelay
	}
	r, err := role(mode, spec.Side)
	if err != nil {
		return nil, err
	}

	host := strings.TrimSpace(spec.Params[paramListenHost])
	if host == "" {
		// Loopback by default: a tunnel that must accept remote peers says so
		// explicitly. Failing closed beats silently binding the world.
		host = "127.0.0.1"
	}
	p := &plan{mode: mode, side: spec.Side, role: r, host: host, transport: "ws"}
	if v := strings.TrimSpace(spec.Params[paramTransport]); v != "" {
		p.transport = strings.ToLower(v)
	}
	switch p.transport {
	case "ws", "wss":
	default:
		return nil, fmt.Errorf("%w: params.%s %q must be ws or wss", tunnel.ErrInvalidSpec, paramTransport, p.transport)
	}

	// Ports. Render has none unless the panel pinned listen_port
	// (CONTRACT ParamListenPort); Control is always Listen+1, and inner only
	// ever comes from the allocator's Extra.
	if v := strings.TrimSpace(spec.Params[tunnel.ParamListenPort]); v != "" {
		n, aerr := strconv.Atoi(v)
		if aerr != nil || n <= 0 || n > 65534 {
			return nil, fmt.Errorf("%w: %s %q is not a port", tunnel.ErrInvalidSpec, tunnel.ParamListenPort, v)
		}
		p.listen, p.control = n, n+1
	}
	if ports.Listen != 0 {
		p.listen, p.control = ports.Listen, ports.Control
	}
	if ports.Extra != nil {
		p.inner = ports.Extra[extraInner]
	}
	if mode == tunnel.ModeReverse && spec.Side == tunnel.SideA && p.inner == 0 && p.listen != 0 {
		// ponytail: the RPC layer allocates Listen+Control only, so the
		// websocket entry the counting proxy dials derives Listen+2 — the
		// same trade frp's tap makes for its own extra port. A guaranteed-
		// free third port would need AllocPair plumbed through the RPC
		// surface (a CONTRACT §2.1 change); until then +2 is operator-visible
		// and documented in docs/multi/tunnels/wstunnel.md.
		p.inner = p.listen + 2
	}

	// What this side dials, and what the payload is delivered to.
	needPeer := (mode == tunnel.ModeRelay && spec.Side == tunnel.SideA) ||
		(mode == tunnel.ModeReverse && spec.Side == tunnel.SideB)
	needTarget := (mode == tunnel.ModeRelay && spec.Side == tunnel.SideA) ||
		(mode == tunnel.ModeReverse && spec.Side == tunnel.SideB)

	if p.peer, err = requiredHostPort(spec.Params, paramPeer, needPeer); err != nil {
		return nil, err
	}
	if p.peer != "" {
		host, port, _ := net.SplitHostPort(p.peer)
		p.peerHost, p.peerPort = host, portNum(port)
	}
	if p.target, err = requiredHostPort(spec.Params, paramTarget, needTarget); err != nil {
		return nil, err
	}

	if p.restrict, err = restrictList(spec.Params[paramRestrictTo]); err != nil {
		return nil, err
	}
	// restrict_to is where the SERVER dials: only relay's side b dials a
	// destination on a client's behalf. Silently ignoring it in the other
	// three shapes would let an operator believe a restriction is active.
	if len(p.restrict) > 0 && !(mode == tunnel.ModeRelay && spec.Side == tunnel.SideB) {
		return nil, fmt.Errorf("%w: params.%s only applies to mode=relay side=b (the side that dials the destination); %s=%q is not enforced in mode=%s side=%s",
			tunnel.ErrInvalidSpec, paramRestrictTo, paramRestrictTo, spec.Params[paramRestrictTo], mode, spec.Side)
	}
	// A server bound past loopback with no destination allowlist and no TLS is
	// an open relay for anyone holding the token. Refuse (scope: "default the
	// configuration to something safe, or refuse to start").
	if spec.Side == tunnel.SideB && mode == tunnel.ModeRelay && !isLoopback(host) && len(p.restrict) == 0 {
		return nil, fmt.Errorf("%w: mode=relay side=b bound to %s without params.%s would be an open relay — set %s (comma-separated host:port), or bind 127.0.0.1",
			tunnel.ErrInvalidSpec, host, paramRestrictTo, paramRestrictTo)
	}

	if err := p.checkTLS(spec.Params); err != nil {
		return nil, err
	}
	return p, nil
}

// requiredHostPort reads and validates a host:port param.
func requiredHostPort(params map[string]string, key string, required bool) (string, error) {
	v := strings.TrimSpace(params[key])
	if v == "" {
		if required {
			return "", fmt.Errorf("%w: params.%s (host:port) is required", tunnel.ErrInvalidSpec, key)
		}
		return "", nil
	}
	if _, _, err := net.SplitHostPort(v); err != nil {
		return "", fmt.Errorf("%w: params.%s %q must be host:port (%v)", tunnel.ErrInvalidSpec, key, v, err)
	}
	return v, nil
}

func restrictList(raw string) ([]string, error) {
	var out []string
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(item); err != nil {
			return nil, fmt.Errorf("%w: params.%s entry %q must be host:port", tunnel.ErrInvalidSpec, paramRestrictTo, item)
		}
		out = append(out, item)
	}
	return out, nil
}

func portNum(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// checkTLS validates the wss material. Both halves are required together, and
// the files must already exist when this side is the server: an absent cert
// is a Render-time error, never a first-connection surprise.
func (p *plan) checkTLS(params map[string]string) error {
	p.cert = strings.TrimSpace(params[paramTLSCert])
	p.key = strings.TrimSpace(params[paramTLSKey])
	if p.transport != "wss" {
		if p.cert != "" || p.key != "" {
			return fmt.Errorf("%w: %s/%s are set but params.%s is %q — use transport=wss",
				tunnel.ErrInvalidSpec, paramTLSCert, paramTLSKey, paramTransport, p.transport)
		}
		return nil
	}
	if p.role == "server" {
		if p.cert == "" || p.key == "" {
			return fmt.Errorf("%w: transport=wss on the server needs both params.%s and params.%s",
				tunnel.ErrInvalidSpec, paramTLSCert, paramTLSKey)
		}
		for _, f := range []string{p.cert, p.key} {
			if _, err := os.Stat(f); err != nil {
				return fmt.Errorf("%w: TLS material %q is not readable: %v", tunnel.ErrInvalidSpec, f, err)
			}
		}
	} else if p.cert != "" || p.key != "" {
		// mTLS client certificates are a real v11 feature but an untested one
		// here; refusing beats accepting a knob nothing has ever run.
		return fmt.Errorf("%w: params.%s/%s (mTLS client certificate) is not supported by this adapter",
			tunnel.ErrInvalidSpec, paramTLSCert, paramTLSKey)
	}
	return nil
}

func (p *plan) portStr(n int, name string) string {
	if n <= 0 {
		return "{{" + name + "}}"
	}
	return strconv.Itoa(n)
}

func (p *plan) bindURL(port int, name string) string {
	return p.transport + "://" + net.JoinHostPort(p.host, p.portStr(port, name))
}

// args is the exact argv for this side. token is the resolved secret at Start
// and the ${WSTUNNEL_TOKEN} placeholder in Render, which is what keeps the
// secret out of Render's output (CONTRACT §2.1).
func (p *plan) args(token string) []string {
	if p.role == "server" {
		// On reverse side a the counting proxy already owns Ports.Control
		// (proxyBind), so wstunnel's own WebSocket entry has to be the extra
		// inner port. Binding control here as well makes the process abort on
		// startup with "Failed to bind to socket" — both sides fought over it.
		bind, name := p.control, "control_port"
		if p.mode == tunnel.ModeReverse && p.side == tunnel.SideA {
			bind, name = p.inner, "inner_port"
		}
		out := []string{"server", p.bindURL(bind, name), "-r", token}
		for _, d := range p.restrict {
			out = append(out, "--restrict-to", d)
		}
		if p.transport == "wss" {
			out = append(out, "--tls-certificate", p.cert, "--tls-private-key", p.key)
		}
		return append(out, "--no-color")
	}

	// client: p.peer is the far side's address, required and already parsed.
	peerURL := p.transport + "://" + p.peer
	if p.mode == tunnel.ModeRelay {
		// side a binds the ingress locally and hands the destination to the
		// server (wstunnel resolves HOST:PORT on the server's side).
		return []string{"client", peerURL, "-L",
			"tcp://" + net.JoinHostPort(p.host, p.portStr(p.control, "control_port")) + ":" + p.target,
			"-P", token, "--no-color"}
	}
	// reverse side b: p.peer is the address side a PUBLISHES; side a's
	// WebSocket entry is the next port (Control == Listen+1), and the payload
	// goes out through this side's own counting proxy.
	return []string{"client",
		p.transport + "://" + net.JoinHostPort(p.peerHost, p.portStr(p.peerPort+1, "peer_port")),
		"-R", "tcp://" + p.peer + ":" + net.JoinHostPort(p.host, p.portStr(p.listen, "listen_port")),
		"-P", token, "--no-color"}
}

// renderConfig is Render's output: comments naming the shape, then the exact
// command line with the token and any unknown port left as a placeholder.
func (p *plan) renderConfig(version string) string {
	if version == "" {
		version = Version
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# wstunnel %s - mode=%s side=%s role=%s\n", version, p.mode, p.side, p.role)
	b.WriteString("# secrets are read from the environment at Start and are never rendered\n")
	b.WriteString("wstunnel " + shellJoin(p.args(secretPlaceholder)) + "\n")
	return b.String()
}

// shellJoin renders argv as one line, quoting anything that needs it so a
// path with spaces (the usual Windows case) survives the round trip.
func shellJoin(args []string) string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if a == "" || strings.ContainsAny(a, " \t\"'") {
			out = append(out, strconv.Quote(a))
			continue
		}
		out = append(out, a)
	}
	return strings.Join(out, " ")
}
