package chisel

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/pasarguard/node/backend/tunnel"
)

const (
	// Tool is the registered adapter name (CONTRACT §2.1).
	Tool = "chisel"
	// Version is what Handle.Version reports: the pinned upstream release.
	Version = "chisel-1.12.0"
	// SecretAuth is the node-side secret name. Its value is "user:pass"; Start
	// hands it to the chisel process as chisel's own AUTH environment variable,
	// so the credential never lands on argv, in Render's output, or in a log
	// line (CONTRACT §2.1).
	SecretAuth = "CHISEL_AUTH"

	paramPeer        = "peer"         // "host:port" the other side listens on
	paramTarget      = "target"       // destination side B delivers to
	paramListenHost  = "listen_host"  // bind address, default 127.0.0.1
	paramPath        = "path"         // websocket path, default "/"
	paramHeader      = "header"       // optional "Name: Value" request header
	paramPublishPort = "publish_port" // reverse only: side A's published port
)

// requiredParams is what a side cannot work without, beyond the framework's
// own listen_port. Render and Preflight both use it, so a panel that is told
// "side b needs params.target" is told the same thing at start time.
func requiredParams(spec tunnel.Spec) []string {
	keys := []string{tunnel.ParamListenPort}
	ingress := spec.Side == tunnel.SideA
	if modeOf(spec) == tunnel.ModeReverse {
		// reverse: side A publishes, side B dials out and delivers.
		if ingress {
			return append(keys, paramPublishPort)
		}
		return append(keys, paramPeer, paramPublishPort, paramTarget)
	}
	if ingress {
		return append(keys, paramPeer)
	}
	return append(keys, paramTarget)
}

func modeOf(spec tunnel.Spec) string {
	if spec.Mode == "" {
		return tunnel.ModeRelay
	}
	return spec.Mode
}

func hostOf(spec tunnel.Spec) string {
	if h := strings.TrimSpace(spec.Params[paramListenHost]); h != "" {
		return h
	}
	return "127.0.0.1"
}

// dialHost is the address the local shims connect to for a rendezvous that
// lives on this side's own host. You cannot dial 0.0.0.0, so an all-interfaces
// bind is reached over loopback.
func dialHost(host string) string {
	switch host {
	case "0.0.0.0", "::", "[::]", "":
		return "127.0.0.1"
	}
	return host
}

func intParam(spec tunnel.Spec, key string) (int, error) {
	raw := strings.TrimSpace(spec.Params[key])
	if raw == "" {
		return 0, fmt.Errorf("chisel: params.%s is required for mode=%s side=%s", key, modeOf(spec), spec.Side)
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("chisel: params.%s must be a port number 1-65535, got %q", key, raw)
	}
	return n, nil
}

// wsPath normalises the websocket path. chisel dials whatever path the client
// URL carries; it must be a path, not a whole URL.
func wsPath(spec tunnel.Spec) (string, error) {
	p := spec.Params[paramPath]
	if p == "" {
		return "/", nil
	}
	if !strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("chisel: params.%s must start with \"/\", got %q", paramPath, p)
	}
	if strings.ContainsAny(p, " \t\r\n\x00") {
		return "", fmt.Errorf("chisel: params.%s must not contain whitespace or NUL", paramPath)
	}
	return p, nil
}

func headerOf(spec tunnel.Spec) (string, error) {
	h := strings.TrimSpace(spec.Params[paramHeader])
	if h == "" {
		return "", nil
	}
	if !strings.Contains(h, ":") {
		return "", fmt.Errorf("chisel: params.%s must be \"Name: Value\", got %q", paramHeader, h)
	}
	if strings.ContainsAny(h, "\r\n\x00") {
		return "", fmt.Errorf("chisel: params.%s must be a single line", paramHeader)
	}
	return h, nil
}

func splitAddr(key, value string) (string, int, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(value))
	if err != nil {
		return "", 0, fmt.Errorf("chisel: params.%s must be host:port, got %q", key, value)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", 0, fmt.Errorf("chisel: params.%s must be host:port with a port 1-65535, got %q", key, value)
	}
	return host, n, nil
}

// renderArgv is the whole configuration: chisel has no config file, only a
// command line. Pure — Params only, no Ports, no environment, no I/O — which
// is what makes two renders of one Spec byte-identical (CONTRACT §2.1).
//
// Every port below comes from params.listen_port (the panel pins it: the other
// side's `peer` is written from the same number) and its reserved partner
// listen+1. The published port of a reverse tunnel is a third bind on side A
// and comes from params.publish_port, never from an assumed free port.
func renderArgv(spec tunnel.Spec) ([]string, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	mode := modeOf(spec)
	if mode != tunnel.ModeRelay && mode != tunnel.ModeReverse {
		return nil, fmt.Errorf("%w: chisel has a loopback test for relay and reverse, not %q",
			tunnel.ErrModeUnsupported, mode)
	}
	for _, key := range requiredParams(spec) {
		if strings.TrimSpace(spec.Params[key]) == "" {
			return nil, fmt.Errorf("chisel: params.%s is required for mode=%s side=%s", key, mode, spec.Side)
		}
	}

	listen, err := intParam(spec, tunnel.ParamListenPort)
	if err != nil {
		return nil, err
	}
	if listen >= 65535 {
		return nil, fmt.Errorf("chisel: params.%s=%d leaves no room for its control port (listen+1)",
			tunnel.ParamListenPort, listen)
	}
	path, err := wsPath(spec)
	if err != nil {
		return nil, err
	}
	header, err := headerOf(spec)
	if err != nil {
		return nil, err
	}
	host := hostOf(spec)

	withHeader := func(argv []string) []string {
		if header != "" {
			argv = append(argv, "--header", header)
		}
		return argv
	}

	argv := []string{"chisel"}
	switch {
	case mode == tunnel.ModeRelay && spec.Side == tunnel.SideA:
		// Side A is the ingress: a local forward listener for clients, dials
		// side B's websocket. Side B's server then dials 127.0.0.1:<peer+1>,
		// which is side B's own egress shim.
		peerHost, peerPort, err := splitAddr(paramPeer, spec.Params[paramPeer])
		if err != nil {
			return nil, err
		}
		if peerPort >= 65535 {
			return nil, fmt.Errorf("chisel: params.%s=%d leaves no room for its control port (peer+1)",
				paramPeer, peerPort)
		}
		argv = append(argv, "client", "--verbose")
		argv = withHeader(argv)
		argv = append(argv,
			fmt.Sprintf("http://%s%s", net.JoinHostPort(peerHost, strconv.Itoa(peerPort)), path),
			// local = this side's control port, remote = dialled by side B's
			// server on side B's own host, hence 127.0.0.1.
			fmt.Sprintf("%s:%d:127.0.0.1:%d", host, listen+1, peerPort+1),
		)
	case mode == tunnel.ModeRelay && spec.Side == tunnel.SideB:
		argv = append(argv, "server", "--verbose", "--host", host, "--port", strconv.Itoa(listen))
	case mode == tunnel.ModeReverse && spec.Side == tunnel.SideA:
		// Side A is the server: the websocket sits on the control port, and
		// the published port (side B's reverse remote) is the third bind.
		publish, err := intParam(spec, paramPublishPort)
		if err != nil {
			return nil, err
		}
		if publish == listen || publish == listen+1 {
			return nil, fmt.Errorf("chisel: params.%s=%d collides with this side's port %d or its control port %d",
				paramPublishPort, publish, listen, listen+1)
		}
		argv = append(argv, "server", "--verbose", "--host", host, "--port", strconv.Itoa(listen+1), "--reverse")
	case mode == tunnel.ModeReverse && spec.Side == tunnel.SideB:
		// Side B dials out (it is the side behind NAT) and asks side A's
		// server to publish listen_host:publish_port back to this side's
		// egress shim on 127.0.0.1:<listen+1>.
		peerHost, peerPort, err := splitAddr(paramPeer, spec.Params[paramPeer])
		if err != nil {
			return nil, err
		}
		if peerPort >= 65535 {
			return nil, fmt.Errorf("chisel: params.%s=%d leaves no room for its control port (peer+1)",
				paramPeer, peerPort)
		}
		publish, err := intParam(spec, paramPublishPort)
		if err != nil {
			return nil, err
		}
		// In reverse the published port is bound on *side A* (see the port
		// table); side B binds only its ingress shim on listen+1, so listen
		// itself is free here. Refusing publish == listen would reject a
		// perfectly good loopback pair — the published port and this side's
		// unused listen number are not the same socket.
		if publish == listen+1 {
			return nil, fmt.Errorf("chisel: params.%s=%d collides with this side's ingress shim on port %d",
				paramPublishPort, publish, listen+1)
		}
		argv = append(argv, "client", "--verbose")
		argv = withHeader(argv)
		argv = append(argv,
			fmt.Sprintf("http://%s%s", net.JoinHostPort(peerHost, strconv.Itoa(peerPort+1)), path),
			fmt.Sprintf("R:%s:%d:127.0.0.1:%d", host, publish, listen+1),
		)
	}
	return argv, nil
}

// renderJSON is Render's output: the argv as a JSON array of strings. One
// argument per element means no quoting rules to disagree about, and two
// renders of one Spec marshal to the same bytes.
func renderJSON(spec tunnel.Spec) (string, error) {
	argv, err := renderArgv(spec)
	if err != nil {
		return "", err
	}
	out, err := json.Marshal(argv)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// authOf reads the credential from Secrets. chisel's own parser rejects an
// auth string without a username at server start, so refuse here, where the
// message can name the secret instead of quoting a chisel usage line.
func authOf(spec tunnel.Spec) (string, error) {
	value, ok := spec.Secrets[SecretAuth]
	if !ok || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("chisel: secret %s (value \"user:pass\") is not set — refusing to run unauthenticated",
			SecretAuth)
	}
	if strings.ContainsAny(value, "\r\n\x00") {
		return "", fmt.Errorf("chisel: secret %s contains a line break or NUL", SecretAuth)
	}
	user, _, found := strings.Cut(value, ":")
	if !found || user == "" {
		return "", fmt.Errorf("chisel: secret %s must be \"user:pass\", got a value without a username", SecretAuth)
	}
	return value, nil
}

// authEnv is the child process environment: the parent's, minus any AUTH the
// node process happens to carry, plus ours. chisel reads AUTH for both roles,
// so the credential stays out of argv (and therefore out of `ps`).
func authEnv(auth string) []string {
	parent := os.Environ()
	out := make([]string, 0, len(parent)+1)
	for _, kv := range parent {
		if strings.HasPrefix(kv, "AUTH=") {
			continue
		}
		out = append(out, kv)
	}
	return append(out, "AUTH="+auth)
}
