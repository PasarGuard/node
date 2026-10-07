package rathole

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/pasarguard/node/backend/tunnel"
)

// The tool's Params, and the two rules that keep Render honest:
//
//  1. every key is listed here — an unknown key fails Render naming it, so a
//     typo can never become a config rathole starts and silently ignores;
//  2. a key that belongs to the other side fails the same way, so side a can
//     never grow a `remote_addr` nobody reads.
const (
	paramListenHost  = "listen_host"  // both: the address this side's counting tap binds
	paramControlHost = "control_host" // side a: where rathole's server accepts clients
	paramRemoteAddr  = "remote_addr"  // side b: the server's control address (host:port)
	paramTarget      = "target"       // side b: where tunneled bytes are delivered
	paramService     = "service_name" // both: rathole service name; must match on both ends
)

// defaultService is the rathole service name when the spec does not pick one.
// One tunnel is one service, so a constant keeps two configs comparable.
const defaultService = "tunnel"

// frameworkKeys are the Manager's and the panel's own Params: read by the
// framework, never tool knobs, never an "unknown key" for a tool to reject.
func isFrameworkKey(k string) bool {
	return k == tunnel.ParamConfigDir || k == tunnel.ParamBinaryPath || k == tunnel.ParamListenPort
}

// sideParams lists what each side accepts, in a stable order for error text.
var sideParams = map[tunnel.Side][]string{
	tunnel.SideA: {paramListenHost, paramControlHost, paramService},
	tunnel.SideB: {paramListenHost, paramRemoteAddr, paramTarget, paramService},
}

// checkParams is Render's and Preflight's shared validation.
func checkParams(spec tunnel.Spec) error {
	for _, k := range tunnel.SortedParams(spec.Params) {
		if isFrameworkKey(k) {
			continue
		}
		if !allowedOn(spec.Side, k) {
			return fmt.Errorf("rathole: param %q is not a rathole param (side a accepts: %s; side b accepts: %s)",
				k, strings.Join(sideParams[tunnel.SideA], ", "), strings.Join(sideParams[tunnel.SideB], ", "))
		}
	}
	if spec.Side == tunnel.SideB {
		if strings.TrimSpace(spec.Params[paramRemoteAddr]) == "" {
			return fmt.Errorf("rathole: side b needs params.%s (the server's control address, host:port)", paramRemoteAddr)
		}
		if strings.TrimSpace(spec.Params[paramTarget]) == "" {
			return fmt.Errorf("rathole: side b needs params.%s (where tunneled bytes are delivered)", paramTarget)
		}
	}
	if name := spec.Params[paramService]; name != "" && !bareTOMLKey(name) {
		return fmt.Errorf("rathole: params.%s %q must be a bare TOML key ([A-Za-z0-9_-]), because rathole reads it as [*.services.%s]",
			paramService, name, name)
	}
	return nil
}

// allowedOn reports whether a key belongs to rathole at all — either side.
//
// The panel sends ONE params map to both sides (TunnelSpec), so side A
// inevitably carries `remote_addr`/`target`, the keys side B renders with.
// Refusing them made rathole the one tool that could never be started from
// the panel. A key no side declares is still refused by name, which is the
// typo check this table exists for; each side's own *requirements* (above)
// are unchanged.
func allowedOn(side tunnel.Side, key string) bool {
	if hasKey(sideParams[side], key) {
		return true
	}
	other, known := otherSide[side]
	if !known {
		return false // an unknown side has no partner to borrow keys from
	}
	return hasKey(sideParams[other], key)
}

// otherSide is the pair of sides that share one params map.
var otherSide = map[tunnel.Side]tunnel.Side{
	tunnel.SideA: tunnel.SideB,
	tunnel.SideB: tunnel.SideA,
}

func hasKey(keys []string, key string) bool {
	for _, k := range keys {
		if k == key {
			return true
		}
	}
	return false
}

func bareTOMLKey(v string) bool {
	if v == "" || len(v) > 64 {
		return false
	}
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}

// listenPortOf reads the port this side binds. Render is pure and has no
// Ports, so the allocated port arrives as Params["listen_port"]: the Manager's
// Start injects it from Ports.Listen, the panel may pin it itself. Absent
// means unassigned (0) — which only ever happens in a render nobody runs.
func listenPortOf(spec tunnel.Spec) (int, error) {
	raw := strings.TrimSpace(spec.Params[tunnel.ParamListenPort])
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("rathole: %s must be a port number 1-65535, got %q", tunnel.ParamListenPort, raw)
	}
	return n, nil
}

// modeOf is the spec's mode with the tool's default filled in. rathole's only
// data path is the one CONTRACT §2.0 calls reverse: side b dials out to side
// a, and the service is published on side a (CONTRACT §2.0).
func modeOf(spec tunnel.Spec) string {
	if spec.Mode == "" {
		return tunnel.ModeReverse
	}
	return spec.Mode
}

// checkMode is the single refusal point Render and Start share, so a caller
// that skips Render gets the same answer (CONTRACT §2.0: refuse, never fall
// through to a default).
func checkMode(spec tunnel.Spec) error {
	if modeOf(spec) != tunnel.ModeReverse {
		return fmt.Errorf("%w: rathole has only a passing loopback test for mode=%s, not %q (rathole's client always dials the server)",
			tunnel.ErrModeUnsupported, tunnel.ModeReverse, spec.Mode)
	}
	return nil
}

// renderConfig builds one side's config.toml. Deterministic by construction:
// no clock, no randomness, no map iteration (SortedParams), and every value
// goes through the same TOML quoting.
func renderConfig(spec tunnel.Spec) (string, error) {
	listen, err := listenPortOf(spec)
	if err != nil {
		return "", err
	}
	service := spec.Params[paramService]
	if service == "" {
		service = defaultService
	}
	token, err := tomlQuote(spec.Secrets[SecretToken])
	if err != nil {
		return "", fmt.Errorf("rathole: %s: %w", SecretToken, err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# rathole %s config (mode=reverse) — generated by PasarGuard for tunnel %q\n",
		sideLabel(spec.Side), spec.TunnelID)
	fmt.Fprintf(&b, "# rathole v%s; transport=tcp: the token authenticates, it does not encrypt.\n", Version)
	fmt.Fprintf(&b, "# params: listen_host=%q control_host=%q remote_addr=%q target=%q service_name=%q\n",
		spec.Params[paramListenHost], spec.Params[paramControlHost],
		spec.Params[paramRemoteAddr], spec.Params[paramTarget], service)

	if spec.Side == tunnel.SideA {
		control := spec.Params[paramControlHost]
		if control == "" {
			control = defaultLoopback
		}
		// Control is Ports.Listen+1 by the framework's pair rule; 0 means the
		// port was never assigned, which only a render nobody runs can have.
		controlPort := 0
		if listen > 0 {
			controlPort = listen + 1
		}
		bind, err := tomlQuote(net.JoinHostPort(control, strconv.Itoa(controlPort)))
		if err != nil {
			return "", err
		}
		// The service binds IPv6 loopback because this node's counting tap
		// owns <listen_host>:listen — rathole's listener and the tap cannot
		// share an address, and a second framework port does not exist.
		serviceBind, err := tomlQuote(fmt.Sprintf("[::1]:%d", listen))
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "\n[server]\nbind_addr = %s\ndefault_token = %s\n", bind, token)
		fmt.Fprintf(&b, "\n[server.services.%s]\nbind_addr = %s\n", service, serviceBind)
		return b.String(), nil
	}

	remote, err := tomlQuote(spec.Params[paramRemoteAddr])
	if err != nil {
		return "", err
	}
	tapHost := spec.Params[paramListenHost]
	if tapHost == "" {
		tapHost = defaultLoopback
	}
	local, err := tomlQuote(net.JoinHostPort(tapHost, strconv.Itoa(listen)))
	if err != nil {
		return "", err
	}
	fmt.Fprintf(&b, "\n[client]\nremote_addr = %s\ndefault_token = %s\n", remote, token)
	fmt.Fprintf(&b, "\n[client.services.%s]\nlocal_addr = %s\n", service, local)
	return b.String(), nil
}

func sideLabel(side tunnel.Side) string {
	if side == tunnel.SideB {
		return "client"
	}
	return "server"
}

// defaultLoopback is the fail-closed bind address: a tunnel that must accept
// remote peers says so with an explicit param instead of binding the world.
const defaultLoopback = "127.0.0.1"

// tomlQuote renders a basic TOML string. Control characters are refused rather
// than half-escaped: a config line an operator cannot read is worse than a
// Start that says which value broke it.
func tomlQuote(v string) (string, error) {
	if strings.ContainsAny(v, "\n\r\t") || strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", fmt.Errorf("value %q contains a control character", v)
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"`, nil
}
