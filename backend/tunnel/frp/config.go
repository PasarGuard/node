// frp's configuration: the params a Spec carries, the TOML each side runs,
// and the validation that rejects a config nobody can use.
//
// Config format: TOML (frpc.toml / frps.toml) — frp's own default since 0.61
// and what the release tarball ships as its example files. The .ini form is
// legacy and is not generated here.
//
// Three ports belong to one frp tunnel and only two of them are the
// framework's pair (CONTRACT §1.4: Listen and Listen+1):
//
//	listen_port     side a's ingress — our counting relay binds it, clients dial it
//	listen_port+1   frps bindPort — the framework's Control port, frpc dials it
//	listen_port+2   frps proxy listener (loopback) — the relay's upstream
//
// The third one is derived, not allocated: the RPC layer hands out Listen and
// Control only (controller/rpc/tunnel.go portsForTunnel). It is bind-tested
// before frps is launched, and a busy port is a named Start error.
package frp

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/pasarguard/node/backend/tunnel"
)

// Params (the tunnel row's `params` JSON, shared by both sides).
const (
	paramListenHost = "listen_host" // side a: where the ingress relay binds, default 127.0.0.1
	paramServerAddr = "server_addr" // side b: frps host (the port comes from listen_port+1)
	paramLocalIP    = "local_ip"    // side b: destination host, default 127.0.0.1
	paramLocalPort  = "local_port"  // side b: destination port, required
	paramProxyName  = "name"        // frp proxy name, default pg-<tunnel_id>
	paramAdminPort  = "admin_port"  // optional frp admin API port on 127.0.0.1, 0/absent = disabled
	paramType       = "type"        // proxy type — "tcp" only (the only one with a passing run)
)

// allowedType is the one proxy type this adapter exercises. udp/http/https/
// stcp/xtcp and the rest of frp's catalogue are refused by name rather than
// rendered untested (CONTRACT §2.0's rule applied to proxy types).
const allowedType = "tcp"

// maxListenPort leaves room for listen_port+2, frps's derived proxy port.
const maxListenPort = 65533

// sideConfig is a Spec + ports resolved into the numbers both renderers need.
type sideConfig struct {
	mode      string
	tunnelID  string
	side      tunnel.Side
	proxyName string
	proxyType string

	listenHost string // side a ingress bind host
	listenPort int    // side a ingress (tunnel.ParamListenPort) — required
	bindPort   int    // listen+1: frps control port, frpc's serverPort
	proxyPort  int    // listen+2: frps proxy listener, relay upstream
	relayHost  string // this side's counting relay bind host
	relayPort  int    // this side's counting relay bind port
	adminPort  int    // frp webServer port, 0 = disabled

	serverAddr string // side b: frps host
	localIP    string // side b: real destination host
	localPort  int    // side b: real destination port
	token      string // resolved secret; "" while rendering, never rendered
}

// resolve validates a Spec against a side's ports and fills every number the
// renderers need. It is the only place params are read, so a param that is
// missing, unknown or out of range is named here and nowhere else.
func resolve(spec tunnel.Spec, ports tunnel.Ports) (sideConfig, error) {
	if err := spec.Validate(); err != nil {
		return sideConfig{}, err
	}
	mode := spec.Mode
	if mode == "" {
		mode = tunnel.ModeRelay // documented default, and a mode with a passing run
	}
	if mode != tunnel.ModeRelay && mode != tunnel.ModeReverse {
		return sideConfig{}, fmt.Errorf("%w: frp implements relay and reverse, not %q",
			tunnel.ErrModeUnsupported, spec.Mode)
	}

	cfg := sideConfig{
		mode:      mode,
		tunnelID:  spec.TunnelID,
		side:      spec.Side,
		proxyType: strings.TrimSpace(spec.Params[paramType]),
	}
	if cfg.proxyType == "" {
		cfg.proxyType = allowedType
	}
	if cfg.proxyType != allowedType {
		return sideConfig{}, fmt.Errorf(
			"params.%s: %q is not supported by this adapter (only %q has a passing loopback test)",
			paramType, cfg.proxyType, allowedType)
	}

	listen, err := portParam(spec, tunnel.ParamListenPort, 1, maxListenPort, true)
	if err != nil {
		return sideConfig{}, err
	}
	cfg.listenPort = listen
	cfg.bindPort = listen + 1
	cfg.proxyPort = listen + 2

	cfg.proxyName = strings.TrimSpace(spec.Params[paramProxyName])
	if cfg.proxyName == "" {
		cfg.proxyName = "pg-" + spec.TunnelID
	}
	if strings.ContainsAny(cfg.proxyName, "\"\n\r\\ ") {
		return sideConfig{}, fmt.Errorf("params.%s: %q must not contain quotes, spaces or line breaks",
			paramProxyName, cfg.proxyName)
	}

	if cfg.adminPort, err = portParam(spec, paramAdminPort, 0, 65535, false); err != nil {
		return sideConfig{}, err
	}
	if cfg.adminPort == 0 {
		// An allocated extra port wins over "nobody asked": the kit hands one
		// out, a node that does not has no admin API rather than frp's default
		// 7400 (which collides the moment a node runs two frp instances).
		if extra, ok := ports.ExtraPort("admin"); ok && extra != 0 {
			cfg.adminPort = extra
		}
	}

	switch spec.Side {
	case tunnel.SideA:
		cfg.listenHost = strings.TrimSpace(spec.Params[paramListenHost])
		if cfg.listenHost == "" {
			cfg.listenHost = "127.0.0.1" // fail closed: an open ingress says so
		}
		if strings.ContainsAny(cfg.listenHost, "\"\n\r\\ ") {
			return sideConfig{}, fmt.Errorf("params.%s: %q is not a bind address", paramListenHost, cfg.listenHost)
		}
		cfg.relayHost = cfg.listenHost
		cfg.relayPort = listen
		if ports.Listen != 0 && ports.Listen != listen {
			return sideConfig{}, fmt.Errorf(
				"params.%s: %d does not match the allocated listen port %d — pin the port the peer dials, or let the node allocate both",
				tunnel.ParamListenPort, listen, ports.Listen)
		}
		if ports.Listen != 0 {
			cfg.relayPort = ports.Listen
		}

	case tunnel.SideB:
		cfg.serverAddr = strings.TrimSpace(spec.Params[paramServerAddr])
		if cfg.serverAddr == "" {
			return sideConfig{}, fmt.Errorf("params.%s: required — frpc dials frps at this host (port is %s+1)",
				paramServerAddr, tunnel.ParamListenPort)
		}
		if strings.ContainsAny(cfg.serverAddr, "\"\n\r\\ :") {
			return sideConfig{}, fmt.Errorf(
				"params.%s: %q must be a bare host — the port is %s+1 (frps bindPort)",
				paramServerAddr, cfg.serverAddr, tunnel.ParamListenPort)
		}
		cfg.localIP = strings.TrimSpace(spec.Params[paramLocalIP])
		if cfg.localIP == "" {
			cfg.localIP = "127.0.0.1"
		}
		if strings.ContainsAny(cfg.localIP, "\"\n\r\\ ") {
			return sideConfig{}, fmt.Errorf("params.%s: %q is not a host", paramLocalIP, cfg.localIP)
		}
		if strings.TrimSpace(spec.Params[paramLocalPort]) == "" {
			return sideConfig{}, fmt.Errorf(
				"params.%s: required — frpc's [[proxies]] needs localPort (a port number 1-65535)",
				paramLocalPort)
		}
		if cfg.localPort, err = portParam(spec, paramLocalPort, 1, 65535, true); err != nil {
			return sideConfig{}, err
		}
		// The relay counts what frpc delivers; frpc points at it, not at the
		// destination, so TunnelStatus has numbers frp itself never reports.
		cfg.relayHost = "127.0.0.1"
		if ports.Listen != 0 && ports.Listen != listen {
			// The node allocated us a distinct port (the kit, two hosts).
			cfg.relayPort = ports.Listen
		} else {
			// The shared pin puts us on the same triple frps owns (listen..+2),
			// which is fine across hosts but a bind collision on one box. When
			// the allocated port and the pin agree — the panel pins one number
			// for both sides — side B's tap must step aside to the number frps
			// does not hold: listen+3. Nothing else can take it: side a owns
			// listen..listen+2 and the node's tunnel allocator reserves
			// listen+1 beside every listen it hands out, and the panel's pin
			// is the only other source of numbers here.
			cfg.relayPort = listen + 3
		}
	}
	return cfg, nil
}

// portParam reads an optional/required integer param and names it when it is
// wrong. required=false treats "" as 0.
func portParam(spec tunnel.Spec, key string, lo, hi int, required bool) (int, error) {
	raw := strings.TrimSpace(spec.Params[key])
	if raw == "" {
		if required {
			return 0, fmt.Errorf("params.%s: required (a port number %d-%d)", key, lo, hi)
		}
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < lo || n > hi {
		return 0, fmt.Errorf("params.%s: %q must be a port number %d-%d", key, raw, lo, hi)
	}
	return n, nil
}

// renderFrps is side a's frps.toml. Deterministic: sorted nothing, fixed
// layout, no timestamps — two renders of one Spec are byte-identical.
func renderFrps(c sideConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# PasarGuard frp frps — tunnel %s side=a mode=%s version=%s\n", c.tunnelID, c.mode, Version)
	b.WriteString("# auth.token is resolved from the environment at Start and is never rendered.\n")
	fmt.Fprintf(&b, "bindPort = %d\n", c.bindPort)
	b.WriteString("proxyBindAddr = \"127.0.0.1\"\n")
	writeWebServer(&b, c.adminPort)
	if c.token != "" {
		b.WriteString("auth.method = \"token\"\n")
		fmt.Fprintf(&b, "auth.token = %s\n", strconv.Quote(c.token))
	}
	return b.String()
}

// renderFrpc is side b's frpc.toml.
func renderFrpc(c sideConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# PasarGuard frp frpc — tunnel %s side=b mode=%s version=%s\n", c.tunnelID, c.mode, Version)
	b.WriteString("# auth.token is resolved from the environment at Start and is never rendered.\n")
	fmt.Fprintf(&b, "serverAddr = %s\n", strconv.Quote(c.serverAddr))
	fmt.Fprintf(&b, "serverPort = %d\n", c.bindPort)
	b.WriteString("loginFailExit = true\n")
	writeWebServer(&b, c.adminPort)
	if c.token != "" {
		b.WriteString("auth.method = \"token\"\n")
		fmt.Fprintf(&b, "auth.token = %s\n", strconv.Quote(c.token))
	}
	b.WriteString("\n[[proxies]]\n")
	fmt.Fprintf(&b, "name = %s\n", strconv.Quote(c.proxyName))
	fmt.Fprintf(&b, "type = %s\n", strconv.Quote(c.proxyType))
	fmt.Fprintf(&b, "localIP = %s\n", strconv.Quote(c.relayHost))
	fmt.Fprintf(&b, "localPort = %d\n", c.relayPort)
	fmt.Fprintf(&b, "remotePort = %d\n", c.proxyPort)
	return b.String()
}

// writeWebServer always writes both keys. Omitting them is what leaves frp's
// own default (127.0.0.1:7400) in force, which collides as soon as a node
// runs two frp instances — so a disabled admin API is spelled `port = 0`.
func writeWebServer(b *strings.Builder, port int) {
	b.WriteString("webServer.addr = \"127.0.0.1\"\n")
	fmt.Fprintf(b, "webServer.port = %d\n", port)
}

// validateProxyBlocks re-reads a rendered frpc config and rejects what frps
// would reject later or silently misbehave on: a proxy with no name, the same
// name twice, a type this adapter never tested, a proxy with no localPort.
// Render calls it on its own output; the tests call it on hand-written text.
func validateProxyBlocks(text string) error {
	type block struct{ name, typ, localPort string }
	var blocks []block
	inProxies := false
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "[[proxies]]":
			blocks = append(blocks, block{})
			inProxies = true
		case strings.HasPrefix(line, "[["):
			inProxies = false
		case !inProxies || len(blocks) == 0 || strings.HasPrefix(line, "#") || !strings.Contains(line, "="):
		default:
			key, value, _ := strings.Cut(line, "=")
			key = strings.TrimSpace(key)
			value = strings.Trim(strings.TrimSpace(value), `"`)
			last := &blocks[len(blocks)-1]
			switch key {
			case "name":
				last.name = value
			case "type":
				last.typ = value
			case "localPort":
				last.localPort = value
			}
		}
	}
	if len(blocks) == 0 {
		return fmt.Errorf("[[proxies]]: the frpc config declares no proxy")
	}
	seen := make(map[string]bool, len(blocks))
	for _, blk := range blocks {
		if blk.name == "" {
			return fmt.Errorf("[[proxies]].name: a proxy must have a name")
		}
		if seen[blk.name] {
			return fmt.Errorf("[[proxies]].name: duplicate proxy name %q — frps keys proxies by name", blk.name)
		}
		seen[blk.name] = true
		if blk.typ != allowedType {
			return fmt.Errorf("[[proxies]].type: %q is not supported by this adapter (only %q is tested)",
				blk.typ, allowedType)
		}
		if blk.localPort == "" {
			return fmt.Errorf("[[proxies]].localPort: missing — a %s proxy forwards to localPort", allowedType)
		}
	}
	return nil
}
