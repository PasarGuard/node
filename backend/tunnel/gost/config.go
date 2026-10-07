package gost

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/pasarguard/node/backend/tunnel"
)

// Parameters. They travel as one map shared by BOTH sides — the panel sends
// the same `params` to side a and side b (app/operation/tunnel.py), so every
// side reads the keys it needs and ignores the rest. An unknown key is refused
// by name: a typo must not become a running tunnel with default settings.
const (
	// ParamListenHost is the bind address. Default 127.0.0.1 — a tunnel that
	// accepts the world says so with 0.0.0.0 explicitly.
	ParamListenHost = "listen_host"
	// ParamPeer is the address this side dials: side b's listen address in
	// mode=relay, side a's control address (listen_port+1) in mode=reverse.
	ParamPeer = "peer"
	// ParamTarget is the destination: mode=relay side a names it (side b
	// dials whatever side a asks for), mode=reverse side b names the service
	// behind it.
	ParamTarget = "target"
	// ParamPublish is mode=reverse side b only: the address gost opens ON
	// side a ("host:port", side a's listen_port). Side b's own listen port is
	// not used in this mode — it sits behind NAT and dials out.
	ParamPublish = "publish"
	// ParamMetricsPort is the loopback Prometheus endpoint Stats() reads live
	// byte counters from. Start fills it in when the caller did not pin it.
	ParamMetricsPort = "metrics_port"
)

// toolParams are the keys this tool understands; everything else is refused.
var toolParams = map[string]bool{
	ParamListenHost:        true,
	ParamPeer:              true,
	ParamTarget:            true,
	ParamPublish:           true,
	ParamMetricsPort:       true,
	tunnel.ParamListenPort: true, // framework: the caller's pinned port
}

// requiredParams is what each (mode, side) cannot work without. A key listed
// here but absent (or blank) is an explicit error naming it.
var requiredParams = map[string]map[tunnel.Side][]string{
	tunnel.ModeRelay: {
		tunnel.SideA: {ParamPeer, ParamTarget},
		tunnel.SideB: {},
	},
	tunnel.ModeReverse: {
		tunnel.SideA: {},
		tunnel.SideB: {ParamPeer, ParamTarget, ParamPublish},
	},
}

// effectiveMode is the mode this spec runs in. "" is gost's default and is
// documented as relay — a mode whose loopback test passed (CONTRACT §2.0).
func effectiveMode(spec tunnel.Spec) string {
	if spec.Mode == "" {
		return tunnel.ModeRelay
	}
	return spec.Mode
}

// checkParams is the schema: unknown keys refused by name, missing required
// keys refused by name. Called from Render, Start and Preflight so the panel,
// the test and the operator all see the same refusal.
func checkParams(spec tunnel.Spec) error {
	mode := effectiveMode(spec)
	for _, key := range tunnel.SortedParams(spec.Params) {
		if !toolParams[key] && !strings.HasPrefix(key, "pg_") {
			return fmt.Errorf("%w: gost has no param %q (allowed: listen_host, peer, target, publish, metrics_port)", tunnel.ErrInvalidSpec, key)
		}
	}
	for _, key := range requiredParams[mode][spec.Side] {
		if strings.TrimSpace(spec.Params[key]) == "" {
			return fmt.Errorf("%w: mode=%s side=%s requires params.%s", tunnel.ErrInvalidSpec, mode, spec.Side, key)
		}
	}
	return nil
}

func param(spec tunnel.Spec, key, fallback string) string {
	if v := strings.TrimSpace(spec.Params[key]); v != "" {
		return v
	}
	return fallback
}

// listenPort is the port this side's publish/ingress lives on. The framework
// always hands Control = Listen+1 (CONTRACT §1.4), so one number is enough.
func listenPort(spec tunnel.Spec) int {
	p, err := strconv.Atoi(strings.TrimSpace(spec.Params[tunnel.ParamListenPort]))
	if err != nil || p < 0 || p > 65535 {
		return 0
	}
	return p
}

// Render is pure and deterministic: fixed struct order, sorted-by-construction
// maps, no I/O, no clock. The same Spec — including Mode — is byte-identical
// twice, which is what makes the testkit's restart step mean anything.
//
// The secret IS part of the output: gost cannot authenticate a relay without
// the password in its config. The file is only ever written by Start, under
// the per-tunnel directory, mode 0600 (CONTRACT §2.1).
func (Adapter) Render(spec tunnel.Spec) (string, error) {
	if err := spec.Validate(); err != nil {
		return "", err
	}
	if err := checkParams(spec); err != nil {
		return "", err
	}
	cfg, _ := buildConfig(spec)
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out) + "\n", nil
}

// buildConfig renders one side of one tunnel against the gost v3 file schema
// (v3.gost.run/en/reference/configuration/file/) and returns the address the
// process is expected to listen on, so Start can wait for exactly that bind.
//
// mode=relay   side a: tcp service on listen_port, fixed target, chain node
//
//	(relay connector, token) at `peer`.
//	side b: relay handler on listen_port with the token.
//
// mode=reverse side a: relay handler with BIND enabled on listen_port+1 — it
//
//	opens listen_port itself when side b registers.
//	side b: rtcp service whose LISTENER carries the chain, so the
//	published port opens on side a and no local port is bound.
func buildConfig(spec tunnel.Spec) (*gostConfig, string) {
	mode := effectiveMode(spec)
	host := param(spec, ParamListenHost, "127.0.0.1")
	lp := listenPort(spec)
	auth := &authSpec{Username: username, Password: spec.Secrets[SecretToken]}
	chain := gostChain(spec, mode)

	cfg := &gostConfig{Log: &logSpec{Output: "stdout", Level: "info", Format: "json"}}
	if p := portParam(spec, ParamMetricsPort); p > 0 {
		cfg.Metrics = &addrSpec{Addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(p))}
	}

	switch {
	case mode == tunnel.ModeRelay && spec.Side == tunnel.SideA:
		addr := net.JoinHostPort(host, strconv.Itoa(lp))
		cfg.Services = []serviceSpec{{
			Name:     sideName(spec.Side),
			Addr:     addr,
			Handler:  &handlerSpec{Type: "tcp", Chain: chainName},
			Listener: &listenerSpec{Type: "tcp"},
			Forwarder: &forwarderSpec{Nodes: []nodeSpec{{
				Name: "target", Addr: spec.Params[ParamTarget],
			}}},
		}}
		cfg.Chains = chain
		return cfg, addr

	case mode == tunnel.ModeRelay && spec.Side == tunnel.SideB:
		addr := net.JoinHostPort(host, strconv.Itoa(lp))
		cfg.Services = []serviceSpec{{
			Name:     sideName(spec.Side),
			Addr:     addr,
			Handler:  &handlerSpec{Type: "relay", Auth: auth},
			Listener: &listenerSpec{Type: "tcp"},
		}}
		return cfg, addr

	case mode == tunnel.ModeReverse && spec.Side == tunnel.SideA:
		// Control on listen_port+1; the published port is listen_port and is
		// bound by this same process once side b registers.
		addr := net.JoinHostPort(host, strconv.Itoa(controlPort(lp)))
		cfg.Services = []serviceSpec{{
			Name:     sideName(spec.Side),
			Addr:     addr,
			Handler:  &handlerSpec{Type: "relay", Auth: auth, Metadata: map[string]any{"bind": true}},
			Listener: &listenerSpec{Type: "tcp"},
		}}
		return cfg, addr

	default: // mode=reverse, side b
		addr := spec.Params[ParamPublish]
		cfg.Services = []serviceSpec{{
			Name:     sideName(spec.Side),
			Addr:     addr,
			Handler:  &handlerSpec{Type: "rtcp"},
			Listener: &listenerSpec{Type: "rtcp", Chain: chainName},
			Forwarder: &forwarderSpec{Nodes: []nodeSpec{{
				Name: "target", Addr: spec.Params[ParamTarget],
			}}},
		}}
		cfg.Chains = chain
		return cfg, addr
	}
}

func gostChain(spec tunnel.Spec, mode string) []chainSpec {
	if mode == tunnel.ModeReverse && spec.Side == tunnel.SideA {
		return nil // side a is the chain end in this mode, it dials nothing
	}
	if mode == tunnel.ModeRelay && spec.Side == tunnel.SideB {
		return nil // side b only listens
	}
	return []chainSpec{{
		Name: chainName,
		Hops: []hopSpec{{
			Name: "hop-0",
			Nodes: []nodeSpec{{
				Name:      "peer",
				Addr:      spec.Params[ParamPeer],
				Connector: &connectorSpec{Type: "relay", Auth: &authSpec{Username: username, Password: spec.Secrets[SecretToken]}},
				Dialer:    &dialerSpec{Type: "tcp"},
			}},
		}},
	}}
}

// portParam reads one param as a port number, 0 when it is absent or bogus.
func portParam(spec tunnel.Spec, key string) int {
	p, err := strconv.Atoi(strings.TrimSpace(spec.Params[key]))
	if err != nil || p < 1 || p > 65535 {
		return 0
	}
	return p
}

func controlPort(listen int) int {
	if listen <= 0 || listen >= 65535 {
		return 0
	}
	return listen + 1
}

func sideName(side tunnel.Side) string { return "side-" + side.String() }

// --- the gost v3 file schema, the subset this adapter renders ---------------

type gostConfig struct {
	Services []serviceSpec `json:"services"`
	Chains   []chainSpec   `json:"chains,omitempty"`
	Metrics  *addrSpec     `json:"metrics,omitempty"`
	Log      *logSpec      `json:"log"`
}

type serviceSpec struct {
	Name      string         `json:"name"`
	Addr      string         `json:"addr"`
	Handler   *handlerSpec   `json:"handler,omitempty"`
	Listener  *listenerSpec  `json:"listener,omitempty"`
	Forwarder *forwarderSpec `json:"forwarder,omitempty"`
}

type handlerSpec struct {
	Type     string         `json:"type"`
	Auth     *authSpec      `json:"auth,omitempty"`
	Chain    string         `json:"chain,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

type listenerSpec struct {
	Type  string `json:"type"`
	Chain string `json:"chain,omitempty"`
}

type forwarderSpec struct {
	Nodes []nodeSpec `json:"nodes"`
}

type chainSpec struct {
	Name string    `json:"name"`
	Hops []hopSpec `json:"hops"`
}

type hopSpec struct {
	Name  string     `json:"name"`
	Nodes []nodeSpec `json:"nodes"`
}

type nodeSpec struct {
	Name      string         `json:"name"`
	Addr      string         `json:"addr"`
	Connector *connectorSpec `json:"connector,omitempty"`
	Dialer    *dialerSpec    `json:"dialer,omitempty"`
}

type connectorSpec struct {
	Type string    `json:"type"`
	Auth *authSpec `json:"auth,omitempty"`
}

type dialerSpec struct {
	Type string `json:"type"`
}

type authSpec struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type addrSpec struct {
	Addr string `json:"addr"`
}

type logSpec struct {
	Output string `json:"output"`
	Level  string `json:"level"`
	Format string `json:"format"`
}
