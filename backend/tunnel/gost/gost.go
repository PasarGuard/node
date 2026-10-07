// Package gost runs go-gost v3 as a Phase 3 tunnel (CONTRACT §2).
//
// gost is a child process, never a library: the adapter writes one config file
// per side (0600, under the framework's per-tunnel directory), execs the pinned
// binary with -C, waits for the service address to bind, and reads the process'
// JSON log stream for records, levels and — as a fallback — byte counters.
//
// Mode support: relay AND reverse, both proven by a four-part loopback run in
// gost_test.go. Anything else is refused by Render (CONTRACT §2.0).
package gost

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pasarguard/node/backend/tunnel"
	nodeLogger "github.com/pasarguard/node/logger"
)

//go:embed pins.json
var pinsJSON []byte

const (
	// Tool is the registered adapter name.
	Tool = "gost"
	// Version is what Handle.Version reports. The binary is pin-verified
	// against pins.json before it is ever exec'd, so the pin's version is the
	// running binary's version without spawning a second process.
	Version = "gost v" + pinVersion
	// pinVersion mirrors pins.json "version"; one place to change on an upgrade.
	pinVersion = "3.3.0"

	// SecretToken is the shared token both ends present (relay handler auth,
	// chain connector auth). Start refuses to run without it: an unauthenticated
	// gost relay is an open proxy.
	SecretToken = "GOST_TOKEN"

	// username is the fixed auth user; only the password is secret.
	username = "pasarguard"

	chainName = "chain-0"

	// readyTimeout is how long Start waits for the service address to bind.
	// gost is up in a few hundred milliseconds; a config it rejects exits
	// sooner and is reported from its own log output instead.
	readyTimeout = 5 * time.Second
)

func init() {
	tunnel.Register(Tool, Adapter{})
	if err := tunnel.RegisterPinJSON(pinsJSON, "pins.json"); err != nil {
		// A pin that will not parse must not degrade into "no pin, run
		// anything": panic at init rather than start an unverified binary.
		panic("gost: pins.json: " + err.Error())
	}
}

// Adapter implements tunnel.Adapter.
type Adapter struct{}

var _ tunnel.Adapter = Adapter{}

// Start writes the config, launches the pinned gost and waits for the service
// address to bind — so "started" means the port answers, not "the process was
// spawned".
//
// The ports it was handed are rendered from, not guessed: Params are cloned
// first so the Manager's persisted spec stays free of runtime values.
func (Adapter) Start(ctx context.Context, spec tunnel.Spec, ports tunnel.Ports) (tunnel.Handle, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if err := checkParams(spec); err != nil {
		return nil, err
	}
	if strings.TrimSpace(spec.Secrets[SecretToken]) == "" {
		return nil, fmt.Errorf("%w: gost requires the %s secret (declare it and set the environment variable on the node)",
			tunnel.ErrSecretUnresolved, SecretToken)
	}
	dir := spec.Params[tunnel.ParamConfigDir]
	if dir == "" {
		return nil, fmt.Errorf("gost: %s is not set — the config file needs the per-tunnel directory", tunnel.ParamConfigDir)
	}
	bin := spec.Params[tunnel.ParamBinaryPath]
	if bin == "" {
		resolved, err := tunnel.ResolveBinary(Tool, "")
		if err != nil {
			return nil, err
		}
		bin = resolved
	}

	// Render with the ports this call was handed and, unless the caller pinned
	// one, a fresh loopback metrics port. The clone never reaches the Manager,
	// so nothing here is persisted or logged.
	rspec := spec.Clone()
	if rspec.Params == nil {
		rspec.Params = map[string]string{}
	}
	rspec.Params[tunnel.ParamListenPort] = strconv.Itoa(ports.Listen)
	if portParam(rspec, ParamMetricsPort) == 0 {
		if p := loopbackPort(); p > 0 {
			rspec.Params[ParamMetricsPort] = strconv.Itoa(p)
		}
	}
	config, serviceAddr := buildConfig(rspec)
	rendered, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, err
	}
	cfgPath := filepath.Join(dir, "gost.json")
	if err := os.WriteFile(cfgPath, append(rendered, '\n'), 0o600); err != nil {
		return nil, fmt.Errorf("gost: write config: %w", err)
	}

	h := &handle{
		spec:        spec.Clone(),
		ports:       ports,
		bin:         bin,
		cfgPath:     cfgPath,
		serviceAddr: serviceAddr,
		metrics:     metricsAddr(config),
		version:     Version,
		logs:        make(chan string, 1024),
		lines:       make(chan nodeLogger.LogLine, 1024),
		exited:      make(chan struct{}),
	}
	if effectiveMode(spec) == tunnel.ModeReverse && spec.Side == tunnel.SideB {
		h.confirmAddr = serviceAddr
	}
	if err := h.launch(); err != nil {
		return nil, err
	}
	if err := h.waitReady(readyTimeout); err != nil {
		h.Shutdown()
		return nil, err
	}
	return h, nil
}

// Preflight reports what this host cannot do. Empty means ready.
func (Adapter) Preflight(_ context.Context, spec tunnel.Spec) []tunnel.Problem {
	var out []tunnel.Problem
	if err := spec.Validate(); err != nil {
		out = append(out, tunnel.Problem{Check: "params", Detail: err.Error()})
	} else if err := checkParams(spec); err != nil {
		out = append(out, tunnel.Problem{Check: "params", Detail: err.Error()})
	}
	out = append(out, tunnel.CheckBinary(Tool)...)
	// Both modes bind two adjacent ports; anything under the well-known line
	// needs root on this side of the start.
	if lp := listenPort(spec); lp > 0 && lp < 1024 {
		out = append(out, tunnel.Problem{
			Check:  "root",
			Detail: fmt.Sprintf("listen_port %d is privileged", lp),
			Fix:    "start the node as root, or pick a port above 1023",
		})
	}
	return out
}

func metricsAddr(cfg *gostConfig) string {
	if cfg == nil || cfg.Metrics == nil {
		return ""
	}
	return cfg.Metrics.Addr
}

// loopbackPort bind-tests 127.0.0.1:0 so gost can expose live byte counters
// on a port nobody else dials.
//
// ponytail: the port is released before gost binds it, so a process racing us
// can steal it; Stats() then falls back to the close-time counters in the log
// stream. Pin metrics_port in Params if that ever matters.
func loopbackPort() int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// handle is one running side of one gost tunnel.
type handle struct {
	spec        tunnel.Spec
	ports       tunnel.Ports
	bin         string
	cfgPath     string
	serviceAddr string
	// confirmAddr is set when the service address is bound by the OTHER side
	// of the tunnel (mode=reverse, side b publishes on side a). The
	// "listening on" line is emitted optimistically by gost, so that mode
	// also waits for the real bind.
	confirmAddr string
	metrics     string
	version     string

	logs  chan string
	lines chan nodeLogger.LogLine

	cmd     *exec.Cmd
	exited  chan struct{} // closed by the waiter goroutine
	waitErr atomic.Value  // error, for waitReady's failure path

	started atomic.Bool
	ready   atomic.Bool   // gost said "listening on <service addr>"
	up      atomic.Uint64 // client -> target, from the log stream (fallback)
	down    atomic.Uint64 // target -> client

	mu       sync.Mutex
	lastLine string
	out      io.ReadCloser
}

// launch starts the process and begins reading its output. The write end of
// the pipe is closed in the parent so the reader sees EOF when gost exits.
func (h *handle) launch() error {
	h.ready.Store(false)
	cmd := exec.Command(h.bin, "-C", h.cfgPath)
	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("gost: pipe: %w", err)
	}
	cmd.Stdout = w
	cmd.Stderr = w
	if err := cmd.Start(); err != nil {
		_ = r.Close()
		_ = w.Close()
		return fmt.Errorf("gost: start %s: %w", h.bin, err)
	}
	_ = w.Close()

	h.mu.Lock()
	h.cmd = cmd
	h.out = r
	h.exited = make(chan struct{})
	h.mu.Unlock()

	go h.pump(r)
	go func() {
		err := cmd.Wait()
		if err != nil {
			h.waitErr.Store(fmt.Errorf("gost exited: %w%s", err, h.tail()))
		} else {
			h.waitErr.Store(fmt.Errorf("gost exited%s", h.tail()))
		}
		close(h.exited)
	}()
	h.started.Store(true)
	return nil
}

// pump reads gost's stdout/stderr: one JSON record per line (we render
// log.format=json), promoted to the manager's LogLiner channel with its own
// level, and counted into the fallback byte totals.
func (h *handle) pump(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		raw := sc.Text()
		if strings.TrimSpace(raw) == "" {
			continue
		}
		rec := gostRecord{Level: "info"}
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			// Not JSON (gost prints plain text before its logger is up):
			// keep the line, classify it as Info.
			rec = gostRecord{Level: "info", Msg: raw}
		}
		h.mu.Lock()
		h.lastLine = raw
		h.mu.Unlock()

		// gost logs one line per service once its listener is up. That line —
		// not a port probe — is the readiness signal: probing the port from
		// here would race the very bind we are waiting for.
		if h.serviceAddr != "" && strings.Contains(raw, "listening on "+h.serviceAddr) {
			h.ready.Store(true)
		}

		// A closed connection carries its byte totals; keep them so Stats
		// still answers after the process is gone.
		if rec.InputBytes > 0 {
			h.up.Add(uint64(rec.InputBytes))
		}
		if rec.OutputBytes > 0 {
			h.down.Add(uint64(rec.OutputBytes))
		}

		select {
		case h.logs <- raw:
		default:
		}
		select {
		case h.lines <- classify(raw, rec):
		default:
		}
	}
}

// gostRecord is the shape gost emits with log.format=json.
type gostRecord struct {
	Time        string  `json:"time"`
	Level       string  `json:"level"`
	Msg         string  `json:"msg"`
	InputBytes  float64 `json:"inputBytes"`
	OutputBytes float64 `json:"outputBytes"`
}

// classify turns one gost line into the manager's LogLine: gost's own level
// and timestamp when it emitted JSON, the node clock and Info when it did not.
func classify(raw string, rec gostRecord) nodeLogger.LogLine {
	line := nodeLogger.LogLine{Detail: raw, Level: mapLevel(rec.Level), TsUnixMs: time.Now().UnixMilli()}
	if rec.Time != "" {
		if t, err := time.Parse(time.RFC3339, rec.Time); err == nil {
			line.TsUnixMs = t.UnixMilli()
		}
	}
	return line
}

func mapLevel(v string) nodeLogger.LogLevel {
	switch strings.ToLower(v) {
	case "debug", "trace":
		return nodeLogger.LogDebug
	case "warn", "warning":
		return nodeLogger.LogWarning
	case "error":
		return nodeLogger.LogError
	case "fatal", "panic", "critical":
		return nodeLogger.LogCritical
	default:
		return nodeLogger.LogInfo
	}
}

// waitReady blocks until gost reports its service listening (the line we wait
// for is "listening on <addr>", which our own log block guarantees in JSON), or
// the process dies, or the budget runs out. It never probes the port itself:
// a probe would bind it for a moment and race gost's own bind.
func (h *handle) waitReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		select {
		case <-h.exited:
			return fmt.Errorf("gost did not come up: %w", h.err())
		default:
		}
		if h.ready.Load() && (h.confirmAddr == "" || !portFree(h.confirmAddr)) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("gost did not bring up %s within %s%s", h.serviceAddr, timeout, h.tail())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// portFree reports whether addr is still unbound. Used only to confirm a port
// another side of the tunnel opens (mode=reverse); never to probe our own
// service address, where holding it for a moment would race gost's bind.
func portFree(addr string) bool {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

// tail is the last log line, for a start-up refusal's error message. The
// config itself is never included — it holds the token.
func (h *handle) tail() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.lastLine == "" {
		return ""
	}
	return ": " + h.lastLine
}

func (h *handle) err() error {
	if v := h.waitErr.Load(); v != nil {
		if err, ok := v.(error); ok {
			return err
		}
	}
	return fmt.Errorf("gost exited%s", h.tail())
}

// Started reports whether the process is still running.
func (h *handle) Started() bool {
	if !h.started.Load() {
		return false
	}
	select {
	case <-h.exited:
		return false
	default:
		return true
	}
}

// Version is the pinned gost version (the binary was hash-checked before exec).
func (h *handle) Version() string { return h.version }

// Logs is the legacy string channel: gost's own lines, verbatim.
func (h *handle) Logs() <-chan string { return h.logs }

// LogLines is the classified channel the Manager prefers (node/logger).
func (h *handle) LogLines() <-chan nodeLogger.LogLine { return h.lines }

// Stats reads gost's own Prometheus counters while the process is alive —
// they move while a connection is still open, which is what the testkit's
// "both directions counted" step needs — and falls back to the byte counts
// the log stream carried on each close.
func (h *handle) Stats(ctx context.Context) (tunnel.Bytes, error) {
	if b, err := h.scrape(ctx); err == nil {
		return b, nil
	}
	return tunnel.Bytes{Up: h.up.Load(), Down: h.down.Load()}, nil
}

func (h *handle) scrape(ctx context.Context) (tunnel.Bytes, error) {
	if h.metrics == "" {
		return tunnel.Bytes{}, fmt.Errorf("gost: no metrics endpoint")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+h.metrics+"/metrics", nil)
	if err != nil {
		return tunnel.Bytes{}, err
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return tunnel.Bytes{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return tunnel.Bytes{}, fmt.Errorf("gost: metrics endpoint answered %d", resp.StatusCode)
	}
	var out tunnel.Bytes
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := sc.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		v, err := strconv.ParseFloat(fields[len(fields)-1], 64)
		if err != nil {
			continue
		}
		// Samples are per (client, service) label; one service per side, but
		// sum anyway so a future second service cannot vanish from the total.
		switch {
		case strings.HasPrefix(line, "gost_service_transfer_input_bytes_total"):
			out.Up += uint64(v)
		case strings.HasPrefix(line, "gost_service_transfer_output_bytes_total"):
			out.Down += uint64(v)
		}
	}
	return out, sc.Err()
}

// Restart relaunches the process from the config already on disk: same spec,
// same ports, no manual step.
func (h *handle) Restart() error {
	h.Shutdown()
	if err := h.launch(); err != nil {
		return err
	}
	return h.waitReady(readyTimeout)
}

// Shutdown kills the process and waits for it. Idempotent; safe to call on a
// handle that never started.
func (h *handle) Shutdown() {
	h.mu.Lock()
	cmd := h.cmd
	started := h.started.Load()
	h.mu.Unlock()
	if cmd == nil || !started {
		return
	}
	h.started.Store(false)
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	<-h.exited
}
