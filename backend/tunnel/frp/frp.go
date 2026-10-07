// Package frp is the Phase 3 adapter for fatedier/frp (CONTRACT §2).
//
// Side A renders and runs frps, side B renders and runs frpc: frps is the
// reachable ingress (relay) or the publisher (reverse), frpc dials out to it
// and delivers to the destination — one frp topology, two passing loopback
// runs, one config format (TOML).
//
// What this adapter adds on top of the binaries, and why:
//
//   - a counting relay on each side. frps flushes its traffic counters only
//     when a connection closes and frpc exposes none at all, so neither
//     binary can answer Handle.Stats while bytes are moving. Each side runs
//     an in-process TCP relay in front of its leg and counts there, which is
//     also what the four-part kit polls.
//   - frp's own admin API (webServer) stays off unless the operator passes
//     admin_port: its default 7400 collides the moment a node runs two frp
//     instances, and its counters are the close-time ones above anyway.
//
// Modes: relay and reverse both have a passing tunneltest run (two kit runs,
// one per mode). Proxy types: tcp only — udp/http/https/stcp/xtcp are refused
// by name instead of rendered untested.
package frp

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	Tool = "frp"
	// Version is the pinned upstream version (pins.json).
	Version = "0.71.0"
	// SecretToken is the env var / secret name both sides must agree on. The
	// panel carries the name only; the value is read at Start.
	SecretToken = "FRP_TOKEN"

	// readyTimeout is how long a side may take to come up: frps to bind its
	// control port, frpc to register its proxy. Generous for a loaded box,
	// short enough that a bad token fails instead of hanging.
	readyTimeout = 8 * time.Second
	// registerMarker is frpc's own success line (verified in the binary):
	// printed after frps has accepted the proxy, i.e. after frps has bound
	// the ingress the client dials.
	registerMarker = "start proxy success"
)

func init() {
	tunnel.Register(Tool, Adapter{})
	if err := tunnel.RegisterPinJSON(pinsJSON, "frp/pins.json"); err != nil {
		panic("frp: pins.json: " + err.Error())
	}
	var extra struct {
		Peer map[string]peerAsset `json:"peer"`
	}
	if err := json.Unmarshal(pinsJSON, &extra); err != nil {
		panic("frp: pins.json peer: " + err.Error())
	}
	peerAssets = extra.Peer
}

// peerAsset is the sibling binary frpc next to the pinned frps. It lives in
// pins.json under its own key because the framework's Pin carries one bin per
// asset and frp ships two executables in one archive.
type peerAsset struct {
	Bin       string `json:"bin"`
	BinSHA256 string `json:"bin_sha256"`
}

var peerAssets map[string]peerAsset

// Adapter implements tunnel.Adapter.
type Adapter struct{}

var _ tunnel.Adapter = Adapter{}

// Render is pure and deterministic: same Spec ⇒ byte-identical TOML, with the
// token left out (secrets never enter Render's output — CONTRACT §2.1).
func (Adapter) Render(spec tunnel.Spec) (string, error) {
	cfg, err := resolve(spec, tunnel.Ports{})
	if err != nil {
		return "", err
	}
	text := render(spec, cfg)
	if spec.Side == tunnel.SideB {
		if err := validateProxyBlocks(text); err != nil {
			return "", err
		}
	}
	return text, nil
}

// Start writes one side's config, brings up its counting relay and its frp
// process, and returns only once that side can carry traffic: frps has bound
// its control port, frpc has registered its proxy.
func (Adapter) Start(ctx context.Context, spec tunnel.Spec, ports tunnel.Ports) (tunnel.Handle, error) {
	cfg, err := resolve(spec, ports)
	if err != nil {
		return nil, err
	}
	bin, err := binaryFor(spec)
	if err != nil {
		return nil, err
	}

	// os.Getenv at Start: the wire carries the secret's NAME, the value comes
	// from this node's environment (the Manager pre-resolves it too; this is
	// the direct-Start path and the documented rule).
	token := spec.Secrets[SecretToken]
	if token == "" {
		token = os.Getenv(SecretToken)
	}
	if strings.ContainsAny(token, "\n\r") {
		return nil, fmt.Errorf("%s: the token contains a line break", SecretToken)
	}
	cfg.token = token

	h := &handle{
		spec:   spec.Clone(),
		ports:  ports,
		cfg:    cfg,
		bin:    bin,
		text:   render(spec, cfg),
		logs:   make(chan string, 1024),
		lines:  make(chan nodeLogger.LogLine, 1024),
		waited: make(chan struct{}),
	}
	if err := h.launch(ctx); err != nil {
		return nil, fmt.Errorf("%s side=%s: %w", Tool, spec.Side, err)
	}
	return h, nil
}

// Preflight reports what this host/spec cannot do: a param frp needs and does
// not have, or a binary the bundle cannot supply.
func (Adapter) Preflight(_ context.Context, spec tunnel.Spec) []tunnel.Problem {
	var out []tunnel.Problem
	if _, err := resolve(spec, tunnel.Ports{}); err != nil {
		out = append(out, tunnel.Problem{Check: "params", Detail: err.Error()})
	}
	return append(out, tunnel.CheckBinary(Tool)...)
}

func render(spec tunnel.Spec, cfg sideConfig) string {
	if spec.Side == tunnel.SideA {
		return renderFrps(cfg)
	}
	return renderFrpc(cfg)
}

// binaryFor resolves this side's executable: frps for side a (the path the
// Manager already pin-verified), frpc for side b (its sibling, hash-checked
// against the same pins.json).
func binaryFor(spec tunnel.Spec) (string, error) {
	bin := spec.Params[tunnel.ParamBinaryPath]
	if bin == "" {
		var err error
		if bin, err = tunnel.ResolveBinary(Tool, ""); err != nil {
			return "", err
		}
	}
	if spec.Side == tunnel.SideA {
		return bin, nil
	}
	return frpcBinary(bin)
}

func frpcBinary(frpsPath string) (string, error) {
	pin, ok := tunnel.PinFor(Tool)
	if !ok {
		return "", fmt.Errorf("%w: %q has no pins.json registered", tunnel.ErrUnknownTool, Tool)
	}
	asset, err := pin.AssetFor(tunnel.PlatformKey())
	if err != nil {
		return "", err
	}
	peer, ok := peerAssets[tunnel.PlatformKey()]
	if !ok || peer.Bin == "" || peer.BinSHA256 == "" {
		return "", fmt.Errorf("frp/pins.json: no frpc entry for %s", tunnel.PlatformKey())
	}
	rel := filepath.FromSlash(asset.Bin)
	if !strings.HasSuffix(frpsPath, rel) {
		return "", fmt.Errorf("frp: %s is not the pinned frps path, cannot locate frpc alongside it", frpsPath)
	}
	path := filepath.Join(strings.TrimSuffix(frpsPath, rel), filepath.FromSlash(peer.Bin))
	sum, err := tunnel.FileSHA256(path)
	if err != nil {
		return "", fmt.Errorf("%w: frpc: %v", tunnel.ErrBinaryNotFound, err)
	}
	if !strings.EqualFold(sum, peer.BinSHA256) {
		return "", fmt.Errorf("%w: %s has %s, pin wants %s (%s@%s)",
			tunnel.ErrBinaryMismatch, path, sum, peer.BinSHA256, Tool, Version)
	}
	return path, nil
}

// handle is one running side: a counting relay, an frp process, and a log
// ring tagged with this tunnel's id.
type handle struct {
	spec    tunnel.Spec
	ports   tunnel.Ports
	cfg     sideConfig
	bin     string
	text    string // the config Start wrote, reused verbatim by Restart
	cfgPath string
	tempDir string

	relay *relay

	logs  chan string
	lines chan nodeLogger.LogLine

	started    atomic.Bool
	exited     atomic.Bool
	registered atomic.Bool
	waited     chan struct{}

	mu       sync.Mutex
	cmd      *exec.Cmd
	exitErr  error
	recent   []string
	stopping bool
}

// launch writes the config, starts the relay, starts the process and waits
// for readiness. The caller holds no lock; Start is serialised by the Manager.
func (h *handle) launch(_ context.Context) error {
	// A relaunch (Restart) inherits a handle that already saw its process die.
	h.exited.Store(false)
	h.registered.Store(false)
	h.mu.Lock()
	h.exitErr = nil
	h.recent = nil
	h.mu.Unlock()

	dir := h.spec.Params[tunnel.ParamConfigDir]
	if dir == "" {
		tmp, err := os.MkdirTemp("", "frp-*")
		if err != nil {
			return err
		}
		dir = tmp
		h.tempDir = tmp
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("config dir: %w", err)
	}
	h.cfgPath = filepath.Join(dir, configName(h.spec.Side))
	if err := os.WriteFile(h.cfgPath, []byte(h.text), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(h.cfgPath), err)
	}

	if h.spec.Side == tunnel.SideA {
		// frps's proxy listener is derived (listen_port+2), not allocated:
		// bind-test it before anything else so a busy port is a named error
		// here and a confusing "proxy start failed" ten seconds later.
		probe, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", h.cfg.proxyPort))
		if err != nil {
			return fmt.Errorf("frp proxy port %s+2 (%d) is in use: %w",
				tunnel.ParamListenPort, h.cfg.proxyPort, err)
		}
		_ = probe.Close()
	}

	relay, err := newRelay(h.cfg.relayHost, h.cfg.relayPort, h.upstream(), h.logf)
	if err != nil {
		return err
	}
	h.relay = relay

	cmd := exec.Command(h.bin, "-c", h.cfgPath)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		relay.close()
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		relay.close()
		return err
	}
	if err := cmd.Start(); err != nil {
		relay.close()
		return fmt.Errorf("start %s: %w", filepath.Base(h.bin), err)
	}
	h.cmd = cmd
	waited := make(chan struct{})
	h.waited = waited
	go h.pump(stdout)
	go h.pump(stderr)
	go func() {
		err := cmd.Wait()
		h.mu.Lock()
		if err != nil && h.exitErr == nil {
			h.exitErr = err
		}
		h.mu.Unlock()
		h.exited.Store(true)
		close(waited)
	}()

	if err := h.waitReady(); err != nil {
		h.stopProcess()
		h.relay.close()
		h.relay = nil
		return err
	}
	h.started.Store(true)
	h.logf(nodeLogger.LogInfo, "side=%s ready: relay %s:%d -> %s (config %s)",
		h.spec.Side, h.cfg.relayHost, h.cfg.relayPort, h.upstream(), filepath.Base(h.cfgPath))
	return nil
}

func configName(side tunnel.Side) string {
	if side == tunnel.SideA {
		return "frps.toml"
	}
	return "frpc.toml"
}

// upstream is what this side's relay forwards to: frps's loopback proxy port
// on side a, the operator's destination on side b.
func (h *handle) upstream() string {
	if h.spec.Side == tunnel.SideA {
		return fmt.Sprintf("127.0.0.1:%d", h.cfg.proxyPort)
	}
	return fmt.Sprintf("%s:%d", h.cfg.localIP, h.cfg.localPort)
}

// waitReady blocks until the side can do its job, or fails with the process's
// own words. A corrupted token is this path: frpc exits (loginFailExit) and
// Start returns that instead of a half-open tunnel.
func (h *handle) waitReady() error {
	deadline := time.Now().Add(readyTimeout)
	for time.Now().Before(deadline) {
		if h.exited.Load() {
			return fmt.Errorf("%s exited before it was ready: %s", filepath.Base(h.bin), h.lastLines())
		}
		if h.sideReady() {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("%s was not ready within %s: %s", filepath.Base(h.bin), readyTimeout, h.lastLines())
}

func (h *handle) sideReady() bool {
	if h.spec.Side == tunnel.SideB {
		return h.registered.Load()
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", h.cfg.bindPort), 250*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (h *handle) pump(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		h.publish(stripANSI(sc.Text()))
	}
}

// ansiRe strips the colour codes frp writes when its output is a pipe; they
// would otherwise land in the panel's log view verbatim.
var ansiRe = regexp.MustCompile("\x1b\\[[0-9;]*m")

func stripANSI(s string) string {
	if strings.ContainsRune(s, 0x1b) {
		return ansiRe.ReplaceAllString(s, "")
	}
	return s
}

func (h *handle) publish(line string) {
	if strings.Contains(line, registerMarker) {
		h.registered.Store(true)
	}
	level := nodeLogger.LogInfo
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(line, "[E]"), strings.Contains(lower, "failed"),
		strings.Contains(lower, "error"), strings.Contains(lower, "refused"),
		strings.Contains(lower, "mismatch"), strings.Contains(lower, "cannot"):
		level = nodeLogger.LogError
	case strings.Contains(line, "[W]"), strings.Contains(lower, "warn"):
		level = nodeLogger.LogWarning
	}
	h.mu.Lock()
	h.recent = append(h.recent, line)
	if len(h.recent) > 8 {
		h.recent = h.recent[len(h.recent)-8:]
	}
	h.mu.Unlock()
	h.logf(level, "%s", line)
}

func (h *handle) lastLines() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.recent) == 0 {
		return "no output"
	}
	return strings.Join(h.recent, " | ")
}

func (h *handle) stopProcess() {
	h.mu.Lock()
	cmd := h.cmd
	h.cmd = nil
	h.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	select {
	case <-h.waited:
	case <-time.After(5 * time.Second):
	}
}

// logf publishes one line to both channels, never blocking: a consumer that
// stopped reading must not stall the data path.
func (h *handle) logf(level nodeLogger.LogLevel, format string, args ...any) {
	msg := fmt.Sprintf("frp[%s/%s] %s", h.spec.TunnelID, h.spec.Side, fmt.Sprintf(format, args...))
	select {
	case h.logs <- msg:
	default:
	}
	select {
	case h.lines <- nodeLogger.LogLine{Detail: msg, Level: level, TsUnixMs: time.Now().UnixMilli()}:
	default:
	}
}

func (h *handle) Started() bool       { return h.started.Load() && !h.exited.Load() }
func (h *handle) Version() string     { return "frp-" + Version }
func (h *handle) Logs() <-chan string { return h.logs }

// LogLines is the classified stream the Manager prefers (CONTRACT §3.1).
func (h *handle) LogLines() <-chan nodeLogger.LogLine { return h.lines }

// Stats counts the bytes this side's relay carried — aggregate up/down for
// the whole tunnel, never per-user (CONTRACT §3.5).
func (h *handle) Stats(context.Context) (tunnel.Bytes, error) {
	if h.relay == nil {
		return tunnel.Bytes{}, nil
	}
	return tunnel.Bytes{Up: h.relay.up.Load(), Down: h.relay.down.Load()}, nil
}

// Restart rebinds and relaunches from the config already on disk: same Spec,
// same ports, same bytes.
func (h *handle) Restart() error {
	h.Shutdown()
	h.mu.Lock()
	h.stopping = false
	h.mu.Unlock()
	if err := h.launch(context.Background()); err != nil {
		return err
	}
	h.logf(nodeLogger.LogInfo, "side=%s restarted", h.spec.Side)
	return nil
}

// Shutdown stops the process and the relay. Idempotent; the log channels stay
// open, as the reference adapter's do.
func (h *handle) Shutdown() {
	h.mu.Lock()
	if h.stopping {
		h.mu.Unlock()
		return
	}
	h.stopping = true
	temp := h.tempDir
	h.mu.Unlock()

	h.stopProcess()
	if h.relay != nil {
		h.relay.close()
		h.relay = nil
	}
	h.started.Store(false)
	if temp != "" {
		_ = os.RemoveAll(temp)
	}
	h.logf(nodeLogger.LogInfo, "side=%s stopped", h.spec.Side)
}

// ---------------------------------------------------------------------------
// relay: the counting hop each side puts in front of its leg of the tunnel.

type relay struct {
	ln       net.Listener
	upstream string
	up       atomic.Uint64 // near -> far
	down     atomic.Uint64 // far -> near

	logf func(nodeLogger.LogLevel, string, ...any)

	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	stopping bool
	wg       sync.WaitGroup
}

func newRelay(host string, port int, upstream string, logf func(nodeLogger.LogLevel, string, ...any)) (*relay, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("relay listen %s: %w", addr, err)
	}
	r := &relay{ln: ln, upstream: upstream, logf: logf, conns: map[net.Conn]struct{}{}}
	r.wg.Add(1)
	go r.accept()
	return r, nil
}

func (r *relay) accept() {
	defer r.wg.Done()
	for {
		conn, err := r.ln.Accept()
		if err != nil {
			return
		}
		r.track(conn, true)
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			defer r.track(conn, false)
			r.forward(conn)
		}()
	}
}

func (r *relay) track(c net.Conn, add bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if add {
		r.conns[c] = struct{}{}
		return
	}
	delete(r.conns, c)
	_ = c.Close()
}

func (r *relay) forward(near net.Conn) {
	far, err := net.DialTimeout("tcp", r.upstream, 10*time.Second)
	if err != nil {
		r.logf(nodeLogger.LogError, "relay dial %s: %v", r.upstream, err)
		_ = near.Close()
		return
	}
	r.track(far, true)
	defer r.track(far, false)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); copyHalf(far, near, &r.up) }()
	go func() { defer wg.Done(); copyHalf(near, far, &r.down) }()
	wg.Wait()
	_ = near.Close()
	_ = far.Close()
}

func (r *relay) close() {
	r.mu.Lock()
	if r.stopping {
		r.mu.Unlock()
		return
	}
	r.stopping = true
	conns := make([]net.Conn, 0, len(r.conns))
	for c := range r.conns {
		conns = append(conns, c)
	}
	r.mu.Unlock()

	_ = r.ln.Close()
	for _, c := range conns {
		_ = c.Close()
	}
	r.wg.Wait()
}

// copyHalf copies src -> dst, counting what was written, and half-closes dst's
// write side when src ends so the peer sees a FIN while the other direction
// can still drain. Counted per write, not at connection close: Stats has to
// answer while the tunnel is still carrying traffic (frps itself does not).
func copyHalf(dst, src net.Conn, counter *atomic.Uint64) {
	buf := make([]byte, 32*1024)
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			written := 0
			for written < n {
				m, err := dst.Write(buf[written:n])
				if m > 0 {
					written += m
					counter.Add(uint64(m))
				}
				if err != nil {
					return
				}
			}
		}
		if readErr != nil {
			break
		}
	}
	if tcp, ok := dst.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
}
