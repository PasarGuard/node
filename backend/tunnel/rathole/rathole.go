// Package rathole runs rathole v0.5.0 as a Phase 3 tunnel (CONTRACT §2).
//
// Mode support: `reverse` only — rathole's own shape. Side b (the client, the
// side behind NAT) dials side a's control port, side a publishes the service,
// and every byte enters at a and is delivered to a listener behind b
// (CONTRACT §2.0). rathole has no forward path, so Render and Start refuse
// mode=relay instead of falling through to a default.
//
// The shape of one side, and why there is a tap:
//
//	side a:  world -> [tap] -> rathole server service ([::1]:listen)
//	         rathole server control (control = listen+1)
//	side b:  rathole client -> [tap] -> target
//
// rathole v0.5.0 exposes no counters, and TunnelStatus must carry real
// aggregate bytes (CONTRACT §3.5), so each side puts a byte-counting tap in
// its own path. The tap owns Ports.Listen — the port the peer or the world
// dials — and rathole's service binds the same number on IPv6 loopback, which
// is what lets one framework port pair carry both listeners.
package rathole

import (
	"bufio"
	"context"
	_ "embed"
	"fmt"
	"io"
	"net"
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

const (
	// Tool is the registered adapter name.
	Tool = "rathole"
	// Version is the pinned release (pins.json). rathole is refused unless its
	// sha256 matches the pin, so this is the only version a node can run.
	Version = "0.5.0"
	// SecretToken is the env var / secret name both ends must agree on. It is
	// read from the environment at Start, never from Params, never logged: the
	// config rathole reads on disk needs the value, the wire never carries it.
	SecretToken = "RATHOLE_TOKEN"

	// startupTimeout is how long side a waits for its control port, and side b
	// waits for the control channel, before giving up. A side whose peer is
	// simply not up yet starts anyway and keeps retrying (rathole's own
	// behaviour); only a refusal rathole states — a wrong token — fails Start.
	startupTimeout = 10 * time.Second

	// tapDialWindow is how long one accepted connection waits for rathole's
	// service listener. The server binds it only after the client's control
	// channel authenticates, so the first connection can arrive a few
	// milliseconds early. ponytail: 2s, plenty for the kit's start ordering —
	// raise it if a loaded node proves the service binds slower than that.
	tapDialWindow   = 2 * time.Second
	tapDialInterval = 50 * time.Millisecond

	// recentLines is how many log lines the handle keeps for its own startup
	// checks and error tails. The Manager owns the durable ring.
	recentLines = 200
)

//go:embed pins.json
var pinsJSON []byte

func init() {
	tunnel.Register(Tool, Adapter{})
	if err := tunnel.RegisterPinJSON(pinsJSON, "backend/tunnel/rathole/pins.json"); err != nil {
		panic("rathole: pins.json: " + err.Error())
	}
}

// Adapter implements tunnel.Adapter.
type Adapter struct{}

var _ tunnel.Adapter = Adapter{}

// Render is pure and deterministic: fixed layout, sorted params, no clock and
// no randomness, so two renders of one Spec are byte-identical.
//
// The port comes from Params["listen_port"], which Start injects from the
// allocated Ports before it renders: Render has no Ports argument of its own.
func (Adapter) Render(spec tunnel.Spec) (string, error) {
	if err := spec.Validate(); err != nil {
		return "", err
	}
	if err := checkMode(spec); err != nil {
		return "", err
	}
	if err := checkParams(spec); err != nil {
		return "", err
	}
	return renderConfig(spec)
}

// Start writes this side's config, launches the pinned binary and puts a
// byte-counting tap in front of it.
func (Adapter) Start(ctx context.Context, spec tunnel.Spec, ports tunnel.Ports) (tunnel.Handle, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if err := checkMode(spec); err != nil {
		return nil, err
	}
	if err := checkParams(spec); err != nil {
		return nil, err
	}

	pspec, err := withPorts(spec, ports)
	if err != nil {
		return nil, err
	}
	bin, err := binaryFor(pspec)
	if err != nil {
		return nil, err
	}
	cfg, err := renderConfig(pspec)
	if err != nil {
		return nil, err
	}
	dir := pspec.Params[tunnel.ParamConfigDir]
	if dir == "" {
		return nil, fmt.Errorf("rathole: no config dir: %s is not set", tunnel.ParamConfigDir)
	}
	cfgPath := filepath.Join(dir, "config.toml")
	// 0600: rathole's config carries the token because rathole reads its token
	// from the config (CONTRACT §2.1's "unless the tool requires it").
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		return nil, fmt.Errorf("rathole: write config: %w", err)
	}

	h := &handle{
		spec:    pspec,
		ports:   ports,
		bin:     bin,
		cfgPath: cfgPath,
		logs:    make(chan string, 1024),
		lines:   make(chan nodeLogger.LogLine, 1024),
	}
	if err := h.launch(ctx); err != nil {
		h.Shutdown()
		return nil, err
	}
	return h, nil
}

// Preflight reports what this host or spec cannot do. Empty means ready.
func (Adapter) Preflight(_ context.Context, spec tunnel.Spec) []tunnel.Problem {
	if err := spec.Validate(); err != nil {
		return []tunnel.Problem{{Check: "params", Detail: err.Error()}}
	}
	var out []tunnel.Problem
	if err := checkMode(spec); err != nil {
		out = append(out, tunnel.Problem{
			Check:  "mode",
			Detail: err.Error(),
			Fix:    "use mode=reverse: rathole's client always dials the server",
		})
	}
	if err := checkParams(spec); err != nil {
		out = append(out, tunnel.Problem{Check: "params", Detail: err.Error()})
	}
	out = append(out, tunnel.CheckBinary(Tool)...)
	if spec.Side == tunnel.SideA && !ipv6LoopbackAvailable() {
		out = append(out, tunnel.Problem{
			Check:  "ipv6_loopback",
			Detail: "[::1] cannot be bound, and side a's rathole service binds there (the tap owns the IPv4 port)",
			Fix:    "enable IPv6 loopback on this node, or run a tunnel tool that needs no second listener",
		})
	}
	return out
}

// ipv6LoopbackAvailable is Preflight's half of the side-a requirement. The
// service listener and the tap cannot share one address, so side a needs
// IPv6 loopback; say so before Start fails on it.
func ipv6LoopbackAvailable() bool {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

// withPorts pins this side's port into Params so Render can see it. A pinned
// value that disagrees with the allocated pair is refused rather than
// silently reinterpreted: the other side dials the pinned number.
func withPorts(spec tunnel.Spec, ports tunnel.Ports) (tunnel.Spec, error) {
	if ports.Listen <= 0 {
		return spec, fmt.Errorf("rathole: ports.Listen must be a port number, got %d", ports.Listen)
	}
	pspec := spec.Clone()
	if raw := strings.TrimSpace(pspec.Params[tunnel.ParamListenPort]); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n != ports.Listen {
			return spec, fmt.Errorf("rathole: %s=%q does not match the allocated port %d",
				tunnel.ParamListenPort, raw, ports.Listen)
		}
		return pspec, nil
	}
	if pspec.Params == nil {
		pspec.Params = map[string]string{}
	}
	pspec.Params[tunnel.ParamListenPort] = strconv.Itoa(ports.Listen)
	return pspec, nil
}

// binaryFor resolves this side's executable and refuses anything that is not
// the pin: Start never runs a binary it cannot verify (CONTRACT §2.1).
func binaryFor(spec tunnel.Spec) (string, error) {
	bin := spec.Params[tunnel.ParamBinaryPath]
	if bin == "" {
		var err error
		if bin, err = tunnel.ResolveBinary(Tool, ""); err != nil {
			return "", err
		}
	}
	if err := verifyBinary(bin); err != nil {
		return "", err
	}
	return bin, nil
}

func verifyBinary(path string) error {
	pin, ok := tunnel.PinFor(Tool)
	if !ok {
		return fmt.Errorf("rathole: no pin registered")
	}
	asset, err := pin.AssetFor(tunnel.PlatformKey())
	if err != nil {
		return err
	}
	want := asset.BinSHA256
	if want == "" {
		want = asset.SHA256
	}
	got, err := tunnel.FileSHA256(path)
	if err != nil {
		return fmt.Errorf("rathole: %s: %w", path, err)
	}
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("%w: %s has %s, pin %s@%s wants %s",
			tunnel.ErrBinaryMismatch, path, got, Tool, pin.Version, want)
	}
	return nil
}

// handle is one running side: the rathole process, its log reader, and the
// counting tap. Idempotent Shutdown; Restart re-renders from the same Spec.
type handle struct {
	spec    tunnel.Spec
	ports   tunnel.Ports
	bin     string
	cfgPath string

	logs  chan string
	lines chan nodeLogger.LogLine

	started atomic.Bool
	up      atomic.Uint64 // ingress -> target
	down    atomic.Uint64 // target -> ingress

	mu      sync.Mutex
	cmd     *exec.Cmd
	exited  chan struct{}
	exitErr error
	tap     *tapConn
	closed  bool
	recent  []nodeLogger.LogLine
}

// launch brings the tap and the process up and waits for the side's readiness
// signal: side a for its control port, side b for the control channel (which
// is also where a wrong token is refused, loudly).
func (h *handle) launch(ctx context.Context) error {
	if err := h.startTap(); err != nil {
		return err
	}
	if err := h.startProcess(); err != nil {
		return err
	}
	return h.waitReady(ctx)
}

func (h *handle) waitReady(ctx context.Context) error {
	if h.spec.Side == tunnel.SideA {
		return h.waitControlPort(ctx)
	}
	return h.waitControlChannel(ctx)
}

// startTap binds this side's counting listener and points it at what it
// forwards to: rathole's service on side a, the target on side b.
func (h *handle) startTap() error {
	host := h.spec.Params[paramListenHost]
	if host == "" {
		host = defaultLoopback
	}
	addr := net.JoinHostPort(host, strconv.Itoa(h.ports.Listen))
	upstream := h.spec.Params[paramTarget]
	if h.spec.Side == tunnel.SideA {
		// rathole's service: same port number, IPv6 loopback, so it never
		// collides with the tap that owns the IPv4 address.
		upstream = net.JoinHostPort("::1", strconv.Itoa(h.ports.Listen))
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("rathole: tap listen %s: %w", addr, err)
	}
	t := &tapConn{
		ln:       ln,
		upstream: upstream,
		h:        h,
		stop:     make(chan struct{}),
		conns:    map[net.Conn]struct{}{},
	}
	h.mu.Lock()
	h.tap = t
	h.mu.Unlock()
	go t.acceptLoop()
	return nil
}

// startProcess spawns the pinned binary with the config already on disk and
// starts the reader that turns its stderr/stderr tracing output into records.
func (h *handle) startProcess() error {
	flag := "-s"
	if h.spec.Side == tunnel.SideB {
		flag = "-c"
	}
	cmd := exec.Command(h.bin, flag, h.cfgPath)
	cmd.Env = withDefaultLogLevel(os.Environ())
	pr, pw, err := os.Pipe()
	if err != nil {
		return err
	}
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return fmt.Errorf("rathole: start %s: %w", h.bin, err)
	}
	_ = pw.Close() // the child owns it now; the reader sees EOF when it exits

	exited := make(chan struct{})
	h.mu.Lock()
	h.cmd, h.exited = cmd, exited
	h.mu.Unlock()

	go h.readOutput(pr)
	go func() {
		err := cmd.Wait()
		h.mu.Lock()
		h.exitErr = err
		h.mu.Unlock()
		h.started.Store(false)
		close(exited)
	}()
	h.started.Store(true)
	return nil
}

// withDefaultLogLevel leaves an operator's RUST_LOG alone and asks for info
// otherwise, because the tunnel's log ring is a product feature and rathole's
// default without the variable is not guaranteed to reach it.
func withDefaultLogLevel(env []string) []string {
	for _, kv := range env {
		if strings.HasPrefix(kv, "RUST_LOG=") {
			return env
		}
	}
	return append(append([]string{}, env...), "RUST_LOG=info")
}

func (h *handle) readOutput(r io.ReadCloser) {
	defer func() { _ = r.Close() }()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		h.publishRathole(sc.Text())
	}
}

// publishRathole classifies one line of rathole's tracing output
// ("<timestamp> <LEVEL> <target>: <msg>") and records it.
func (h *handle) publishRathole(line string) {
	h.publish(parseLevel(line), line)
}

// publish records one line: it feeds the handle's own recent-window (the
// startup checks and error tails read that) and the two channels the Manager's
// pump consumes. Non-blocking, and refused once the handle is closed, so a
// consumer that stopped reading or a Shutdown in flight can never panic or
// stall the data path.
func (h *handle) publish(level nodeLogger.LogLevel, line string) {
	rec := nodeLogger.LogLine{Detail: line, Level: level, TsUnixMs: time.Now().UnixMilli()}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.recent = append(h.recent, rec)
	if len(h.recent) > recentLines {
		h.recent = h.recent[len(h.recent)-recentLines:]
	}
	select {
	case h.lines <- rec:
	default:
	}
	select {
	case h.logs <- line:
	default:
	}
}

// parseLevel reads rathole's own severity token; anything that is not a
// tracing line falls back to Info (the handle's own lines are published with
// an explicit level instead).
func parseLevel(line string) nodeLogger.LogLevel {
	rest := line
	if i := strings.IndexByte(line, ' '); i > 0 && len(line[:i]) >= 20 && line[:i][4] == '-' {
		rest = line[i+1:]
	}
	if i := strings.IndexByte(rest, ' '); i > 0 {
		switch strings.ToUpper(rest[:i]) {
		case "ERROR":
			return nodeLogger.LogError
		case "WARN":
			return nodeLogger.LogWarning
		case "DEBUG", "TRACE":
			return nodeLogger.LogDebug
		case "INFO":
			return nodeLogger.LogInfo
		}
	}
	return nodeLogger.LogInfo
}

// waitControlPort is side a's readiness: rathole's server binds its control
// port at startup, and nothing else about it is observable before the client
// shows up. A process that died says so with its own output.
func (h *handle) waitControlPort(ctx context.Context) error {
	host := h.spec.Params[paramControlHost]
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = defaultLoopback
	}
	control := h.ports.Control
	if control <= 0 {
		control = h.ports.Listen + 1
	}
	addr := net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(control))
	deadline := time.Now().Add(startupTimeout)
	for {
		if conn, err := net.DialTimeout("tcp", addr, 250*time.Millisecond); err == nil {
			_ = conn.Close()
			return nil
		}
		if err := h.processGone(); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("rathole server never bound its control port %s within %s%s",
				addr, startupTimeout, h.tail())
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// waitControlChannel is side b's readiness and the headline refusal: rathole
// states a wrong token as an authentication error, and Start fails with it
// rather than leaving a side up that will never carry a byte. A peer that is
// merely not running yet is not an error — rathole retries on its own, and a
// tunnel that waits for its peer is the normal order of operations.
func (h *handle) waitControlChannel(ctx context.Context) error {
	deadline := time.Now().Add(startupTimeout)
	for {
		for _, rec := range h.snapshot() {
			switch {
			case strings.Contains(rec.Detail, "Control channel established"):
				return nil
			case strings.Contains(rec.Detail, "Authentication failed"), strings.Contains(rec.Detail, "Incorrect token"):
				h.publish(nodeLogger.LogError, "rathole: control channel refused by the server (token mismatch)")
				return fmt.Errorf("rathole: authentication failed, the peer's token does not match%s", h.tail())
			}
		}
		if err := h.processGone(); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if time.Now().After(deadline) {
			h.publish(nodeLogger.LogWarning,
				fmt.Sprintf("rathole: control channel not established within %s; keeping the side up, rathole keeps retrying", startupTimeout))
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// processGone reports a process that exited during startup, with the lines it
// left behind — a config rathole rejects is otherwise invisible.
func (h *handle) processGone() error {
	h.mu.Lock()
	exited, err := h.exited, h.exitErr
	h.mu.Unlock()
	if exited == nil {
		return nil
	}
	select {
	case <-exited:
		return fmt.Errorf("rathole exited during startup: %v%s", err, h.tail())
	default:
		return nil
	}
}

// snapshot is the recent log window, oldest first.
func (h *handle) snapshot() []nodeLogger.LogLine {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]nodeLogger.LogLine, len(h.recent))
	copy(out, h.recent)
	return out
}

// tail renders the last few lines for an error message.
func (h *handle) tail() string {
	recs := h.snapshot()
	if len(recs) == 0 {
		return ""
	}
	if len(recs) > 5 {
		recs = recs[len(recs)-5:]
	}
	lines := make([]string, 0, len(recs))
	for _, rec := range recs {
		lines = append(lines, rec.Detail)
	}
	return "\nlast rathole output:\n  " + strings.Join(lines, "\n  ")
}

// stopProcess kills the child and waits for it. Safe to call when nothing is
// running; never closes the log channels (Restart reuses them).
func (h *handle) stopProcess() {
	h.mu.Lock()
	cmd, exited := h.cmd, h.exited
	h.cmd = nil
	h.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	if exited != nil {
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
		}
	}
}

func (h *handle) stopTap() {
	h.mu.Lock()
	t := h.tap
	h.tap = nil
	h.mu.Unlock()
	if t != nil {
		t.close()
	}
}

// Started reports whether the rathole process for this side is alive.
func (h *handle) Started() bool { return h.started.Load() }

// Version is the pinned release this side runs.
func (h *handle) Version() string { return Version }

// Logs is the legacy string channel (Backend.Logs' shape).
func (h *handle) Logs() <-chan string { return h.logs }

// LogLines is the classified channel the Manager prefers: rathole's own
// severity travels with the line instead of being guessed downstream.
func (h *handle) LogLines() <-chan nodeLogger.LogLine { return h.lines }

// Stats returns what this side's tap has counted. Aggregate only — a tunnel
// never sees a user (CONTRACT §3.5).
func (h *handle) Stats(context.Context) (tunnel.Bytes, error) {
	return tunnel.Bytes{Up: h.up.Load(), Down: h.down.Load()}, nil
}

// Restart stops this side's children and brings them back from the same Spec:
// re-render (byte-identical, that is what makes it a restart), rebind, respawn.
func (h *handle) Restart() error {
	h.stopProcess()
	h.stopTap()

	cfg, err := renderConfig(h.spec)
	if err != nil {
		return err
	}
	if err := os.WriteFile(h.cfgPath, []byte(cfg), 0o600); err != nil {
		return fmt.Errorf("rathole: write config: %w", err)
	}
	if err := h.startTap(); err != nil {
		return err
	}
	if err := h.startProcess(); err != nil {
		return err
	}
	if err := h.waitReady(context.Background()); err != nil {
		h.stopProcess()
		h.stopTap()
		return err
	}
	return nil
}

// Shutdown takes the side down: child first, then the tap, then the channels
// the Manager's pump ranges over, so the pump ends instead of hanging.
// Idempotent.
func (h *handle) Shutdown() {
	h.stopProcess()
	h.stopTap()
	h.mu.Lock()
	if !h.closed {
		h.closed = true
		close(h.logs)
		close(h.lines)
	}
	h.mu.Unlock()
	h.started.Store(false)
}

// tapConn is this side's counting listener: it accepts, dials what this side
// forwards to, and counts both directions as the bytes move.
type tapConn struct {
	ln       net.Listener
	upstream string
	h        *handle
	stop     chan struct{}

	mu    sync.Mutex
	conns map[net.Conn]struct{}
	wg    sync.WaitGroup
}

func (t *tapConn) acceptLoop() {
	for {
		conn, err := t.ln.Accept()
		if err != nil {
			return
		}
		t.mu.Lock()
		select {
		case <-t.stop:
			t.mu.Unlock()
			_ = conn.Close()
			return
		default:
		}
		t.conns[conn] = struct{}{}
		t.mu.Unlock()

		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			t.serve(conn)
		}()
	}
}

func (t *tapConn) serve(conn net.Conn) {
	defer t.forget(conn)

	up, err := t.dialUpstream()
	if err != nil {
		t.h.publish(nodeLogger.LogError, fmt.Sprintf("rathole tap: %s unreachable: %v", t.upstream, err))
		return
	}
	defer func() { _ = up.Close() }()

	t.h.publish(nodeLogger.LogInfo, fmt.Sprintf("rathole tap: %s -> %s", conn.RemoteAddr(), t.upstream))
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		copyCount(up, conn, &t.h.up) // ingress -> target is the tunnel's up
	}()
	go func() {
		defer wg.Done()
		copyCount(conn, up, &t.h.down)
	}()
	wg.Wait()
}

// dialUpstream retries inside tapDialWindow: side a's service listener does
// not exist until the client authenticates, so the first connection of a fresh
// tunnel can arrive a few milliseconds before it does.
func (t *tapConn) dialUpstream() (net.Conn, error) {
	deadline := time.Now().Add(tapDialWindow)
	var last error
	for {
		conn, err := net.DialTimeout("tcp", t.upstream, time.Second)
		if err == nil {
			return conn, nil
		}
		last = err
		select {
		case <-t.stop:
			return nil, fmt.Errorf("tunnel stopped while dialing %s: %w", t.upstream, err)
		default:
		}
		if time.Now().After(deadline) {
			return nil, last
		}
		time.Sleep(tapDialInterval)
	}
}

func (t *tapConn) forget(conn net.Conn) {
	t.mu.Lock()
	delete(t.conns, conn)
	t.mu.Unlock()
	_ = conn.Close()
}

func (t *tapConn) close() {
	close(t.stop)
	_ = t.ln.Close()
	t.mu.Lock()
	for conn := range t.conns {
		_ = conn.Close()
	}
	t.mu.Unlock()
	t.wg.Wait()
}

// copyCount copies src -> dst and counts what actually landed, per write and
// not at connection close, so Stats answers while the tunnel is still moving
// bytes. It half-closes dst when src ends so the peer sees a FIN while the
// reverse direction drains.
func copyCount(dst, src net.Conn, counter *atomic.Uint64) {
	buf := make([]byte, 32*1024)
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			written := 0
			for written < n {
				m, err := dst.Write(buf[written:n])
				if m > 0 {
					counter.Add(uint64(m))
					written += m
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
