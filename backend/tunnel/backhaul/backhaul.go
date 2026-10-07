// Package backhaul drives Musixal/Backhaul v0.7.2 (AGPL-3.0) as a Phase 3
// tunnel on tunnel.Adapter (CONTRACT §2.1).
//
// Backhaul is dispatched exactly the way the other five tools are: one
// sha256-pinned binary, started as a child process. Its source is never
// copied into this repository and it is never a Go module dependency —
// PasarGuard is AGPL-3.0 as well, and the licence boundary is kept at the
// process edge (UPSTREAM.md).
//
// # Topology, both modes
//
//	side a  runs Backhaul's [server]: it binds the tunnel transport on the
//	        framework's Ports.Control and publishes the ingress on
//	        Ports.Listen.
//	side b  runs Backhaul's [client]: it dials out to side a and delivers to
//	        `target`, the address side a's own config names.
//
// That is Backhaul's native shape (the server lists ports, the client dials
// them), and it covers both CONTRACT §2.0 modes — the mode decides what
// `target` means:
//
//	relay    `target` is the destination: bytes enter at a and leave at b.
//	reverse  `target` is a service behind b: it is published on a and
//	         delivered to a listener behind b.
//
// # Why each side runs a small counting proxy
//
// Backhaul publishes no byte counter this adapter can read, and every Handle
// has to answer Stats with aggregate up/down (CONTRACT §3.5). Each side
// therefore fronts one local listener with a proxy that counts what crosses
// it:
//
//	a binds the published ingress (Ports.Listen) and forwards to Backhaul's
//	   own ingress listener on loopback. As well as the counters, this is the
//	   listener the rest of the system dials — Backhaul binds its ingress
//	   only once the control channel is up, which is after Start returns.
//	b binds a loopback port that Backhaul's client uses as its remote_addr,
//	   and dials side a's transport behind it.
//
// A proxy that cannot reach its backend waits, then fails with an
// Error-level record and closes the connection: never a silent swallow. That
// is the explicit failure the testkit's negative control asks for.
package backhaul

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

func init() {
	tunnel.Register(Tool, Adapter{})
	if err := tunnel.RegisterPinJSON(pinsJSON, "pins.json"); err != nil {
		panic("backhaul: " + err.Error())
	}
}

const (
	// Tool is the registered adapter name.
	Tool = "backhaul"
	// Version is what Handle.Version reports. The binary that runs is
	// verified against this pin's sha256 before exec (CONTRACT §2.1), so the
	// two cannot drift; `backhaul -v` prints the same release as v0.7.2.
	Version = "0.7.2"
	// SecretToken is the tunnel's authentication token: the environment
	// variable the Manager resolves, and the `token` both ends must agree on.
	SecretToken = "BACKHAUL_TOKEN"

	cfgName = "config.toml"

	// backendWait is how long a proxy waits for its backend before it fails
	// the connection. Backhaul binds its ingress only after the control
	// channel is established, so a proxy that gave up instantly would close
	// every connection during the tunnel's own start-up. It stays under the
	// testkit's 10s I/O budget so a tunnel that never comes up fails inside
	// that budget instead of hanging it.
	backendWait = 8 * time.Second
	// startupWait is how long Start watches for a process that dies on its
	// own config — a port in use, a malformed file — so the operator gets
	// Backhaul's own words rather than a connection that goes nowhere.
	startupWait = 250 * time.Millisecond
	// dialPoll is the retry interval while waiting for the backend.
	dialPoll = 50 * time.Millisecond
	// tailLines is how many log lines Start keeps for a start-up failure.
	tailLines = 20
)

// Adapter implements tunnel.Adapter.
type Adapter struct{}

var _ tunnel.Adapter = Adapter{}

// Render produces this side's TOML. Pure and deterministic: same Spec ⇒
// byte-identical output (CONTRACT §2.1), which is what makes the testkit's
// restart step mean anything. It never refuses a host — rendering is data, so
// a Windows node can still render what it cannot run; Start and Preflight are
// where the platform refusal lives.
func (Adapter) Render(spec tunnel.Spec) (string, error) {
	mode, k, err := validate(spec)
	if err != nil {
		return "", err
	}
	return renderConfig(spec, mode, k, spec.Secrets[SecretToken]), nil
}

// Start brings one side up: validate, refuse a host that cannot run this
// tool, write the config, bind the counting proxy, exec the pinned binary.
func (Adapter) Start(_ context.Context, spec tunnel.Spec, ports tunnel.Ports) (tunnel.Handle, error) {
	mode, k, err := prepare(spec, ports)
	if err != nil {
		return nil, err
	}
	cfgDir := spec.Params[tunnel.ParamConfigDir]
	if cfgDir == "" {
		return nil, fmt.Errorf("backhaul: %s is not set — the Manager sets it before Start", tunnel.ParamConfigDir)
	}
	// Host checks come after every caller-side check: a node that cannot run
	// this tool says so only once the spec in front of it is worth running.
	if runtime.GOOS == "windows" {
		return nil, errNoWindows()
	}
	bin := spec.Params[tunnel.ParamBinaryPath]
	if bin == "" {
		// The Manager always injects it for a tool with a pin; resolving
		// here keeps a direct Adapter.Start (tests, a future caller) on the
		// same verified binary rather than a bare PATH lookup.
		if bin, err = tunnel.ResolveBinary(Tool, ""); err != nil {
			return nil, err
		}
	}

	h := &handle{
		spec:   spec,
		ports:  ports,
		mode:   mode,
		knobs:  k,
		bin:    bin,
		cfgDir: cfgDir,
		logs:   make(chan string, 1024),
		lines:  make(chan nodeLogger.LogLine, 1024),
	}
	if err := h.start(); err != nil {
		h.Shutdown()
		return nil, err
	}
	return h, nil
}

// Preflight is what this host cannot do for this spec. Empty means ready.
func (Adapter) Preflight(_ context.Context, spec tunnel.Spec) []tunnel.Problem {
	if runtime.GOOS == "windows" {
		// Nothing else can be answered on a host that cannot run the binary.
		return []tunnel.Problem{windowsProblem()}
	}
	var out []tunnel.Problem
	if err := spec.Validate(); err != nil {
		out = append(out, tunnel.Problem{Check: "params", Detail: err.Error()})
	} else if _, err := resolveMode(spec.Mode); err != nil {
		out = append(out, tunnel.Problem{
			Check:  "mode",
			Detail: err.Error(),
			Fix:    "use mode=relay (forward) or mode=reverse (publish a service behind side b)",
		})
	} else if _, err := knobsOf(spec); err != nil {
		out = append(out, tunnel.Problem{Check: "params", Detail: err.Error()})
	}
	return append(out, tunnel.CheckBinary(Tool)...)
}

// handle is one running side: the counting proxy plus the Backhaul process.
type handle struct {
	spec   tunnel.Spec
	ports  tunnel.Ports
	mode   string
	knobs  knobs
	bin    string
	cfgDir string

	logs  chan string
	lines chan nodeLogger.LogLine

	started atomic.Bool

	mu       sync.Mutex
	sh       *shim
	cmd      *exec.Cmd
	done     chan struct{}
	exitErr  error
	stopping bool
	tail     []string
}

// start is the whole bring-up, shared by Start and Restart. Every failure
// path leaves nothing behind: the proxy is closed and the process, if one
// got as far as starting, is killed.
func (h *handle) start() error {
	h.mu.Lock()
	h.stopping = false
	h.tail = nil
	h.mu.Unlock()

	// Side a needs a third port: Backhaul's own ingress listener, reached
	// only by the proxy. Side b's proxy is what Backhaul's client dials, so
	// it takes an ephemeral loopback port and tells the config its number.
	var (
		ingress  int
		proxyNet string
		backend  string
	)
	if h.spec.Side == tunnel.SideA {
		p, err := pickPort(h.ports.Listen, h.ports.Control)
		if err != nil {
			return err
		}
		ingress = p
		proxyNet = net.JoinHostPort(h.knobs.listenHost, strconv.Itoa(h.ports.Listen))
		backend = net.JoinHostPort("127.0.0.1", strconv.Itoa(ingress))
	} else {
		peer, err := transportAddr(h.knobs.peer)
		if err != nil {
			return err
		}
		proxyNet = net.JoinHostPort("127.0.0.1", "0")
		backend = peer
	}

	sh, err := newShim(proxyNet, backend, h.publish)
	if err != nil {
		return err
	}
	h.mu.Lock()
	h.sh = sh
	h.mu.Unlock()

	tokens := map[string]int{}
	switch h.spec.Side {
	case tunnel.SideA:
		tokens[tokControl] = h.ports.Control
		tokens[tokIngress] = ingress
	default:
		_, port, err := net.SplitHostPort(sh.addr)
		if err != nil {
			return fmt.Errorf("backhaul: proxy bound %q: %w", sh.addr, err)
		}
		tokens[tokShim], _ = strconv.Atoi(port)
	}
	cfg := substPorts(renderConfig(h.spec, h.mode, h.knobs, h.spec.Secrets[SecretToken]), tokens)
	cfgPath := filepath.Join(h.cfgDir, cfgName)
	// 0600: this file carries the tunnel token (CONTRACT §2.1).
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		return fmt.Errorf("backhaul: write %s: %w", cfgPath, err)
	}

	cmd := exec.Command(h.bin, "-c", cfgPath)
	cmd.Dir = h.cfgDir
	out := &lineWriter{h: h}
	errW := &lineWriter{h: h}
	cmd.Stdout = out
	cmd.Stderr = errW
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("backhaul: start %s: %w", h.bin, err)
	}
	done := make(chan struct{})
	h.mu.Lock()
	h.cmd = cmd
	h.done = done
	h.mu.Unlock()
	go func() {
		err := cmd.Wait()
		h.mu.Lock()
		h.exitErr = err
		wasStopping := h.stopping
		h.mu.Unlock()
		close(done)
		if wasStopping {
			return // our own Shutdown: not news
		}
		h.started.Store(false)
		h.publish(nodeLogger.LogError, "side=%s process exited: %v", h.spec.Side, err)
	}()

	select {
	case <-done:
		return fmt.Errorf("backhaul: %s exited during start-up: %v\n%s", h.bin, h.exitErr, h.tailText())
	case <-time.After(startupWait):
	}

	h.started.Store(true)
	h.publish(nodeLogger.LogInfo, "side=%s mode=%s proxy on %s -> %s, binary %s (config %s)",
		h.spec.Side, h.mode, sh.addr, backend, h.bin, cfgPath)
	return nil
}

// Started reports whether the side is up: proxy bound and process alive.
func (h *handle) Started() bool {
	if !h.started.Load() {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cmd == nil || h.done == nil {
		return false
	}
	select {
	case <-h.done:
		return false
	default:
		return true
	}
}

// Version is the pinned release the binary was verified against.
func (h *handle) Version() string { return Version }

// Logs is the legacy string channel (Backend.Logs' shape).
func (h *handle) Logs() <-chan string { return h.logs }

// LogLines is the classified channel the Manager prefers: backhaul's own
// level travels with the line instead of being guessed downstream.
func (h *handle) LogLines() <-chan nodeLogger.LogLine { return h.lines }

// Stats is aggregate up/down for this side, counted by the proxy that every
// byte crosses. There is no per-user breakdown for a tunnel, ever
// (CONTRACT §3.5).
func (h *handle) Stats(context.Context) (tunnel.Bytes, error) {
	h.mu.Lock()
	sh := h.sh
	h.mu.Unlock()
	if sh == nil {
		return tunnel.Bytes{}, nil
	}
	return tunnel.Bytes{Up: sh.up.Load(), Down: sh.down.Load()}, nil
}

// Restart is stop then start with the same Spec and Ports, re-rendering the
// config — so a restart cannot resurrect a config the spec no longer
// describes. A fresh ingress port is picked: the old one belongs to the
// process that just went away and may already be gone elsewhere.
func (h *handle) Restart() error {
	h.Shutdown()
	return h.start()
}

// Shutdown takes the proxy down, kills the process and waits for it. Idempotent.
func (h *handle) Shutdown() {
	h.mu.Lock()
	if h.stopping {
		h.mu.Unlock()
		return
	}
	h.stopping = true
	sh, cmd, done := h.sh, h.cmd, h.done
	h.sh, h.cmd = nil, nil
	wasRunning := sh != nil || cmd != nil
	h.mu.Unlock()

	if sh != nil {
		sh.shutdown()
	}
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	if done != nil {
		<-done
	}
	h.started.Store(false)
	if wasRunning {
		h.publish(nodeLogger.LogInfo, "side=%s stopped", h.spec.Side)
	}
}

func (h *handle) tailText() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.tail) == 0 {
		return "    (no output)"
	}
	return "    " + strings.Join(h.tail, "\n    ")
}

// publish sends one line to both channels without ever blocking: a consumer
// that stopped reading must not stall the data path. It also keeps the tail
// Start reports when the process dies on its own config.
func (h *handle) publish(level nodeLogger.LogLevel, format string, args ...any) {
	msg := fmt.Sprintf("backhaul[%s/%s] %s", h.spec.TunnelID, h.spec.Side, fmt.Sprintf(format, args...))
	h.mu.Lock()
	h.tail = append(h.tail, stripANSI(msg))
	if len(h.tail) > tailLines {
		h.tail = h.tail[len(h.tail)-tailLines:]
	}
	h.mu.Unlock()

	select {
	case h.logs <- msg:
	default:
	}
	select {
	case h.lines <- nodeLogger.LogLine{Detail: msg, Level: level, TsUnixMs: time.Now().UnixMilli()}:
	default:
	}
}

// logToolLine publishes one line of Backhaul's own output, with the colour
// codes removed and the level the tool itself declared.
func (h *handle) logToolLine(line string) {
	line = strings.TrimRight(stripANSI(line), "\r")
	if strings.TrimSpace(line) == "" {
		return
	}
	h.publish(nodeLogger.LogLevel(classify(line)), "%s", line)
}

// lineWriter turns a child process's byte stream into log lines. stdout and
// stderr each get their own: exec.Cmd copies each into its own goroutine, and
// the buffer is not shared.
type lineWriter struct {
	h   *handle
	mu  sync.Mutex
	buf []byte
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		w.h.logToolLine(string(w.buf[:i]))
		w.buf = w.buf[i+1:]
	}
	// A line with no newline (a panic without one) must not grow forever.
	if len(w.buf) > 64*1024 {
		w.h.logToolLine(string(w.buf))
		w.buf = w.buf[:0]
	}
	return len(p), nil
}

// shim is the counting proxy every side runs in front of one local listener.
type shim struct {
	addr    string
	backend string
	ln      net.Listener

	// up is local -> backend, down is backend -> local: on side a that is
	// bytes entering the tunnel and bytes returning to the client; on side b
	// it is the tunnel transport in each direction.
	up, down atomic.Uint64

	logf func(nodeLogger.LogLevel, string, ...any)

	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	stopping bool
	wg       sync.WaitGroup
}

func newShim(addr, backend string, logf func(nodeLogger.LogLevel, string, ...any)) (*shim, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("backhaul: listen %s: %w", addr, err)
	}
	s := &shim{addr: ln.Addr().String(), backend: backend, ln: ln, logf: logf, conns: map[net.Conn]struct{}{}}
	s.wg.Add(1)
	go s.acceptLoop()
	return s, nil
}

func (s *shim) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.track(conn, true)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.track(conn, false)
			s.serve(conn)
		}()
	}
}

func (s *shim) track(c net.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.conns[c] = struct{}{}
		return
	}
	delete(s.conns, c)
	_ = c.Close()
}

// serve dials the backend, waiting for it, then pipes bytes through while
// counting them. A backend that never appears is an explicit, logged failure
// — the connection is closed, never held open with nowhere to go.
func (s *shim) serve(client net.Conn) {
	backend, err := s.dialBackend()
	if err != nil {
		s.logf(nodeLogger.LogError, "cannot reach %s: %v (connection refused)", s.backend, err)
		_ = client.Close()
		return
	}
	s.track(backend, true)
	defer s.track(backend, false)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); pipeCount(backend, client, &s.up) }()
	go func() { defer wg.Done(); pipeCount(client, backend, &s.down) }()
	wg.Wait()
	_ = client.Close()
	_ = backend.Close()
}

func (s *shim) dialBackend() (net.Conn, error) {
	deadline := time.Now().Add(backendWait)
	for {
		conn, err := net.DialTimeout("tcp", s.backend, time.Second)
		if err == nil {
			return conn, nil
		}
		s.mu.Lock()
		stopping := s.stopping
		s.mu.Unlock()
		if stopping || time.Now().After(deadline) {
			return nil, err
		}
		time.Sleep(dialPoll)
	}
}

// pipeCount copies src -> dst counting what actually lands, then half-closes
// dst's write side so the peer sees a FIN while the reverse direction can
// still drain.
func pipeCount(dst, src net.Conn, counter *atomic.Uint64) {
	_, _ = io.Copy(countingWriter{w: dst, n: counter}, src)
	if tcp, ok := dst.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
}

type countingWriter struct {
	w io.Writer
	n *atomic.Uint64
}

func (c countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if n > 0 {
		c.n.Add(uint64(n))
	}
	return n, err
}

func (s *shim) shutdown() {
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		return
	}
	s.stopping = true
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()

	_ = s.ln.Close()
	for _, c := range conns {
		_ = c.Close()
	}
	s.wg.Wait()
}
