package wstunnel

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pasarguard/node/backend/tunnel"
	nodeLogger "github.com/pasarguard/node/logger"
)

// Adapter implements tunnel.Adapter for wstunnel.
type Adapter struct{}

var _ tunnel.Adapter = Adapter{}

// readyTimeout is how long Start waits for wstunnel to bind its own port.
const readyTimeout = 5 * time.Second

// authProbeTimeout is how long a side that binds nothing (reverse side b)
// watches for a rejected handshake before it declares itself started. The
// client retries about once a second, so two seconds covers one full cycle
// with slop; a side with a correct secret prints nothing and starts.
const authProbeTimeout = 2 * time.Second

// Render is pure apart from os.Stat on the TLS material (newPlan): same Spec
// ⇒ byte-identical output, the token rendered as a ${WSTUNNEL_TOKEN}
// placeholder, and a missing certificate refused here rather than at the
// first connection.
func (Adapter) Render(spec tunnel.Spec) (string, error) {
	p, err := newPlan(spec, tunnel.Ports{})
	if err != nil {
		return "", err
	}
	version := spec.ToolVersion
	if version == "" {
		if pin, ok := tunnel.PinFor(Tool); ok {
			version = pin.Version
		}
	}
	return p.renderConfig(version), nil
}

// Start brings one side up: resolve the plan, check the pin-verified binary
// (already done by the Manager and handed over in pg_binary_path), bind the
// counting proxy, exec wstunnel, wait for it to be ready.
func (Adapter) Start(_ context.Context, spec tunnel.Spec, ports tunnel.Ports) (tunnel.Handle, error) {
	if ports.Listen <= 0 || ports.Control != ports.Listen+1 {
		return nil, fmt.Errorf("wstunnel: invalid ports %+v (Control must be Listen+1)", ports)
	}
	p, err := newPlan(spec, ports)
	if err != nil {
		return nil, err
	}
	if p.mode == tunnel.ModeReverse && p.side == tunnel.SideA && p.inner == 0 {
		return nil, fmt.Errorf("wstunnel: mode=reverse side=a needs an extra port — allocate with AllocPair(%q)", extraInner)
	}
	token, err := resolvedToken(spec)
	if err != nil {
		return nil, err
	}
	bin := spec.Params[tunnel.ParamBinaryPath]
	if bin == "" {
		return nil, fmt.Errorf("wstunnel: %s is empty — the Manager resolves the pinned binary before Start", tunnel.ParamBinaryPath)
	}
	if _, err := os.Stat(bin); err != nil {
		return nil, fmt.Errorf("wstunnel: binary %q is not runnable: %w", bin, err)
	}

	h := &handle{
		spec: spec, plan: p, ports: ports, bin: bin, token: token,
		logs:  make(chan string, 1024),
		lines: make(chan nodeLogger.LogLine, 1024),
	}
	if err := h.launch(); err != nil {
		return nil, err
	}
	return h, nil
}

// Preflight reports what this host/spec cannot do; empty means ready.
func (Adapter) Preflight(_ context.Context, spec tunnel.Spec) []tunnel.Problem {
	var out []tunnel.Problem
	if _, err := newPlan(spec, tunnel.Ports{}); err != nil {
		check := "params"
		if strings.Contains(err.Error(), tunnel.ErrModeUnsupported.Error()) {
			check = "mode"
		}
		out = append(out, tunnel.Problem{Check: check, Detail: err.Error()})
	}
	return append(out, tunnel.CheckBinary(Tool)...)
}

// resolvedToken requires the credential: an empty value is the same refusal
// as an unresolved secret, and the value may not break the URL path it is
// about to be carried in.
func resolvedToken(spec tunnel.Spec) (string, error) {
	tok := spec.Secrets[SecretToken]
	if tok == "" {
		return "", fmt.Errorf("%w: %s is empty (set it in the node environment)", tunnel.ErrSecretUnresolved, SecretToken)
	}
	if strings.ContainsAny(tok, "/?# \t\r\n") || strings.ContainsAny(tok, "\x00") {
		return "", fmt.Errorf("%s must not contain whitespace, '/', '?' or '#': it is the WebSocket upgrade path prefix", SecretToken)
	}
	return tok, nil
}

// launch binds the counting proxy, starts the process and waits until the
// side is actually usable. Split out of Start so Restart can call it again.
func (h *handle) launch() error {
	bind, err := h.plan.proxyBind()
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		return fmt.Errorf("wstunnel: counting proxy listen %s: %w", bind, err)
	}

	cmd := exec.Command(h.bin, h.plan.args(h.token)...)
	out := &lineWriter{emit: h.publish}
	errOut := &lineWriter{emit: h.publish}
	cmd.Stdout, cmd.Stderr = out, errOut

	if err := cmd.Start(); err != nil {
		_ = ln.Close()
		return fmt.Errorf("wstunnel: start %s: %w", h.bin, err)
	}

	h.mu.Lock()
	h.cmd = cmd
	h.ln = ln
	h.done = make(chan struct{})
	h.stopping = false
	h.flush = func() { out.flush(); errOut.flush() }
	done := h.done
	h.mu.Unlock()

	h.wg.Add(1)
	go h.acceptLoop(ln)
	go h.reap(cmd, done)

	if err := h.waitReady(done); err != nil {
		h.Shutdown()
		return err
	}
	h.started.Store(true)
	h.logf(nodeLogger.LogInfo, "side=%s mode=%s role=%s %s (%s)",
		h.spec.Side, h.plan.mode, h.plan.role, bind, h.bin)
	return nil
}

// reap waits for the process, flushes its last partial log line and records
// why it went away. A death that was not asked for is an Error record — the
// testkit's negative control looks for exactly that.
func (h *handle) reap(cmd *exec.Cmd, done chan struct{}) {
	err := cmd.Wait()
	h.mu.Lock()
	stopping := h.stopping
	flush := h.flush
	h.cmd = nil
	h.mu.Unlock()
	if flush != nil {
		flush()
	}
	h.started.Store(false)
	if stopping {
		h.logf(nodeLogger.LogInfo, "side=%s process stopped", h.spec.Side)
	} else {
		h.logf(nodeLogger.LogError, "side=%s process exited: %v", h.spec.Side, err)
	}
	close(done)
}

// waitReady waits until the port wstunnel itself binds accepts a connection,
// or until the process gives up. A side that never comes up must fail Start
// rather than hand back a handle nothing can use.
func (h *handle) waitReady(done chan struct{}) error {
	addr := h.plan.readyAddr()
	deadline := time.Now().Add(readyTimeout)
	for {
		select {
		case <-done:
			return fmt.Errorf("wstunnel side=%s exited before it was ready:%s", h.spec.Side, h.tailLog())
		default:
		}
		if addr == "" {
			// reverse side b binds nothing of its own: it dials out when the
			// server asks, so there is no listener to wait for. What *is*
			// observable in that window is a rejected handshake — a wrong
			// secret prints one within a retry cycle (verified on v11.0.0:
			// "cannot connect to remote server: failed to do websocket
			// handshake"), and returning a handle that can never connect is
			// exactly the half-open tunnel CONTRACT §2.1 forbids.
			probeEnd := time.Now().Add(authProbeTimeout)
			for {
				if fail := h.authFailure(); fail != "" {
					return fmt.Errorf("wstunnel side=%s cannot reach its peer: %s",
						h.spec.Side, strings.TrimSpace(fail))
				}
				if time.Now().After(probeEnd) {
					// Nothing asked it to connect yet — liveness is all a
					// client that dials on demand can show.
					return nil
				}
				select {
				case <-done:
					return fmt.Errorf("wstunnel side=%s exited during startup", h.spec.Side)
				case <-time.After(100 * time.Millisecond):
				}
			}
		}
		if c, err := net.DialTimeout("tcp", addr, 250*time.Millisecond); err == nil {
			_ = c.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("wstunnel side=%s never listened on %s within %s", h.spec.Side, addr, readyTimeout)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// proxyBind is the address the counting proxy takes: Ports.Listen everywhere
// except reverse side a, where Listen is the published service and Control is
// the WebSocket entry the far side dials.
func (p *plan) proxyBind() (string, error) {
	if p.mode == tunnel.ModeReverse && p.side == tunnel.SideA {
		if p.inner == 0 {
			return "", fmt.Errorf("wstunnel: mode=reverse side=a needs an extra port — allocate with AllocPair(%q)", extraInner)
		}
		return net.JoinHostPort(p.host, strconv.Itoa(p.control)), nil
	}
	return net.JoinHostPort(p.host, strconv.Itoa(p.listen)), nil
}

// proxyTo is what the counting proxy dials: wstunnel's own listener, or (for
// reverse side b) the destination behind this side.
func (p *plan) proxyTo() string {
	if p.mode == tunnel.ModeReverse && p.side == tunnel.SideA {
		return net.JoinHostPort(p.host, strconv.Itoa(p.inner))
	}
	if p.mode == tunnel.ModeReverse {
		return p.target
	}
	return net.JoinHostPort(p.host, strconv.Itoa(p.control))
}

// readyAddr is the port wstunnel binds itself; "" when it binds none.
func (p *plan) readyAddr() string {
	if p.mode == tunnel.ModeReverse && p.side == tunnel.SideB {
		return ""
	}
	return p.proxyTo()
}

// Restart rebinds and re-execs from the same Spec: stop, then start, no
// manual step (CONTRACT's restart obligation).
func (h *handle) Restart() error {
	h.Shutdown()
	return h.launch()
}

// Shutdown stops the process and the proxy. Idempotent.
func (h *handle) Shutdown() {
	h.mu.Lock()
	if h.stopping {
		h.mu.Unlock()
		return
	}
	h.stopping = true
	ln, cmd, done := h.ln, h.cmd, h.done
	h.ln, h.cmd = nil, nil
	h.mu.Unlock()

	if ln != nil {
		_ = ln.Close()
	}
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	if done != nil {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			h.logf(nodeLogger.LogWarning, "side=%s process did not exit within 5s of being killed", h.spec.Side)
		}
	}
	waitGroup(&h.wg, 3*time.Second)
	h.started.Store(false)
}

func waitGroup(wg *sync.WaitGroup, d time.Duration) {
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
	}
}

// Started reports whether the side is up.
func (h *handle) Started() bool { return h.started.Load() }

// Version is the pinned version: the binary was hash-verified against that
// same pin before it was exec'd, so the pin names what is running.
func (h *handle) Version() string {
	if pin, ok := tunnel.PinFor(Tool); ok {
		return Tool + " " + pin.Version
	}
	return Tool + " " + Version
}

// Logs is the legacy string channel (Backend.Logs' shape).
func (h *handle) Logs() <-chan string { return h.logs }

// LogLines is the classified channel the Manager prefers: wstunnel's own
// ERROR/WARN/INFO markers decide the level instead of a substring guess.
func (h *handle) LogLines() <-chan nodeLogger.LogLine { return h.lines }

// Stats returns the counters the proxy measured on this side. Aggregate only:
// a tunnel never sees a user (CONTRACT §3.5).
func (h *handle) Stats(context.Context) (tunnel.Bytes, error) {
	return tunnel.Bytes{Up: h.up.Load(), Down: h.down.Load()}, nil
}

// publish sends one process line to both channels, never blocking: the token
// is redacted first, because wstunnel logs the accepted path prefix verbatim.
func (h *handle) publish(line string) {
	line = redact(stripANSI(line), h.token)
	msg := fmt.Sprintf("wstunnel[%s/%s] %s", h.spec.TunnelID, h.spec.Side, line)
	level := classify(line)
	h.remember(msg)
	select {
	case h.logs <- msg:
	default:
	}
	select {
	case h.lines <- nodeLogger.LogLine{Detail: msg, Level: level, TsUnixMs: time.Now().UnixMilli()}:
	default:
	}
}

func classify(line string) nodeLogger.LogLevel {
	switch {
	case strings.Contains(line, "ERROR"), strings.Contains(line, "failed"),
		strings.Contains(line, "Failed"):
		return nodeLogger.LogError
	case strings.Contains(line, "WARN"), strings.Contains(line, "warn"):
		return nodeLogger.LogWarning
	}
	return nodeLogger.LogInfo
}

// acceptLoop fronts wstunnel's listener and counts both directions.
func (h *handle) acceptLoop(ln net.Listener) {
	defer h.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		h.wg.Add(1)
		go func() { defer h.wg.Done(); h.proxy(conn) }()
	}
}

// proxy pipes one connection through to the far address, counting ingress →
// far as up and far → ingress as down. That is "toward the destination" for
// every shape this adapter runs, so one rule serves all four.
func (h *handle) proxy(ingress net.Conn) {
	defer ingress.Close()
	p := h.plan
	far, err := net.DialTimeout("tcp", p.proxyTo(), 5*time.Second)
	if err != nil {
		h.logf(nodeLogger.LogError, "side=%s dial %s: %v", h.spec.Side, p.proxyTo(), err)
		return
	}
	defer far.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); copyHalf(far, ingress, &h.up) }()
	go func() { defer wg.Done(); copyHalf(ingress, far, &h.down) }()
	wg.Wait()
}

// copyHalf copies src → dst counting into counter, then half-closes dst's
// write side so the peer sees a FIN while the reverse direction drains.
func copyHalf(dst, src net.Conn, counter *atomic.Uint64) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			written := 0
			for written < n {
				m, werr := dst.Write(buf[written:n])
				if m > 0 {
					written += m
					counter.Add(uint64(m))
				}
				if werr != nil {
					return
				}
			}
		}
		if err != nil {
			break
		}
	}
	if tcp, ok := dst.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
}

// logf publishes one line tagged with this tunnel and side, non-blocking.
func (h *handle) logf(level nodeLogger.LogLevel, format string, args ...any) {
	msg := fmt.Sprintf("wstunnel[%s/%s] %s", h.spec.TunnelID, h.spec.Side, fmt.Sprintf(format, args...))
	h.remember(msg)
	select {
	case h.logs <- msg:
	default:
	}
	select {
	case h.lines <- nodeLogger.LogLine{Detail: msg, Level: level, TsUnixMs: time.Now().UnixMilli()}:
	default:
	}
}

// remember keeps the last few lines so a Start that fails can quote what the
// process actually said instead of only that it died.
func (h *handle) remember(msg string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.tail = append(h.tail, msg)
	if len(h.tail) > 8 {
		h.tail = h.tail[len(h.tail)-8:]
	}
}

// tailLog is the quoted tail, or "" when there is nothing yet.
func (h *handle) tailLog() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.tail) == 0 {
		return ""
	}
	return "\n  " + strings.Join(h.tail, "\n  ")
}

// authFailure is the recent error line that means this side can never reach
// its peer — a wrong secret, a refused handshake — or "" if none has appeared
// yet. Only lines that name the connection itself count: a stray ERROR about
// something else must not take a healthy side down.
func (h *handle) authFailure() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, line := range h.tail {
		if classify(line) != nodeLogger.LogError {
			continue
		}
		low := strings.ToLower(line)
		switch {
		case strings.Contains(low, "handshake"),
			strings.Contains(low, "cannot connect"),
			strings.Contains(low, "authentication"),
			strings.Contains(low, "unauthorized"),
			strings.Contains(low, "bad token"):
			return line
		}
	}
	return ""
}

// handle is one running side.
type handle struct {
	spec  tunnel.Spec
	plan  *plan
	ports tunnel.Ports
	bin   string
	token string

	logs  chan string
	lines chan nodeLogger.LogLine

	started atomic.Bool
	up      atomic.Uint64
	down    atomic.Uint64

	mu       sync.Mutex
	ln       net.Listener
	cmd      *exec.Cmd
	done     chan struct{}
	stopping bool
	flush    func()
	tail     []string
	wg       sync.WaitGroup
}

// lineWriter turns a process's byte stream into whole lines for the log ring.
type lineWriter struct {
	mu   sync.Mutex
	buf  []byte
	emit func(string)
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
		w.emit(string(bytes.TrimRight(w.buf[:i], "\r")))
		w.buf = w.buf[i+1:]
	}
	return len(p), nil
}

// flush emits the trailing partial line the process left behind at exit.
func (w *lineWriter) flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.buf) > 0 {
		w.emit(string(bytes.TrimRight(w.buf, "\r\n")))
		w.buf = nil
	}
}

// ansiRE strips whatever colouring wstunnel still emits. The adapter passes
// --no-color, so this is the belt to that brace.
var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

func stripANSI(s string) string {
	if !strings.Contains(s, "\x1b") {
		return s
	}
	return ansiRE.ReplaceAllString(s, "")
}

// redact removes the token from a log line. wstunnel prints the accepted path
// prefix verbatim ("Allow path prefix <token>"), which would otherwise put the
// secret in the ring the panel reads.
func redact(s, token string) string {
	if token == "" || !strings.Contains(s, token) {
		return strings.TrimSpace(s)
	}
	return strings.TrimSpace(strings.ReplaceAll(s, token, "[redacted]"))
}

var _ io.Writer = (*lineWriter)(nil)
