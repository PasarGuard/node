// Package chisel runs jpillora/chisel as a Phase 3 tunnel adapter
// (CONTRACT.md §2.1): one pinned binary, two roles, no config file — the
// configuration *is* a command line, so Render's job is to produce an argv
// that is byte-identical for one Spec, and Start's job is to exec that argv
// directly (never through a shell: a param that reaches a shell is remote
// code execution).
//
// Mode support (CONTRACT §2.0), both with a passing four-part loopback run:
//
//	relay   side A binds the ingress and runs chisel's *client* (local
//	        forward), side B runs chisel's *server* and delivers to the
//	        target: bytes enter at A, leave at B.
//	reverse side B is behind NAT and dials out as chisel's *client* with a
//	        reverse remote; side A runs chisel's *server*, which publishes
//	        the service on A: bytes enter at A and are delivered to the
//	        listener behind B.
//
// Each side also binds one small shim of its own, on the port the framework
// handed it: side A's shim is the ingress the rest of the system dials, side
// B's shim is what the tunnel delivers to. The shims exist for two reasons
// chisel cannot provide itself: aggregate byte counters (Handle.Stats) and a
// refusal that is explicit instead of a socket that accepts and then holds a
// connection open with no tunnel behind it.
//
// Ports, per side (control is always listen+1, reserved with it):
//
//	        ingress shim   chisel's own bind      published port
//	relay   A: listen      A: listen+1 (client L)  —
//	        B: listen+1    B: listen (server ws)   —
//	reverse A: listen      A: listen+1 (server ws) params.publish_port
//	        B: listen+1    B: — (client binds none)
package chisel

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os/exec"
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
	if err := tunnel.RegisterPinJSON(pinsJSON, Tool+"/pins.json"); err != nil {
		panic("chisel: " + err.Error())
	}
}

const (
	// ingressWait is how long side A's shim holds an arriving connection while
	// waiting for the tunnel itself to come up. Long enough for chisel's
	// client retry backoff to land, short enough that a wrong credential is a
	// fast, logged refusal instead of a client's 10s read timeout.
	ingressWait = 5 * time.Second
	// dialAttempt / dialGap bound each upstream connect inside that window.
	dialAttempt = time.Second
	dialGap     = 100 * time.Millisecond
	// startWindow is how long Start watches the freshly spawned process for an
	// immediate exit (bad remote, port already in use, invalid flag).
	startWindow = 250 * time.Millisecond
	// tailLines is how many process lines Start keeps for an error message.
	tailLines = 8
)

// Adapter implements tunnel.Adapter.
type Adapter struct{}

var _ tunnel.Adapter = Adapter{}

// Render produces the chisel argv for one side as a JSON array of arguments
// (argv[0] is the tool name; the resolved, hash-verified binary replaces it at
// Start). Pure and deterministic: no ports from the allocator, no environment,
// no secret values — only Spec.Params.
func (Adapter) Render(spec tunnel.Spec) (string, error) { return renderJSON(spec) }

// Preflight reports what this host or this Spec cannot do; empty means ready.
func (Adapter) Preflight(_ context.Context, spec tunnel.Spec) []tunnel.Problem {
	var out []tunnel.Problem
	if err := spec.Validate(); err != nil {
		return []tunnel.Problem{{Check: "params", Detail: err.Error()}}
	}
	for _, key := range requiredParams(spec) {
		if strings.TrimSpace(spec.Params[key]) == "" {
			out = append(out, tunnel.Problem{
				Check: "params",
				Detail: fmt.Sprintf("side %s of mode %s needs params.%s",
					spec.Side, modeOf(spec), key),
			})
		}
	}
	if _, ok := spec.Secrets[SecretAuth]; !ok {
		out = append(out, tunnel.Problem{
			Check:  "secret",
			Detail: fmt.Sprintf("secret_names must include %s (value \"user:pass\"), or chisel refuses to start", SecretAuth),
			Fix:    "add " + SecretAuth + " to the tunnel's secret names",
		})
	}
	// A Spec that cannot render cannot start either: report the argv's own
	// complaints (bad port, colliding publish port, malformed path) verbatim.
	if _, err := renderArgv(withListenPort(spec)); err != nil {
		out = append(out, tunnel.Problem{Check: "params", Detail: err.Error()})
	}
	out = append(out, tunnel.CheckBinary(Tool)...)
	return out
}

// withListenPort gives renderArgv a listen_port when the caller has none, so
// Preflight's argv check is about the *other* params rather than about a port
// the node has not allocated yet.
func withListenPort(spec tunnel.Spec) tunnel.Spec {
	if strings.TrimSpace(spec.Params[tunnel.ParamListenPort]) != "" {
		return spec
	}
	out := spec.Clone()
	if out.Params == nil {
		out.Params = map[string]string{}
	}
	out.Params[tunnel.ParamListenPort] = "1"
	return out
}

// Start brings one side up: validate, resolve the secret and the pinned
// binary, bind this side's shim, then exec chisel with an explicit argv.
func (Adapter) Start(_ context.Context, spec tunnel.Spec, ports tunnel.Ports) (tunnel.Handle, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if ports.Listen < 1 || ports.Listen > 65534 {
		return nil, fmt.Errorf("chisel: listen port %d is not usable (need 1-65534; the control port is listen+1)",
			ports.Listen)
	}

	pspec := spec.Clone()
	if pspec.Params == nil {
		pspec.Params = map[string]string{}
	}
	// The panel pins listen_port so the other side can write `peer` from it;
	// when it did not, the allocated port becomes the pin for this run. A
	// disagreement between the two is a bug upstream, not something to paper
	// over by listening somewhere the peer was not told about.
	if raw := strings.TrimSpace(pspec.Params[tunnel.ParamListenPort]); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n != ports.Listen {
			return nil, fmt.Errorf("chisel: params.%s=%q but the node allocated port %d",
				tunnel.ParamListenPort, raw, ports.Listen)
		}
	} else {
		pspec.Params[tunnel.ParamListenPort] = strconv.Itoa(ports.Listen)
	}

	auth, err := authOf(pspec)
	if err != nil {
		return nil, err
	}

	bin := strings.TrimSpace(pspec.Params[tunnel.ParamBinaryPath])
	if bin == "" {
		// The Manager injects pg_binary_path for any tool with a pin; resolve
		// here only so a direct Adapter.Start (tests, tools) still runs the
		// hash-checked binary and never a random chisel on PATH.
		if bin, err = tunnel.ResolveBinary(Tool, ""); err != nil {
			return nil, err
		}
	}

	argv, err := renderArgv(pspec)
	if err != nil {
		return nil, err
	}

	h := &handle{
		spec:   pspec,
		ports:  ports,
		host:   hostOf(pspec),
		mode:   modeOf(pspec),
		bin:    bin,
		argv:   argv,
		auth:   auth,
		logs:   make(chan string, 1024),
		lines:  make(chan nodeLogger.LogLine, 1024),
		target: strings.TrimSpace(pspec.Params[paramTarget]),
	}
	if h.mode == tunnel.ModeReverse {
		h.publish = strconv.Itoa(mustPort(pspec, paramPublishPort))
	}
	if err := h.start(); err != nil {
		return nil, fmt.Errorf("tunnel %s/%s (%s): %w", pspec.TunnelID, pspec.Side, Tool, err)
	}
	return h, nil
}

func mustPort(spec tunnel.Spec, key string) int {
	n, err := intParam(spec, key)
	if err != nil {
		return 0 // renderArgv already refused a Spec without it
	}
	return n
}

// handle is one running side: a chisel process, this side's shim, and the log
// ring feeds the Manager pumps.
type handle struct {
	spec    tunnel.Spec
	ports   tunnel.Ports
	host    string
	mode    string
	bin     string
	argv    []string
	auth    string
	target  string // side B: where the egress shim delivers
	publish string // reverse: side A's published port, as a string

	logs  chan string
	lines chan nodeLogger.LogLine

	mu       sync.Mutex
	shim     *shim
	cmd      *exec.Cmd
	exited   chan struct{}
	waitErr  error
	stopping bool
	tailBuf  []string

	started  atomic.Bool
	clientUp atomic.Bool  // chisel client: ssh session established
	sessions atomic.Int32 // chisel server: open sessions
	up       atomic.Uint64
	down     atomic.Uint64
}

// start binds this side's shim, then spawns chisel. The shim binds first: a
// port that is already taken must fail the Start, not be discovered after a
// process is running.
func (h *handle) start() error {
	bindHost := h.host
	shimBind := net.JoinHostPort(bindHost, strconv.Itoa(h.ports.Listen))
	var upstream string
	var gate func() bool
	if h.spec.Side == tunnel.SideA {
		// Ingress: hand off to this side's own chisel endpoint.
		if h.mode == tunnel.ModeRelay {
			upstream = net.JoinHostPort(dialHost(h.host), strconv.Itoa(h.ports.Listen+1))
		} else {
			upstream = net.JoinHostPort(dialHost(h.host), h.publish)
		}
		gate = h.ingressReady
	} else {
		// Egress: what chisel delivers to.
		shimBind = net.JoinHostPort(bindHost, strconv.Itoa(h.ports.Listen+1))
		upstream = h.target
	}
	sh, err := newShim(h, shimBind, upstream, gate)
	if err != nil {
		return err
	}

	cmd := exec.Command(h.bin, h.argv[1:]...) // explicit argv, never a shell
	cmd.Env = authEnv(h.auth)
	lw := &lineWriter{handle: h}
	cmd.Stdout = lw
	cmd.Stderr = lw

	if err := cmd.Start(); err != nil {
		sh.stop()
		return fmt.Errorf("exec %s: %w", h.bin, err)
	}
	exited := make(chan struct{})
	h.mu.Lock()
	h.shim, h.cmd, h.exited = sh, cmd, exited
	h.waitErr = nil
	h.mu.Unlock()

	go func() {
		waitErr := cmd.Wait()
		h.mu.Lock()
		h.waitErr = waitErr
		unexpected := !h.stopping
		h.mu.Unlock()
		close(exited)
		if unexpected {
			h.started.Store(false)
			h.clientUp.Store(false)
			h.sessions.Store(0)
			h.logf(nodeLogger.LogError, "chisel exited: %v%s", waitErr, h.tail())
		}
	}()

	// Catch the failures that kill chisel inside its first quarter second —
	// a remote it will not decode, a port someone else holds — while Start can
	// still refuse instead of reporting a tunnel that is already dead.
	deadline := time.Now().Add(startWindow)
	for {
		select {
		case <-exited:
			sh.stop()
			err := h.waitErr
			return fmt.Errorf("chisel exited during start: %v%s", err, h.tail())
		case <-time.After(10 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			break
		}
	}

	h.started.Store(true)
	h.logf(nodeLogger.LogInfo, "side=%s mode=%s started (binary %s, argv %s)",
		h.spec.Side, h.mode, h.bin, mustJSON(h.argv))
	return nil
}

// ingressReady is the gate side A's shim applies to arriving connections: the
// socket chisel would hand them to exists either way, so without this gate a
// tunnel with a wrong credential would accept a connection and sit on it.
func (h *handle) ingressReady() bool {
	if h.spec.Side != tunnel.SideA {
		return true
	}
	if h.mode == tunnel.ModeRelay {
		return h.clientUp.Load()
	}
	return h.sessions.Load() > 0
}

// stop tears the side down: shim first (no new connections), then the process,
// then wait for it. Safe to call twice; Restart calls it and starts again.
func (h *handle) stop() {
	h.mu.Lock()
	if h.stopping {
		h.mu.Unlock()
		return
	}
	h.stopping = true
	sh, cmd, exited := h.shim, h.cmd, h.exited
	h.shim, h.cmd, h.exited = nil, nil, nil
	h.mu.Unlock()

	if sh != nil {
		sh.stop()
	}
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	if exited != nil {
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			h.logf(nodeLogger.LogWarning, "chisel did not exit within 5s of being killed")
		}
	}
	h.mu.Lock()
	h.stopping = false
	h.mu.Unlock()
	h.started.Store(false)
	h.clientUp.Store(false)
	h.sessions.Store(0)
}

// Shutdown stops the side. Idempotent.
func (h *handle) Shutdown() {
	h.stop()
	h.logf(nodeLogger.LogInfo, "side=%s stopped", h.spec.Side)
}

// Restart is stop-then-start with the same Spec, Ports and argv: no manual
// step, no re-render drift (the Manager normally does this as Stop+Start).
func (h *handle) Restart() error {
	h.stop()
	return h.start()
}

func (h *handle) Started() bool       { return h.started.Load() }
func (h *handle) Version() string     { return Version }
func (h *handle) Logs() <-chan string { return h.logs }

// LogLines is the classified channel the Manager prefers (node/logger's
// LogLiner): the level travels with the line instead of being guessed from
// chisel's wording downstream.
func (h *handle) LogLines() <-chan nodeLogger.LogLine { return h.lines }

// Stats is this side's shim counters, aggregate for the whole tunnel
// (CONTRACT §3.5). A tunnel never sees a user, so there is nothing per-user
// to report and nothing that could be added.
func (h *handle) Stats(context.Context) (tunnel.Bytes, error) {
	return tunnel.Bytes{Up: h.up.Load(), Down: h.down.Load()}, nil
}

// onLine is every line chisel writes to stdout or stderr: keep the readiness
// bookkeeping, classify it, and publish it under this tunnel's id.
func (h *handle) onLine(line string) {
	line = strings.TrimRight(line, "\r")
	if line == "" {
		return
	}
	// Readiness, from chisel's own words (v1.12.0): the client prints
	// "Connected (Latency …)" once the ssh session is up and "Connection
	// error:" whenever it is not; the server prints "session#N: Open"/"Close".
	if strings.Contains(line, "Connected ") {
		h.clientUp.Store(true)
	}
	if strings.Contains(line, "Connection error") || strings.Contains(line, "Disconnected") {
		h.clientUp.Store(false)
	}
	if strings.Contains(line, "session#") {
		switch {
		case strings.Contains(line, " Open ("):
			h.sessions.Add(1)
		case strings.Contains(line, " Close ("):
			if h.sessions.Add(-1) < 0 {
				h.sessions.Store(0)
			}
		}
	}
	h.pushTail(line)
	h.logf(classifyLine(line), "%s", line)
}

// logf publishes one line to both channels without ever blocking: a consumer
// that stopped reading must not stall a data path.
func (h *handle) logf(level nodeLogger.LogLevel, format string, args ...any) {
	msg := fmt.Sprintf("chisel[%s/%s] %s", h.spec.TunnelID, h.spec.Side, fmt.Sprintf(format, args...))
	select {
	case h.logs <- msg:
	default:
	}
	select {
	case h.lines <- nodeLogger.LogLine{
		Detail:   msg,
		Level:    level,
		TsUnixMs: time.Now().UnixMilli(),
	}:
	default:
	}
}

func (h *handle) pushTail(line string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.tailBuf = append(h.tailBuf, line)
	if len(h.tailBuf) > tailLines {
		h.tailBuf = h.tailBuf[len(h.tailBuf)-tailLines:]
	}
}

// tail is the last few process lines, for the error Start returns when chisel
// dies immediately. Never includes the environment, so it cannot leak AUTH.
func (h *handle) tail() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.tailBuf) == 0 {
		return ""
	}
	return "\nlast output:\n  " + strings.Join(h.tailBuf, "\n  ")
}

func mustJSON(v any) string {
	out, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(out)
}

// classifyLine maps a chisel line onto node/logger's levels. chisel words its
// failures inconsistently ("Login failed" is an INFO line upstream), and the
// testkit's negative control asks for an *Error* record, so the mapping lives
// here rather than being left to a substring guess downstream.
func classifyLine(line string) nodeLogger.LogLevel {
	l := strings.ToLower(line)
	switch {
	case strings.Contains(l, "login failed"), strings.Contains(l, "authentication failed"),
		strings.Contains(l, "connection error"), strings.Contains(l, "error"),
		strings.Contains(l, "failed"), strings.Contains(l, "refused"),
		strings.Contains(l, "denied"), strings.Contains(l, "mismatch"),
		strings.Contains(l, "cannot"), strings.Contains(l, "panic"):
		return nodeLogger.LogError
	case strings.Contains(l, "warn"), strings.Contains(l, "retrying"):
		return nodeLogger.LogWarning
	}
	return nodeLogger.LogInfo
}

// lineWriter turns the process's stdout/stderr into whole lines. One writer
// for both streams, mutex-guarded: exec may call Write from two goroutines.
type lineWriter struct {
	handle *handle
	mu     sync.Mutex
	buf    []byte
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
		w.handle.onLine(string(w.buf[:i]))
		w.buf = w.buf[i+1:]
	}
	return len(p), nil
}

// shim is this side's own listener: side A's ingress, side B's egress. It
// counts both directions (Handle.Stats) and it refuses a connection that
// cannot be carried, instead of holding it open with no tunnel behind it.
type shim struct {
	h        *handle
	ln       net.Listener
	bind     string
	upstream string
	gate     func() bool // nil = nothing to wait for (side B's egress)
	wg       sync.WaitGroup
	stopped  atomic.Bool
}

func newShim(h *handle, bind, upstream string, gate func() bool) (*shim, error) {
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", bind, err)
	}
	s := &shim{h: h, ln: ln, bind: bind, upstream: upstream, gate: gate}
	s.wg.Add(1)
	go s.acceptLoop()
	h.logf(nodeLogger.LogInfo, "side=%s shim listening on %s -> %s", h.spec.Side, bind, upstream)
	return s, nil
}

func (s *shim) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if !s.stopped.Load() {
				s.h.logf(nodeLogger.LogError, "shim %s: accept: %v", s.bind, err)
			}
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.forward(conn)
		}()
	}
}

// forward dials the upstream (waiting for the tunnel if there is a gate),
// pipes both ways, counting as it goes.
func (s *shim) forward(conn net.Conn) {
	defer conn.Close()
	up, err := s.dialUpstream()
	if err != nil {
		s.h.logf(nodeLogger.LogError, "shim %s -> %s refused the connection: %v", s.bind, s.upstream, err)
		return
	}
	defer up.Close()
	s.h.logf(nodeLogger.LogInfo, "shim %s -> %s established", s.bind, s.upstream)
	s.pipe(conn, up)
}

// dialUpstream retries until the tunnel is up or ingressWait runs out. The
// gate covers "the tunnel has not connected yet"; the retry also covers the
// moment between the session opening and chisel's server binding the port it
// publishes for it.
func (s *shim) dialUpstream() (net.Conn, error) {
	deadline := time.Now().Add(ingressWait)
	var lastErr error
	for {
		if s.gate == nil || s.gate() {
			dialCtx, cancel := context.WithTimeout(context.Background(), dialAttempt)
			conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", s.upstream)
			cancel()
			if err == nil {
				return conn, nil
			}
			lastErr = err
		} else {
			lastErr = fmt.Errorf("tunnel is not established")
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("gave up after %s: %w", ingressWait, lastErr)
		}
		time.Sleep(dialGap)
	}
}

// pipe copies both directions, counting per write so Stats answers while the
// tunnel is still carrying traffic, and half-closing the write side when a
// direction ends so the peer sees a FIN while the other side drains.
func (s *shim) pipe(near, far net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		copyHalf(far, near, &s.h.up)
	}()
	go func() {
		defer wg.Done()
		copyHalf(near, far, &s.h.down)
	}()
	wg.Wait()
}

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

func (s *shim) stop() {
	s.stopped.Store(true)
	_ = s.ln.Close()
	s.wg.Wait()
}

var _ io.Writer = (*lineWriter)(nil)
