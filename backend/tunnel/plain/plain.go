// Package plain is the reference tunnel adapter: an in-process TCP relay in
// the nginx-stream / socat style, built from Go's stdlib `net` and no external
// binary — so it ships no pins.json and works on a host with no bundle.
//
// It exists to prove node/backend/tunnel's adapter seam before the six binary
// tools land, and to be the worked example their agents copy: deterministic
// Render, explicit refusal of untested modes, a secret that must match on both
// ends, byte counters, per-tunnel log lines.
//
// Mode support: `relay` only. `reverse` has no passing loopback run, so Render
// and Start refuse it (CONTRACT §2.0) instead of falling through to a default.
package plain

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pasarguard/node/backend/tunnel"
	nodeLogger "github.com/pasarguard/node/logger"
)

const (
	// Tool is the registered adapter name.
	Tool = "plain"
	// Version is what Handle.Version and Status.version report.
	Version = "plain-1.0.0"
	// SecretToken is the env var / secret name both sides must agree on. When
	// it is unset the relay still runs, and says so in its log: an operator who
	// wants an authenticated tunnel declares PLAIN_TOKEN on both nodes.
	SecretToken = "PLAIN_TOKEN"

	paramListenHost = "listen_host" // bind address, default 127.0.0.1
	paramPeer       = "peer"        // side a: where to dial (side b's listen)
	paramTarget     = "target"      // side b: the destination to deliver to

	// Handshake framing: one line each way before any payload, so a wrong
	// token is an explicit, logged failure instead of a half-open tunnel.
	hsPrefix  = "PG-PLAIN/1"
	hsOK      = hsPrefix + " OK\n"
	hsDenied  = hsPrefix + " DENIED\n"
	hsTimeout = 10 * time.Second
)

func init() { tunnel.Register(Tool, Adapter{}) }

// Adapter implements tunnel.Adapter.
type Adapter struct{}

var _ tunnel.Adapter = Adapter{}

// Render is pure and deterministic: sorted params, fixed layout, the mode
// spelled out. Two renders of one Spec are byte-identical, which is what makes
// the testkit's restart step meaningful.
func (Adapter) Render(spec tunnel.Spec) (string, error) {
	if err := spec.Validate(); err != nil {
		return "", err
	}
	mode := spec.Mode
	if mode == "" {
		mode = tunnel.ModeRelay
	}
	if mode != tunnel.ModeRelay {
		return "", fmt.Errorf("%w: plain has only a passing loopback test for mode=%s, not %q",
			tunnel.ErrModeUnsupported, tunnel.ModeRelay, mode)
	}

	var b strings.Builder
	b.WriteString("# plain relay config — written by the PasarGuard node\n")
	fmt.Fprintf(&b, "tunnel_id = %s\n", spec.TunnelID)
	fmt.Fprintf(&b, "mode = %s\n", mode)
	fmt.Fprintf(&b, "side = %s\n", spec.Side)
	fmt.Fprintf(&b, "tool_version = %s\n", spec.ToolVersion)
	for _, k := range tunnel.SortedParams(spec.Params) {
		fmt.Fprintf(&b, "%s = %s\n", k, spec.Params[k])
	}
	return b.String(), nil
}

// Start brings one side up in-process.
//
// relay, side a: listens for the ingress client, dials side b (Params["peer"]),
// authenticates, pipes bytes and counts them.
// relay, side b: listens for side a's dial, authenticates, dials
// Params["target"] and delivers.
func (Adapter) Start(ctx context.Context, spec tunnel.Spec, ports tunnel.Ports) (tunnel.Handle, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	mode := spec.Mode
	if mode == "" {
		mode = tunnel.ModeRelay
	}
	if mode != tunnel.ModeRelay {
		return nil, fmt.Errorf("%w: plain supports mode=%s only (reverse has no passing loopback test)",
			tunnel.ErrModeUnsupported, tunnel.ModeRelay)
	}
	switch spec.Side {
	case tunnel.SideA:
		if strings.TrimSpace(spec.Params[paramPeer]) == "" {
			return nil, fmt.Errorf("plain: side a needs params.%s (side b's listen address)", paramPeer)
		}
	case tunnel.SideB:
		if strings.TrimSpace(spec.Params[paramTarget]) == "" {
			return nil, fmt.Errorf("plain: side b needs params.%s (the destination to deliver to)", paramTarget)
		}
	}

	token := spec.Secrets[SecretToken]
	if strings.ContainsAny(token, "\n\r") {
		return nil, fmt.Errorf("plain: %s contains a line break", SecretToken)
	}

	host := spec.Params[paramListenHost]
	if host == "" {
		// Loopback by default: a tunnel that must accept remote peers says so
		// explicitly. Failing closed beats silently binding the world.
		host = "127.0.0.1"
	}

	h := &handle{
		spec:  spec,
		ports: ports,
		host:  host,
		token: token,
		logs:  make(chan string, 1024),
		lines: make(chan nodeLogger.LogLine, 1024),
		conns: map[net.Conn]struct{}{},
	}
	if err := h.listen(); err != nil {
		return nil, err
	}
	h.started.Store(true)
	h.logf(nodeLogger.LogInfo, "side=%s mode=%s listening on %s (token %s)",
		spec.Side, mode, h.addr(), tokenStatus(token))
	return h, nil
}

// Preflight: what this host/spec cannot do. Empty means ready.
func (Adapter) Preflight(_ context.Context, spec tunnel.Spec) []tunnel.Problem {
	var out []tunnel.Problem
	if err := spec.Validate(); err != nil {
		return []tunnel.Problem{{Check: "params", Detail: err.Error()}}
	}
	mode := spec.Mode
	if mode == "" {
		mode = tunnel.ModeRelay
	}
	if mode != tunnel.ModeRelay {
		out = append(out, tunnel.Problem{
			Check:  "mode",
			Detail: fmt.Sprintf("plain is only tested in mode=%s; %q has no passing loopback run", tunnel.ModeRelay, mode),
			Fix:    "use mode=relay, or a tool that supports this mode",
		})
	}
	if spec.Side == tunnel.SideA && strings.TrimSpace(spec.Params[paramPeer]) == "" {
		out = append(out, tunnel.Problem{Check: "params", Detail: "side a needs params.peer (side b's listen address)"})
	}
	if spec.Side == tunnel.SideB && strings.TrimSpace(spec.Params[paramTarget]) == "" {
		out = append(out, tunnel.Problem{Check: "params", Detail: "side b needs params.target (the destination to deliver to)"})
	}
	return out
}

func tokenStatus(token string) string {
	if token == "" {
		return "unset — peers are not authenticated (set " + SecretToken + " to require one)"
	}
	return "required"
}

type handle struct {
	spec  tunnel.Spec
	ports tunnel.Ports
	host  string
	token string

	logs  chan string
	lines chan nodeLogger.LogLine

	started atomic.Bool
	up      atomic.Uint64 // client -> target
	down    atomic.Uint64 // target -> client

	mu       sync.Mutex
	ln       net.Listener
	conns    map[net.Conn]struct{}
	stopping bool
	wg       sync.WaitGroup
}

func (h *handle) addr() string { return h.ports.Addr(h.host) }

func (h *handle) listen() error {
	ln, err := net.Listen("tcp", h.addr())
	if err != nil {
		return fmt.Errorf("plain: listen %s: %w", h.addr(), err)
	}
	h.mu.Lock()
	h.ln = ln
	h.stopping = false
	h.mu.Unlock()

	h.wg.Add(1)
	go h.acceptLoop(ln)
	return nil
}

func (h *handle) acceptLoop(ln net.Listener) {
	defer h.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			h.mu.Lock()
			stopping := h.stopping
			h.mu.Unlock()
			if stopping {
				return
			}
			h.logf(nodeLogger.LogError, "side=%s accept error: %v", h.spec.Side, err)
			return
		}
		h.track(conn, true)
		h.wg.Add(1)
		switch h.spec.Side {
		case tunnel.SideA:
			go func() { defer h.wg.Done(); defer h.track(conn, false); h.serveIngress(conn) }()
		default:
			go func() { defer h.wg.Done(); defer h.track(conn, false); h.serveFarSide(conn) }()
		}
	}
}

func (h *handle) track(c net.Conn, add bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if add {
		h.conns[c] = struct{}{}
		return
	}
	delete(h.conns, c)
	_ = c.Close()
}

// serveIngress is side a: an external client arrived, deliver it through b.
func (h *handle) serveIngress(client net.Conn) {
	peerAddr := h.spec.Params[paramPeer]
	upstream, err := net.DialTimeout("tcp", peerAddr, hsTimeout)
	if err != nil {
		h.logf(nodeLogger.LogError, "side=a dial peer %s: %v", peerAddr, err)
		_ = client.Close()
		return
	}
	h.track(upstream, true)
	defer h.track(upstream, false)

	handshake := hsPrefix + " " + tokenOrDash(h.token) + "\n"
	if _, err := io.WriteString(upstream, handshake); err != nil {
		h.logf(nodeLogger.LogError, "side=a handshake write to %s: %v", peerAddr, err)
		_ = client.Close()
		return
	}
	reply, err := readLine(upstream, hsTimeout)
	if err != nil || reply != strings.TrimRight(hsOK, "\n") {
		h.logf(nodeLogger.LogError, "side=a peer %s refused the handshake (reply=%q err=%v)", peerAddr, reply, err)
		_ = client.Close()
		return
	}
	h.logf(nodeLogger.LogInfo, "side=a established %s -> %s", client.RemoteAddr(), peerAddr)
	h.pipe(client, upstream)
}

// serveFarSide is side b: side a dialled in, authenticate, deliver to target.
func (h *handle) serveFarSide(peer net.Conn) {
	line, err := readLine(peer, hsTimeout)
	if err != nil {
		h.logf(nodeLogger.LogError, "side=b handshake read: %v", err)
		_ = peer.Close()
		return
	}
	got := strings.TrimPrefix(line, hsPrefix+" ")
	if got == line || (h.token != "" && got != h.token) {
		h.logf(nodeLogger.LogError, "side=b token mismatch from %s (denied)", peer.RemoteAddr())
		_, _ = io.WriteString(peer, hsDenied)
		_ = peer.Close()
		return
	}

	targetAddr := h.spec.Params[paramTarget]
	target, err := net.DialTimeout("tcp", targetAddr, hsTimeout)
	if err != nil {
		h.logf(nodeLogger.LogError, "side=b dial target %s: %v", targetAddr, err)
		_, _ = io.WriteString(peer, hsDenied)
		_ = peer.Close()
		return
	}
	h.track(target, true)
	defer h.track(target, false)

	if _, err := io.WriteString(peer, hsOK); err != nil {
		h.logf(nodeLogger.LogError, "side=b handshake ack: %v", err)
		_ = peer.Close()
		return
	}
	h.logf(nodeLogger.LogInfo, "side=b delivering %s -> %s", peer.RemoteAddr(), targetAddr)
	h.pipe(peer, target)
}

// pipe copies both directions between the near side (the conn this side
// accepted or dialled toward the peer) and the far side, counting bytes as
// they move: near -> far is the tunnel's up, far -> near its down
// (CONTRACT §3.5 — whole-tunnel counters, nothing per-user). The count is
// taken per write, not at connection close, so Stats answers while the tunnel
// is still carrying traffic.
func (h *handle) pipe(near, far net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		copyHalf(far, near, &h.up) // near -> far
	}()
	go func() {
		defer wg.Done()
		copyHalf(near, far, &h.down) // far -> near
	}()
	wg.Wait()
	_ = near.Close()
	_ = far.Close()
}

// copyHalf copies src -> dst, counting into counter as bytes are written, and
// half-closes dst's write side when src ends so the peer sees a FIN while the
// reverse direction can still drain.
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

// readLine reads one '\n'-terminated line byte by byte. A bufio.Reader would
// over-read into the payload that follows the handshake and lose those bytes;
// the handshake lines are short, so a byte loop is the correct lazy choice.
func readLine(conn net.Conn, timeout time.Duration) (string, error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}
	defer conn.SetReadDeadline(time.Time{})
	var buf []byte
	one := make([]byte, 1)
	for len(buf) < 256 {
		if _, err := conn.Read(one); err != nil {
			return "", err
		}
		if one[0] == '\n' {
			return string(buf), nil
		}
		buf = append(buf, one[0])
	}
	return "", fmt.Errorf("handshake line longer than 256 bytes")
}

func tokenOrDash(token string) string {
	if token == "" {
		return "-"
	}
	return token
}

// Started reports whether the side is listening.
func (h *handle) Started() bool { return h.started.Load() }

// Version is this adapter's own version: plain has no upstream binary.
func (h *handle) Version() string { return Version }

// Logs is the legacy string channel (Backend.Logs' shape).
func (h *handle) Logs() <-chan string { return h.logs }

// LogLines is the classified channel the Manager prefers: the level travels
// with the line instead of being guessed downstream.
func (h *handle) LogLines() <-chan nodeLogger.LogLine { return h.lines }

// Stats returns aggregate bytes for this side. No per-user breakdown exists
// for a tunnel, ever (CONTRACT §3.5).
func (h *handle) Stats(context.Context) (tunnel.Bytes, error) {
	return tunnel.Bytes{Up: h.up.Load(), Down: h.down.Load()}, nil
}

// Restart rebinds the listen port with the same Spec and Ports: stop, then
// start again, no manual step.
func (h *handle) Restart() error {
	h.Shutdown()
	if err := h.listen(); err != nil {
		return err
	}
	h.started.Store(true)
	h.logf(nodeLogger.LogInfo, "side=%s restarted on %s", h.spec.Side, h.addr())
	return nil
}

// Shutdown closes the listener and every live conn, then waits for the
// goroutines. Idempotent.
func (h *handle) Shutdown() {
	h.mu.Lock()
	if h.stopping {
		h.mu.Unlock()
		return
	}
	h.stopping = true
	ln := h.ln
	h.ln = nil
	conns := make([]net.Conn, 0, len(h.conns))
	for c := range h.conns {
		conns = append(conns, c)
	}
	h.mu.Unlock()

	if ln != nil {
		_ = ln.Close()
	}
	for _, c := range conns {
		_ = c.Close()
	}
	h.wg.Wait()
	h.started.Store(false)
	h.logf(nodeLogger.LogInfo, "side=%s stopped", h.spec.Side)
}

// logf publishes one line to both channels, never blocking: a consumer that
// stopped reading must not stall the data path.
func (h *handle) logf(level nodeLogger.LogLevel, format string, args ...any) {
	msg := fmt.Sprintf("plain[%s/%s] %s", h.spec.TunnelID, h.spec.Side, fmt.Sprintf(format, args...))
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
