package amnezia

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pasarguard/node/backend/tunnel"
	nodeLogger "github.com/pasarguard/node/logger"
)

// handle is one running side of one amnezia tunnel. Unlike wireguard there IS
// a process: amneziawg-go owns the TUN device, so this type supervises the
// daemon, drives its uapi socket, and owns the address/route lifecycle.
type handle struct {
	spec    tunnel.Spec
	ports   tunnel.Ports
	sp      sideParams
	key     string // private key value; memory and the uapi socket only
	bin     string
	ipBin   string
	ifname  string
	version string

	logs  chan string
	lines chan nodeLogger.LogLine

	started  atomic.Bool
	up       atomic.Uint64 // tx: this side -> peer
	down     atomic.Uint64 // rx: peer -> this side
	lastHS   atomic.Int64  // newest peer handshake timestamp seen
	stopPoll chan struct{}
	pollDone chan struct{}

	mu       sync.Mutex
	stopping bool
	cmd      *exec.Cmd
	waitDone chan error
	exited   atomic.Bool
	// daemonLine is the last line the daemon printed — the only text that
	// explains a bare errno, so a failed uapi set can quote it.
	daemonLine string
}

// logf publishes one record on both channels: the manager prefers LogLines()
// (classified), Logs() stays the plain-string view (gost/plain precedent).
// Detail carries this tunnel's id so a ring is readable on its own.
func (h *handle) logf(level nodeLogger.LogLevel, format string, args ...any) {
	detail := fmt.Sprintf("tunnel %s side %s: %s", h.spec.TunnelID, h.spec.Side, fmt.Sprintf(format, args...))
	line := nodeLogger.LogLine{Detail: detail, Level: level, TsUnixMs: time.Now().UnixMilli()}
	select {
	case h.lines <- line:
	default:
	}
	select {
	case h.logs <- detail:
	default:
	}
}

func (h *handle) rememberDaemon(line string) {
	h.mu.Lock()
	h.daemonLine = line
	h.mu.Unlock()
}

func (h *handle) lastDaemonLine() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.daemonLine
}

// run executes bin with args, prefixed with `ip netns exec <ns>` when this
// side lives in a namespace. Key material never appears in argv: it travels
// only over the uapi socket.
func (h *handle) run(bin string, args ...string) (string, error) {
	var cmd *exec.Cmd
	if ns := h.sp.Netns; ns != "" {
		cmd = exec.Command(h.ipBin, append([]string{"netns", "exec", ns, bin}, args...)...)
	} else {
		cmd = exec.Command(bin, args...)
	}
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// step runs one mutation, logs the result, and on failure returns an error
// that names the step and carries the tool's own output — never a config
// file's contents.
func (h *handle) step(what, bin string, args ...string) (string, error) {
	out, err := h.run(bin, args...)
	if err != nil {
		if out == "" {
			return "", fmt.Errorf("amnezia: %s: %w", what, err)
		}
		return "", fmt.Errorf("amnezia: %s: %w (output: %s)", what, err, out)
	}
	if out == "" {
		h.logf(nodeLogger.LogInfo, "%s: ok", what)
	} else {
		h.logf(nodeLogger.LogInfo, "%s: ok (%s)", what, out)
	}
	return out, nil
}

// uapiConfig is this side's set=1 block: identity, obfuscation, then the one
// authorised peer. Terminated by the blank line the daemon's parser wants.
func (h *handle) uapiConfig() (string, error) {
	selfHex, err := hexKey(h.key, SecretPrivateKey)
	if err != nil {
		return "", fmt.Errorf("amnezia: %s: %v", SecretPrivateKey, err)
	}
	peerHex, err := hexKey(h.sp.PeerPublicKey, "peer_public_key")
	if err != nil {
		return "", fmt.Errorf("amnezia: params.%speer_public_key: %v", h.sp.Prefix, err)
	}
	var b strings.Builder
	b.WriteString("private_key=" + selfHex + "\n")
	fmt.Fprintf(&b, "listen_port=%d\n", h.ports.Listen)
	for _, k := range obfsOrder {
		if v, ok := h.sp.Obfs[k]; ok {
			fmt.Fprintf(&b, "%s=%s\n", k, v)
		}
	}
	b.WriteString("replace_peers=true\n")
	fmt.Fprintf(&b, "public_key=%s\n", peerHex)
	fmt.Fprintf(&b, "endpoint=%s\n", h.sp.PeerEndpoint)
	for _, cidr := range h.sp.Allowed {
		fmt.Fprintf(&b, "allowed_ip=%s\n", cidr)
	}
	b.WriteString("persistent_keepalive_interval=25\n")
	b.WriteString("\n")
	return b.String(), nil
}

// spawn starts the daemon in this side's namespace and waits for its control
// socket. Both streams of the child land in this tunnel's log ring.
func (h *handle) spawn() error {
	var cmd *exec.Cmd
	if ns := h.sp.Netns; ns != "" {
		cmd = exec.Command(h.ipBin, "netns", "exec", ns, h.bin, "-f", h.ifname)
	} else {
		cmd = exec.Command(h.bin, "-f", h.ifname)
	}
	// WG_PROCESS_FOREGROUND=1 keeps the daemon in the foreground under us and
	// silences main.go's "kernel module available" banner; LOG_LEVEL unset
	// means error-only, so the ring stays quiet unless something is wrong.
	cmd.Env = append(os.Environ(), "WG_PROCESS_FOREGROUND=1")
	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("amnezia: pipe %s output: %w", BinaryName, err)
	}
	cmd.Stdout = w
	cmd.Stderr = w
	if err := cmd.Start(); err != nil {
		_ = r.Close()
		_ = w.Close()
		return fmt.Errorf("amnezia: start %s: %w", h.bin, err)
	}
	_ = w.Close() // the child holds the write end; the parent must not

	h.mu.Lock()
	h.cmd = cmd
	done := make(chan error, 1)
	h.waitDone = done
	h.mu.Unlock()
	h.exited.Store(false)

	go h.pumpDaemon(r)
	go func() { done <- cmd.Wait(); h.exited.Store(true) }()

	// The control socket appears once the daemon has opened its TUN device.
	// Waiting for it here means a failure to start is reported by Start, not
	// by a status read five seconds later.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(sockPath(h.ifname)); err == nil {
			break
		}
		if h.exited.Load() {
			out := h.lastDaemonLine()
			_ = r.Close()
			return fmt.Errorf("amnezia: %s exited before its uapi socket appeared (last output: %s)", BinaryName, out)
		}
		if time.Now().After(deadline) {
			_ = r.Close()
			return fmt.Errorf("amnezia: %s did not create %s within 10s", BinaryName, sockPath(h.ifname))
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil
}

// pumpDaemon turns the child's output into log lines. Nothing it prints is
// key material (the daemon never echoes a key), so the ring is safe to read.
func (h *handle) pumpDaemon(r *os.File) {
	defer func() { _ = r.Close() }()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			continue
		}
		h.rememberDaemon(line)
		h.logf(nodeLogger.LogInfo, "%s: %s", BinaryName, line)
	}
}

// bringUp brings this side up: daemon, interface, address, uapi config,
// routes. Any failure on the way tears the partial state down — a leaked
// process or route outlives the tunnel and poisons the next run.
func (h *handle) bringUp() (err error) {
	h.mu.Lock()
	h.stopping = false
	h.mu.Unlock()

	defer func() {
		if err != nil {
			h.stopProcess()
			h.removeLink()
		}
	}()

	if _, e := h.run(h.ipBin, "link", "show", h.ifname); e == nil {
		h.logf(nodeLogger.LogWarning, "interface %s already exists — replacing it", h.ifname)
		if out, e := h.run(h.ipBin, "link", "del", h.ifname); e != nil {
			return fmt.Errorf("amnezia: cannot replace leftover interface %s: %w (output: %s)", h.ifname, e, out)
		}
	}

	if err = h.spawn(); err != nil {
		return err
	}
	if _, err = h.step("create address "+h.sp.Address+" on "+h.ifname, h.ipBin, "addr", "add", h.sp.Address, "dev", h.ifname); err != nil {
		return err
	}
	if _, err = h.step("bring "+h.ifname+" up", h.ipBin, "link", "set", h.ifname, "up"); err != nil {
		return err
	}
	if err = h.configureUAPI(); err != nil {
		return err
	}
	for _, cidr := range h.sp.Allowed {
		if _, err = h.step("route "+cidr+" via "+h.ifname, h.ipBin, "route", "replace", cidr, "dev", h.ifname); err != nil {
			return err
		}
	}

	// The daemon must report this side's listen port before Start succeeds —
	// that is the proof the uapi config actually landed.
	u, err := dialUAPI(h.ifname, 3*time.Second)
	if err != nil {
		return fmt.Errorf("amnezia: %w", err)
	}
	lines, gerr := u.get()
	_ = u.Close()
	if gerr != nil {
		return fmt.Errorf("amnezia: verify uapi config: %w (daemon said: %s)", gerr, h.lastDaemonLine())
	}
	if port, _ := parseGet(lines); port != uint32(h.ports.Listen) {
		return fmt.Errorf("amnezia: daemon reports listen_port=%d, want %d (daemon said: %s)", port, h.ports.Listen, h.lastDaemonLine())
	}

	h.lastHS.Store(0)
	h.started.Store(true)
	return nil
}

// configureUAPI sends this side's identity, obfuscation parameters and its
// one peer to the daemon. The key never leaves this process except as one
// line on a unix socket the daemon owns.
func (h *handle) configureUAPI() error {
	payload, err := h.uapiConfig()
	if err != nil {
		return err
	}
	u, err := dialUAPI(h.ifname, 3*time.Second)
	if err != nil {
		return fmt.Errorf("amnezia: %w", err)
	}
	defer func() { _ = u.Close() }()
	if err := u.set(payload); err != nil {
		if extra := h.lastDaemonLine(); extra != "" {
			return fmt.Errorf("amnezia: configure interface %s: %w (daemon said: %s)", h.ifname, err, extra)
		}
		return fmt.Errorf("amnezia: configure interface %s: %w", h.ifname, err)
	}
	h.logf(nodeLogger.LogInfo, "uapi configured %s: listen_port=%d, peer %s, %d allowed cidr(s), obfuscation %s",
		h.ifname, h.ports.Listen, shortKey(h.sp.PeerPublicKey), len(h.sp.Allowed), obfsSummary(h.sp.Obfs))
	return nil
}

// obfsSummary is the log line that says which obfuscation parameters are in
// force — the receipt the mismatch test reads back.
func obfsSummary(obfs map[string]string) string {
	if len(obfs) == 0 {
		return "(daemon defaults)"
	}
	var parts []string
	for _, k := range obfsOrder {
		if v, ok := obfs[k]; ok {
			parts = append(parts, k+"="+v)
		}
	}
	return strings.Join(parts, " ")
}

func shortKey(pub string) string {
	if len(pub) > 8 {
		return pub[:8] + "…"
	}
	return pub
}

// startPoller watches the peer's handshake timestamp over uapi and logs the
// first handshake — the visible proof the peer relationship is live.
func (h *handle) startPoller() {
	h.stopPoll = make(chan struct{})
	done := make(chan struct{})
	h.pollDone = done
	stop := h.stopPoll
	go func() {
		defer close(done)
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				newest := h.readHandshake()
				if newest > 0 && newest > h.lastHS.Load() {
					first := h.lastHS.Swap(newest) == 0
					if first {
						h.logf(nodeLogger.LogInfo, "peer handshake established with %s (peer %s)", h.sp.PeerEndpoint, shortKey(h.sp.PeerPublicKey))
					}
				}
			}
		}
	}()
}

// readHandshake is one uapi get. It returns the newest peer handshake
// timestamp, 0 when there is none. The raw reply is never logged: it carries
// private_key.
func (h *handle) readHandshake() int64 {
	if !h.started.Load() {
		return 0
	}
	u, err := dialUAPI(h.ifname, time.Second)
	if err != nil {
		return 0
	}
	defer func() { _ = u.Close() }()
	lines, err := u.get()
	if err != nil {
		return 0
	}
	_, peers := parseGet(lines)
	var newest int64
	for _, p := range peers {
		if p.LastHandshake > newest {
			newest = p.LastHandshake
		}
	}
	return newest
}

// Started reports whether this side is configured. A daemon that dies later
// shows up as a failed Stats / a log line, not as a flipped flag.
// ponytail: Started does not re-probe the socket; add an on-demand link probe
// if a wedged daemon ever needs to be distinguished from a stopped one.
func (h *handle) Started() bool { return h.started.Load() }

func (h *handle) Version() string { return h.version }

func (h *handle) Logs() <-chan string { return h.logs }

func (h *handle) LogLines() <-chan nodeLogger.LogLine { return h.lines }

// Stats reads this side's cumulative transfer counters over uapi (tx = up,
// rx = down) and keeps the last good values after teardown so a status read
// right after Stop still reports the bytes that flowed.
func (h *handle) Stats(ctx context.Context) (tunnel.Bytes, error) {
	if !h.started.Load() {
		return tunnel.Bytes{Up: h.up.Load(), Down: h.down.Load()}, nil
	}
	select {
	case <-ctx.Done():
		return tunnel.Bytes{}, ctx.Err()
	default:
	}
	u, err := dialUAPI(h.ifname, 2*time.Second)
	if err != nil {
		return tunnel.Bytes{Up: h.up.Load(), Down: h.down.Load()},
			fmt.Errorf("amnezia: uapi get %s: %w", h.ifname, err)
	}
	defer func() { _ = u.Close() }()
	lines, err := u.get()
	if err != nil {
		return tunnel.Bytes{Up: h.up.Load(), Down: h.down.Load()},
			fmt.Errorf("amnezia: uapi get %s: %w", h.ifname, err)
	}
	_, peers := parseGet(lines)
	var up, down uint64
	for _, p := range peers {
		up += p.Tx
		down += p.Rx
	}
	h.up.Store(up)
	h.down.Store(down)
	return tunnel.Bytes{Up: up, Down: down}, nil
}

// Restart tears this side down and brings it back from the same Spec — same
// interface name, same addresses, same peer — with no manual step.
func (h *handle) Restart() error {
	h.Shutdown()
	if err := h.bringUp(); err != nil {
		return err
	}
	h.startPoller()
	return nil
}

// stopProcess terminates the daemon and waits for it. Idempotent.
func (h *handle) stopProcess() {
	h.mu.Lock()
	cmd, done := h.cmd, h.waitDone
	h.cmd, h.waitDone = nil, nil
	h.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return
	}
	if runtime.GOOS == "windows" {
		_ = cmd.Process.Kill()
	} else {
		_ = cmd.Process.Signal(syscall.SIGTERM)
	}
	select {
	case <-done:
		return
	case <-time.After(3 * time.Second):
	}
	_ = cmd.Process.Kill()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		h.logf(nodeLogger.LogError, "%s did not exit after SIGKILL", BinaryName)
	}
}

// removeLink deletes the TUN interface and asserts the absence: the interface,
// its address and every route via it must be gone (a leaked route outlives
// the tunnel and breaks the next one). Idempotent.
func (h *handle) removeLink() {
	if _, err := h.run(h.ipBin, "link", "show", h.ifname); err != nil {
		return // already gone
	}
	if _, err := h.run(h.ipBin, "link", "del", h.ifname); err != nil {
		h.logf(nodeLogger.LogError, "delete interface %s: %v", h.ifname, err)
		return
	}
	if out, err := h.run(h.ipBin, "link", "show", h.ifname); err == nil {
		h.logf(nodeLogger.LogError, "interface %s still present after delete: %s", h.ifname, out)
		return
	}
	h.logf(nodeLogger.LogInfo, "interface %s removed; its address went with it", h.ifname)
	if routes, err := h.run(h.ipBin, "route", "show"); err == nil {
		for _, line := range strings.Split(routes, "\n") {
			if strings.Contains(line, "dev "+h.ifname) {
				h.logf(nodeLogger.LogError, "route survived the teardown: %s", line)
			}
		}
	}
	// A socket left behind by a SIGKILL would block the next start's bind.
	if path := sockPath(h.ifname); fileExists(path) {
		_ = os.Remove(path)
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// Shutdown stops the poller, terminates the daemon and asserts the absence of
// everything this side created. Idempotent.
func (h *handle) Shutdown() {
	h.mu.Lock()
	if h.stopping {
		h.mu.Unlock()
		return
	}
	h.stopping = true
	stop := h.stopPoll
	h.mu.Unlock()

	if stop != nil {
		close(stop)
		if done := h.pollDone; done != nil {
			<-done
		}
	}

	if !h.started.Swap(false) {
		h.stopProcess()
		return
	}
	h.stopProcess()
	h.removeLink()
	h.logf(nodeLogger.LogInfo, "stopped")
}
