// Package udp2raw runs wangyu-/udp2raw as a Phase 3 packet-level tunnel
// (CONTRACT §2).
//
// udp2raw is a child process, never a library: the adapter writes one
// configuration file per side (0600, under the framework's per-tunnel
// directory), execs the pinned binary with --conf-file, waits for the side's
// own readiness line, and publishes the process' log stream — with the key
// redacted, because udp2raw echoes its own command line at INFO.
//
// Mode support: relay only. reverse is refused by Render with
// ErrModeUnsupported (CONTRACT §2.0) — a raw client/server pair has no
// "publish on side a" shape and no run proved one.
//
// Privileges: a raw socket (CAP_NET_RAW) plus, for every faking mode, the
// right to insert its own iptables rules (CAP_NET_ADMIN). Preflight names the
// missing grant and Start refuses with the same text rather than letting the
// tool die on a bare permission denied.
package udp2raw

import (
	"bufio"
	"context"
	_ "embed"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pasarguard/node/backend/tunnel"
	nodeLogger "github.com/pasarguard/node/logger"
)

//go:embed pins.json
var pinsJSON []byte

const (
	// Tool is the registered adapter name.
	Tool = "udp2raw"
	// Version is what Handle.Version reports. The binary is pin-verified
	// against pins.json before it is ever exec'd, so the pin's version is the
	// running binary's version without spawning a second process.
	Version = "udp2raw " + pinVersion
	// pinVersion mirrors pins.json "version"; one place to change on an
	// upgrade.
	pinVersion = "20230206.0"

	// readyTimeout is how long Start waits for the side's readiness line.
	// udp2raw is up in well under a second; a configuration it rejects exits
	// sooner and is reported from its own log output instead.
	readyTimeout = 8 * time.Second
)

func init() {
	tunnel.Register(Tool, Adapter{})
	if err := tunnel.RegisterPinJSON(pinsJSON, "pins.json"); err != nil {
		// A pin that will not parse must not degrade into "no pin, run
		// anything": panic at init rather than start an unverified binary.
		panic("udp2raw: pins.json: " + err.Error())
	}
}

// Adapter implements tunnel.Adapter.
type Adapter struct{}

var _ tunnel.Adapter = Adapter{}

// Render is pure and deterministic: fixed line order, values from the Spec
// only, no I/O, no clock. The same Spec — including Mode — is byte-identical
// twice, which is what makes the restart stage mean anything.
//
// The key IS part of the output: udp2raw cannot derive its cipher without it,
// and a rendered config without one would be a config udp2raw starts with its
// own public default string. Start is the only thing that writes the file,
// under the per-tunnel directory, mode 0600 (CONTRACT §2.1).
func (Adapter) Render(spec tunnel.Spec) (string, error) {
	lines, err := buildLines(spec)
	if err != nil {
		return "", err
	}
	return strings.Join(lines, "\n") + "\n", nil
}

// Preflight reports what this host cannot do for this tool. Empty means ready.
//
// The raw-socket question comes from the framework's helper, not from a second
// root check (CONTRACT §2.3): udp2raw needs CAP_NET_RAW, and its -a rules
// need CAP_NET_ADMIN. The fix text on each problem names the grant.
func (Adapter) Preflight(_ context.Context, spec tunnel.Spec) []tunnel.Problem {
	var out []tunnel.Problem
	if err := spec.Validate(); err != nil {
		out = append(out, tunnel.Problem{Check: "params", Detail: err.Error()})
	} else if err := checkParams(spec); err != nil {
		check := "params"
		if strings.Contains(err.Error(), "mode not supported") {
			check = "mode"
		}
		out = append(out, tunnel.Problem{Check: check, Detail: err.Error()})
	}
	out = append(out, netnsProblems(spec)...)
	out = append(out, tunnel.CheckRawSocket()...)
	if autoRule(spec) {
		out = append(out, tunnel.CheckFirewallTooling()...)
		out = append(out, tunnel.CheckCapability("net_admin")...)
	}
	out = append(out, tunnel.CheckBinary(Tool)...)
	return out
}

// Start writes the configuration, launches the pinned udp2raw and waits for
// the side's readiness line — so "started" means the tunnel is up, not "the
// process was spawned".
//
// Refusals come before exec, in this order, so the operator reads the reason
// they can act on: an unusable Spec, a missing privilege (naming the grant),
// an unresolved key, an unverifiable binary.
func (Adapter) Start(ctx context.Context, spec tunnel.Spec, ports tunnel.Ports) (tunnel.Handle, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if err := checkParams(spec); err != nil {
		return nil, err
	}
	if ns := netnsFor(spec); ns != "" {
		// Most specific, most actionable failure first: a namespace the
		// operator named and this host does not have. Checked before the
		// privilege gate so the message is about the namespace, not about
		// raw sockets on a host that would have both problems.
		if probs := netnsProblems(spec); len(probs) > 0 {
			return nil, fmt.Errorf("udp2raw cannot start on this host: %s", joinProblems(probs))
		}
	}
	if probs := (Adapter{}).Preflight(ctx, spec); hasPrivilegeProblem(probs) {
		return nil, fmt.Errorf("udp2raw cannot start on this host: %s", joinProblems(privilegeProblems(probs)))
	}
	key := strings.TrimSpace(spec.Secrets[SecretKey])
	if key == "" {
		return nil, fmt.Errorf("%w: udp2raw requires the %s secret (declare it and set the environment variable on the node)",
			tunnel.ErrSecretUnresolved, SecretKey)
	}
	dir := spec.Params[tunnel.ParamConfigDir]
	if dir == "" {
		return nil, fmt.Errorf("udp2raw: %s is not set — the config file needs the per-tunnel directory", tunnel.ParamConfigDir)
	}
	bin := spec.Params[tunnel.ParamBinaryPath]
	if bin == "" {
		resolved, err := tunnel.ResolveBinary(Tool, "")
		if err != nil {
			return nil, err
		}
		bin = resolved
	}

	// Render with the ports this call was handed. The clone never reaches the
	// Manager, so nothing here is persisted or logged.
	rspec := spec.Clone()
	if rspec.Params == nil {
		rspec.Params = map[string]string{}
	}
	rspec.Params[tunnel.ParamListenPort] = strconv.Itoa(ports.Listen)
	lines, err := buildLines(rspec)
	if err != nil {
		return nil, err
	}
	cfgPath := filepath.Join(dir, "udp2raw.conf")
	if err := os.WriteFile(cfgPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("udp2raw: write config: %w", err)
	}

	h := &handle{
		spec:    spec.Clone(),
		ports:   ports,
		bin:     bin,
		cfgPath: cfgPath,
		key:     key,
		netns:   netnsFor(spec),
		side:    spec.Side,
		version: Version,
		logs:    make(chan string, 1024),
		lines:   make(chan nodeLogger.LogLine, 1024),
		exited:  make(chan struct{}),
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

// privilegeProblems are the host questions a start cannot proceed without.
func privilegeProblems(probs []tunnel.Problem) []tunnel.Problem {
	var out []tunnel.Problem
	for _, p := range probs {
		switch p.Check {
		case "raw_socket", "root", "capability", "iptables":
			out = append(out, p)
		}
	}
	return out
}

func hasPrivilegeProblem(probs []tunnel.Problem) bool {
	return len(privilegeProblems(probs)) > 0
}

func joinProblems(probs []tunnel.Problem) string {
	parts := make([]string, 0, len(probs))
	for _, p := range probs {
		parts = append(parts, p.String())
	}
	return strings.Join(parts, "; ")
}

// handle is one running side of one udp2raw tunnel.
type handle struct {
	spec    tunnel.Spec
	ports   tunnel.Ports
	bin     string
	cfgPath string
	key     string
	netns   string // pre-placed namespace; "" = the process's own
	side    tunnel.Side
	version string

	logs  chan string
	lines chan nodeLogger.LogLine

	cmd     *exec.Cmd
	exited  chan struct{} // closed by the waiter goroutine
	waitErr atomic.Value  // error, for waitReady's failure path

	started atomic.Bool
	ready   atomic.Bool

	mu       sync.Mutex
	lastLine string
	out      io.ReadCloser
}

// launch starts the process and begins reading its output. The write end of
// the pipe is closed in the parent so the reader sees EOF when udp2raw exits.
func (h *handle) launch() error {
	h.ready.Store(false)
	cmd := h.command()
	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("udp2raw: pipe: %w", err)
	}
	cmd.Stdout = w
	cmd.Stderr = w
	if err := cmd.Start(); err != nil {
		_ = r.Close()
		_ = w.Close()
		return fmt.Errorf("udp2raw: start %s: %w", h.bin, err)
	}
	_ = w.Close()

	h.mu.Lock()
	h.cmd = cmd
	h.out = r
	h.exited = make(chan struct{})
	h.mu.Unlock()

	go h.pump(r)
	go func() {
		if err := cmd.Wait(); err != nil {
			h.waitErr.Store(fmt.Errorf("udp2raw exited: %w%s", err, h.tail()))
		} else {
			h.waitErr.Store(fmt.Errorf("udp2raw exited%s", h.tail()))
		}
		close(h.exited)
	}()
	h.started.Store(true)
	return nil
}

// command is the process this side runs. With a namespace it is
// `ip netns exec <ns> <bin> ...`: iproute2 setns()s and exec()s in the same
// process, so the pid we hold IS udp2raw and Shutdown's signal reaches it —
// verified on the reference host (2a-udp2raw-netns-exec-probe-*.log). Note
// `ip netns exec <ns> -- <cmd>` is NOT accepted by iproute2 (`exec of "--"
// failed`), so there is no double dash here.
func (h *handle) command() *exec.Cmd {
	if h.netns == "" {
		return exec.Command(h.bin, "--conf-file", h.cfgPath)
	}
	return exec.Command("ip", "netns", "exec", h.netns, h.bin, "--conf-file", h.cfgPath)
}

// netnsProblems is what this spec's namespace placement needs from the host:
// Linux (ip netns is a Linux facility), an ip(8) that can enter it, and a
// namespace that already exists. Empty means "this side can be placed".
func netnsProblems(spec tunnel.Spec) []tunnel.Problem {
	ns := netnsFor(spec)
	if ns == "" {
		return nil
	}
	if runtime.GOOS != "linux" {
		return []tunnel.Problem{{
			Check:  "netns",
			Detail: fmt.Sprintf("params netns placement of %q is not available on %s/%s", ns, runtime.GOOS, runtime.GOARCH),
			Fix:    "run this side on a Linux node, or clear a_netns/b_netns to use the node's own namespace",
		}}
	}
	if _, err := exec.LookPath("ip"); err != nil {
		return []tunnel.Problem{{
			Check:  "netns",
			Detail: fmt.Sprintf("ip(8) not found, cannot enter network namespace %q: %v", ns, err),
			Fix:    "install iproute2",
		}}
	}
	// ip netns add binds the namespace at $IP_NETNS_PATH (default
	// /run/netns/<name>); that file is what `ip netns list` reads, so its
	// absence IS "this namespace does not exist".
	base := os.Getenv("IP_NETNS_PATH")
	if base == "" {
		base = "/run/netns"
	}
	if _, err := os.Stat(filepath.Join(base, ns)); err != nil {
		return []tunnel.Problem{{
			Check:  "netns",
			Detail: fmt.Sprintf("network namespace %q does not exist on this host", ns),
			Fix:    fmt.Sprintf("ip netns add %s", ns),
		}}
	}
	return nil
}

// pump reads udp2raw's stdout/stderr: the key is redacted first (the tool
// prints its own argv at INFO, which would otherwise put the shared secret in
// the tunnel's log ring), then the line is published with its own level.
func (h *handle) pump(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		raw := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(raw) == "" {
			continue
		}
		line := redact(raw, h.key)

		h.mu.Lock()
		h.lastLine = line
		h.mu.Unlock()

		// The readiness lines are the ones udp2raw prints once the side is
		// actually up: the server bound its raw listener, the client reached
		// the last handshake step with it (raw-mode easy-faketcp never logs a
		// "client_ready" state at all — it stops at client_handshake2, and
		// datagrams do flow from there; measured on the pinned build). Probing
		// a port from here would race the very bind we are waiting for.
		if strings.Contains(line, "now listening at") ||
			strings.Contains(line, "client_handshake2") ||
			(strings.Contains(line, "to client_ready") && !strings.Contains(line, "from client_ready")) {
			h.ready.Store(true)
		}

		select {
		case h.logs <- line:
		default:
		}
		select {
		case h.lines <- classify(line):
		default:
		}
	}
}

// redact removes the shared key from a log line. udp2raw prints its whole
// command line at INFO and its "important variables" line at INFO too, both of
// which carry -k; a secret must never reach a log (CONTRACT §2.3 rule 3).
func redact(line, key string) string {
	if key == "" {
		return line
	}
	return strings.ReplaceAll(line, key, "<redacted>")
}

// classify turns one udp2raw line into the manager's LogLine using the level
// udp2raw itself printed.
func classify(raw string) nodeLogger.LogLine {
	line := nodeLogger.LogLine{Detail: raw, TsUnixMs: time.Now().UnixMilli()}
	upper := strings.ToUpper(raw)
	switch {
	case strings.Contains(upper, "[FATAL]"), strings.Contains(upper, "[ERROR]"):
		line.Level = nodeLogger.LogError
	case strings.Contains(upper, "[WARN]"):
		line.Level = nodeLogger.LogWarning
	case strings.Contains(upper, "[DEBUG]"), strings.Contains(upper, "[TRACE]"):
		line.Level = nodeLogger.LogDebug
	default:
		line.Level = nodeLogger.LogInfo
	}
	return line
}

// waitReady blocks until the side reports its readiness line, or the process
// dies, or the budget runs out.
func (h *handle) waitReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		select {
		case <-h.exited:
			return fmt.Errorf("udp2raw did not come up: %w", h.err())
		default:
		}
		if h.ready.Load() {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("udp2raw side %s did not come up within %s%s", h.side, timeout, h.tail())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// tail is the last log line, for a start-up refusal's error message. The
// configuration itself is never included — it holds the key.
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
	return fmt.Errorf("udp2raw exited%s", h.tail())
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

// Version is the pinned udp2raw version (the binary was hash-checked before
// exec).
func (h *handle) Version() string { return h.version }

// Logs is the log channel: udp2raw's own lines, verbatim, key redacted.
func (h *handle) Logs() <-chan string { return h.logs }

// LogLines is the classified channel the Manager prefers (node/logger).
func (h *handle) LogLines() <-chan nodeLogger.LogLine { return h.lines }

// Stats returns the tunnel's aggregate counters.
//
// ponytail: always zero — the pinned udp2raw (20230206.0) exposes no byte
// counters anywhere (no metrics endpoint, no fifo command, nothing in its
// logs), so there is nothing to report and inventing a number would be worse
// than none. Upgrade path: tap the process with a per-interface counter the
// day udp2raw grows one, or count at the port-forwarding layer above it.
func (h *handle) Stats(context.Context) (tunnel.Bytes, error) {
	return tunnel.Bytes{}, nil
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

// Shutdown takes the process down and waits for it. Idempotent; safe to call
// on a handle that never started.
//
// The signal matters: udp2raw removes its own -a iptables rules on a clean
// exit, and SIGKILL skips that — on a production node a kill would leave a
// DROP rule for a port nobody is listening on any more (upstream's remedy is
// `udp2raw --clear`, which nobody remembers to run). So: SIGTERM first, a two
// second grace period, then SIGKILL.
func (h *handle) Shutdown() {
	h.mu.Lock()
	cmd := h.cmd
	started := h.started.Load()
	h.mu.Unlock()
	if cmd == nil || !started {
		return
	}
	h.started.Store(false)
	if cmd.Process == nil {
		return
	}
	if runtime.GOOS != "windows" {
		_ = cmd.Process.Signal(syscall.SIGTERM)
	}
	select {
	case <-h.exited:
	case <-time.After(2 * time.Second):
		_ = cmd.Process.Kill()
		<-h.exited
	}
}
