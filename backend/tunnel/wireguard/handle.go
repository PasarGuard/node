package wireguard

import (
	"context"
	"fmt"
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

// handle is one running side of one wireguard tunnel. There is no child
// process: the work lives in the kernel module, so this type owns the
// interface lifecycle (create/verify/delete) plus a poller goroutine that
// turns `wg show` into log lines and byte counters.
type handle struct {
	spec    tunnel.Spec
	ports   tunnel.Ports
	sp      sideParams
	key     string // private key value; memory + a 0600 file only
	dir     string
	ifname  string
	wgBin   string
	ipBin   string
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

// run executes bin with args, prefixed with `ip netns exec <ns>` when this
// side lives in a namespace. Key material never appears in argv: it travels
// only in files this process writes with 0600.
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
// that names the step and carries the tool's own output — never the config
// file's contents.
func (h *handle) step(what, bin string, args ...string) (string, error) {
	out, err := h.run(bin, args...)
	if err != nil {
		if out == "" {
			return "", fmt.Errorf("wireguard: %s: %w", what, err)
		}
		return "", fmt.Errorf("wireguard: %s: %w (output: %s)", what, err, out)
	}
	if out == "" {
		h.logf(nodeLogger.LogInfo, "%s: ok", what)
	} else {
		h.logf(nodeLogger.LogInfo, "%s: ok (%s)", what, out)
	}
	return out, nil
}

// up creates the interface, address, peer and routes from this side's params.
// A leftover interface from a crashed run is replaced, not reused.
func (h *handle) bringUp() error {
	h.mu.Lock()
	h.stopping = false
	h.mu.Unlock()

	if _, err := h.run(h.ipBin, "link", "show", h.ifname); err == nil {
		h.logf(nodeLogger.LogWarning, "interface %s already exists — replacing it", h.ifname)
		if out, err := h.run(h.ipBin, "link", "del", h.ifname); err != nil {
			return fmt.Errorf("wireguard: cannot replace leftover interface %s: %w (output: %s)", h.ifname, err, out)
		}
	}
	if err := h.writeConfig(); err != nil {
		return err
	}
	if _, err := h.step("create interface "+h.ifname, h.ipBin, "link", "add", h.ifname, "type", "wireguard"); err != nil {
		return err
	}
	if _, err := h.step("assign address "+h.sp.Address, h.ipBin, "addr", "add", h.sp.Address, "dev", h.ifname); err != nil {
		return err
	}
	if _, err := h.step("bring "+h.ifname+" up", h.ipBin, "link", "set", h.ifname, "up"); err != nil {
		return err
	}
	if _, err := h.step("configure peer", h.wgBin, "setconf", h.ifname, h.confPath()); err != nil {
		return err
	}
	for _, cidr := range h.sp.Allowed {
		if _, err := h.step("route "+cidr+" via "+h.ifname, h.ipBin, "route", "replace", cidr, "dev", h.ifname); err != nil {
			return err
		}
	}
	// The interface must answer `wg show` before Start reports success.
	if _, err := h.run(h.wgBin, "show", h.ifname); err != nil {
		return fmt.Errorf("wireguard: interface %s did not come up: %w", h.ifname, err)
	}
	h.lastHS.Store(0)
	h.started.Store(true)
	return nil
}

func (h *handle) keyPath() string  { return filepath.Join(h.dir, "private.key") }
func (h *handle) confPath() string { return filepath.Join(h.dir, "wg.conf") }

// writeConfig writes the key file and the `wg setconf` file, both 0600,
// under the per-tunnel directory (CONTRACT §2.1 / §2.3 rule 3).
func (h *handle) writeConfig() error {
	if err := os.WriteFile(h.keyPath(), []byte(h.key+"\n"), 0o600); err != nil {
		return fmt.Errorf("wireguard: write private key file: %w", err)
	}
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", h.key)
	fmt.Fprintf(&b, "ListenPort = %d\n", h.ports.Listen)
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", h.sp.PeerPublicKey)
	fmt.Fprintf(&b, "Endpoint = %s\n", h.sp.PeerEndpoint)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", h.sp.PeerAllowedCIDRs)
	b.WriteString("PersistentKeepalive = 25\n")
	if err := os.WriteFile(h.confPath(), []byte(b.String()), 0o600); err != nil {
		return fmt.Errorf("wireguard: write wg config file: %w", err)
	}
	return nil
}

// startPoller watches `wg show <if> latest-handshakes` and logs the first
// handshake — the visible proof the peer relationship is live.
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
				out, err := h.run(h.wgBin, "show", h.ifname, "latest-handshakes")
				if err != nil || out == "" {
					continue
				}
				if newest := parseNewestHandshake(out); newest > 0 && newest > h.lastHS.Load() {
					first := h.lastHS.Swap(newest) == 0
					if first {
						h.logf(nodeLogger.LogInfo, "peer handshake established with %s (peer %s)", h.sp.PeerEndpoint, shortKey(h.sp.PeerPublicKey))
					}
				}
			}
		}
	}()
}

// parseNewestHandshake reads `wg show … latest-handshakes` lines
// ("<pubkey>\t<unix-seconds>") and returns the newest timestamp, 0 if none.
func parseNewestHandshake(out string) int64 {
	var newest int64
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		tsField := fields[len(fields)-1]
		ts, err := strconv.ParseInt(tsField, 10, 64)
		if err == nil && ts > newest {
			newest = ts
		}
	}
	return newest
}

func shortKey(pub string) string {
	if len(pub) > 8 {
		return pub[:8] + "…"
	}
	return pub
}

// Started reports whether this side's interface is up (a kernel interface
// has no process to die; Shutdown is what takes it down).
// ponytail: Started does not re-exec `ip link show`; external deletion of the
// interface shows up as a failed Stats instead. Add an on-demand link probe if
// that ever matters.
func (h *handle) Started() bool { return h.started.Load() }

func (h *handle) Version() string { return h.version }

func (h *handle) Logs() <-chan string { return h.logs }

func (h *handle) LogLines() <-chan nodeLogger.LogLine { return h.lines }

// Stats reads this side's cumulative transfer counters from the kernel
// (tx = up, rx = down) and keeps the last good values after teardown so a
// status read right after Stop still reports the bytes that flowed.
func (h *handle) Stats(ctx context.Context) (tunnel.Bytes, error) {
	if !h.started.Load() {
		return tunnel.Bytes{Up: h.up.Load(), Down: h.down.Load()}, nil
	}
	select {
	case <-ctx.Done():
		return tunnel.Bytes{}, ctx.Err()
	default:
	}
	out, err := h.run(h.wgBin, "show", h.ifname, "transfer")
	if err != nil {
		return tunnel.Bytes{Up: h.up.Load(), Down: h.down.Load()},
			fmt.Errorf("wireguard: wg show %s transfer: %w", h.ifname, err)
	}
	var up, down uint64
	for _, line := range strings.Split(out, "\n") {
		// <interface>\t<peer-publickey>\t<rx>\t<tx>
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		rx, errRx := strconv.ParseUint(fields[2], 10, 64)
		tx, errTx := strconv.ParseUint(fields[3], 10, 64)
		if errRx != nil || errTx != nil {
			continue
		}
		down += rx
		up += tx
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

// Shutdown deletes the interface and asserts the absence: interface, its
// address and every route via it must be gone (a leaked route outlives the
// tunnel and breaks the next one). Idempotent.
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
		return
	}

	_, delErr := h.run(h.ipBin, "link", "del", h.ifname)
	switch {
	case delErr != nil:
		h.logf(nodeLogger.LogError, "delete interface %s: %v", h.ifname, delErr)
	default:
		if out, err := h.run(h.ipBin, "link", "show", h.ifname); err == nil {
			h.logf(nodeLogger.LogError, "interface %s still present after delete: %s", h.ifname, out)
		} else {
			h.logf(nodeLogger.LogInfo, "interface %s removed; its address went with it", h.ifname)
		}
		if routes, err := h.run(h.ipBin, "route", "show"); err == nil {
			for _, line := range strings.Split(routes, "\n") {
				if strings.Contains(line, "dev "+h.ifname) {
					h.logf(nodeLogger.LogError, "route survived the teardown: %s", line)
				}
			}
		}
	}
	h.logf(nodeLogger.LogInfo, "stopped")
}
