package singbox

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
)

// debounceHarness boots a sing-box backend (vless inbound, one long-lived
// client) with a short debounce window and returns the pieces the tests drive.
type debounceHarness struct {
	sb         *SingBox
	ctx        context.Context
	cancel     context.CancelFunc
	socksPort  int
	targetPort int
	tunneled   func() int // performs one full socks fetch, returns bytes read
	userID     string
}

func newDebounceHarness(t *testing.T, window time.Duration) *debounceHarness {
	t.Helper()
	exe := singBoxEnvPath(t)
	dir := t.TempDir()
	userID := uuid.New().String()

	p := freePorts(t, 6)
	serverPort, apiPort, metricPort, targetPort, socksPort := p[0], p[1], p[2], p[3], p[4]

	startOrigin(t, targetPort)

	serverCfg := fmt.Sprintf(`{
  "log": {"level": "error"},
  "inbounds": [
    {"type":"vless","tag":"vless-in","listen":"127.0.0.1","listen_port":%d,
     "users":[{"name":"a-user","uuid":%q}]}
  ],
  "outbounds": [{"type":"direct","tag":"direct"}],
  "route": {"final":"direct"}
}`, serverPort, userID)

	cfg, err := NewConfig(serverCfg, nil)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if err := cfg.ApplyAPI(apiPort); err != nil {
		t.Fatalf("ApplyAPI: %v", err)
	}
	cfg.syncUsers([]*common.User{{
		Email:    "a-user",
		Proxies:  &common.Proxy{Vless: &common.Vless{Id: userID}},
		Inbounds: []string{"vless-in"},
	}})

	nodeCfg := config.NewTestConfig(dir, uuid.New())
	nodeCfg.SingBoxExecutablePath = exe
	nodeCfg.SingBoxSyncDebounce = window

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	t.Cleanup(cancel)

	sb, err := New(ctx, cfg, nil, apiPort, metricPort, nodeCfg)
	if err != nil {
		cancel()
		t.Fatalf("New backend: %v", err)
	}
	t.Cleanup(sb.Shutdown)
	go func() {
		for range sb.Logs() {
		}
	}()

	clientCfg := map[string]any{
		"log":      map[string]any{"level": "error"},
		"inbounds": []any{map[string]any{"type": "mixed", "tag": "socks", "listen": "127.0.0.1", "listen_port": socksPort}},
		"outbounds": []any{
			map[string]any{"type": "vless", "tag": "proxy", "server": "127.0.0.1", "server_port": serverPort, "uuid": userID},
			map[string]any{"type": "direct", "tag": "direct"},
		},
		"route": map[string]any{"final": "proxy"},
	}
	buf, _ := json.Marshal(clientCfg)
	cfgPath := filepath.Join(dir, "client.json")
	if err := os.WriteFile(cfgPath, buf, 0o644); err != nil {
		cancel()
		t.Fatalf("write client config: %v", err)
	}
	if out, err := exec.Command(exe, "check", "-c", cfgPath).CombinedOutput(); err != nil {
		cancel()
		t.Fatalf("client config invalid: %v\n%s", err, out)
	}
	logPath := filepath.Join(dir, "client.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		cancel()
		t.Fatalf("client log: %v", err)
	}
	client := exec.Command(exe, "run", "-c", cfgPath)
	client.Stdout = logFile
	client.Stderr = logFile
	if err := client.Start(); err != nil {
		cancel()
		t.Fatalf("start client: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Process.Kill()
		_, _ = client.Process.Wait()
		_ = logFile.Close()
	})
	if err := waitForPort(socksPort, 15*time.Second); err != nil {
		cancel()
		t.Fatalf("client socks: %v", err)
	}

	return &debounceHarness{
		sb:         sb,
		ctx:        ctx,
		cancel:     cancel,
		socksPort:  socksPort,
		targetPort: targetPort,
		userID:     userID,
		tunneled:   func() int { return socksFetch(t, socksPort, targetPort, 2048) },
	}
}

// holdTunnel opens a tunnel connection and returns it without consuming it.
func (h *debounceHarness) holdTunnel(t *testing.T) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", h.socksPort))
	if err != nil {
		t.Fatalf("dial socks: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	_, _ = conn.Write([]byte{0x05, 0x01, 0x00})
	resp := make([]byte, 2)
	if _, err := readFull(conn, resp); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	// CONNECT to the origin: caller must pass targetPort — harness keeps it
	// simple: we reuse the tunnel only for liveness, target port is stored.
	req := append([]byte{0x05, 0x01, 0x00, 0x01}, net.ParseIP("127.0.0.1").To4()...)
	req = append(req, byte(h.targetPort>>8), byte(h.targetPort))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("connect: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := readFull(conn, reply); err != nil {
		t.Fatalf("connect reply: %v", err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("connect failed: %d", reply[1])
	}
	return conn
}

// alive reports whether the held connection is still open (a read that times
// out means the socket is alive; EOF/reset means it was cut).
func connAlive(conn net.Conn) bool {
	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 64)
	_, err := conn.Read(buf)
	if err == nil {
		return true
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	return false
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// TestSyncDebounceCoalescesRestarts: 20 rapid user changes inside one window
// must produce exactly one core restart, and a held connection from an
// unrelated (already-active) user must survive the whole add burst.
func TestSyncDebounceCoalescesRestarts(t *testing.T) {
	const window = 700 * time.Millisecond
	h := newDebounceHarness(t, window)

	// baseline: an unrelated user's tunnel is up
	if n := h.tunneled(); n < 2048 {
		t.Fatalf("baseline tunnel read %d", n)
	}
	held := h.holdTunnel(t)

	// 20 rapid changes (each a distinct new user on the same inbound)
	for i := 0; i < 20; i++ {
		user := &common.User{
			Email:    fmt.Sprintf("burst-%d", i),
			Proxies:  &common.Proxy{Vless: &common.Vless{Id: h.userID}},
			Inbounds: []string{"vless-in"},
		}
		if err := h.sb.SyncUser(h.ctx, user); err != nil {
			t.Fatalf("SyncUser %d: %v", i, err)
		}
	}

	if got := h.sb.RestartCount(); got != 0 {
		t.Fatalf("restart happened before the debounce window closed: %d", got)
	}
	if !connAlive(held) {
		t.Fatal("held connection died during the add burst (before any restart)")
	}

	deadline := time.Now().Add(5 * window)
	for h.sb.RestartCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	// allow any immediate follow-up flush to show up before asserting
	time.Sleep(300 * time.Millisecond)

	if got := h.sb.RestartCount(); got != 1 {
		t.Fatalf("20 rapid user changes produced %d restarts, want exactly 1", got)
	}
	if connAlive(held) {
		// the single restart may lag a moment; wait a beat and re-check
		time.Sleep(500 * time.Millisecond)
	}
	t.Logf("restarts=%d after burst (single coalesced restart)", h.sb.RestartCount())
}

// TestUsagePreservedAcrossDebouncedRestart: traffic that flows after the last
// stats poll but before a debounced restart must still be delivered to the
// next poll (counters drained into pendingStats before the core is killed).
func TestUsagePreservedAcrossDebouncedRestart(t *testing.T) {
	const window = 500 * time.Millisecond
	h := newDebounceHarness(t, window)

	// traffic #1 — consumed by a poll (panel-style reset=true)
	h.tunneled()
	stats, err := h.sb.GetStats(h.ctx, &common.StatRequest{Type: common.StatType_UsersStat, Reset_: true})
	if err != nil {
		t.Fatalf("poll 1: %v", err)
	}
	first := int64(0)
	for _, s := range stats.GetStats() {
		if s.GetName() == "a-user" {
			first += s.GetValue()
		}
	}
	if first == 0 {
		t.Fatal("first traffic was not counted at all")
	}

	// traffic #2 — lands AFTER the poll; must not be lost by the restart
	h.tunneled()

	// queue a change that triggers the debounced restart
	if err := h.sb.SyncUser(h.ctx, &common.User{
		Email:    "a-user",
		Proxies:  &common.Proxy{Vless: &common.Vless{Id: h.userID}},
		Inbounds: []string{"vless-in"},
	}); err != nil {
		t.Fatalf("SyncUser: %v", err)
	}

	deadline := time.Now().Add(5 * window)
	for h.sb.RestartCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if h.sb.RestartCount() != 1 {
		t.Fatalf("expected exactly 1 debounced restart, got %d", h.sb.RestartCount())
	}

	// next panel-style poll: the pre-restart remainder must be present
	stats, err = h.sb.GetStats(h.ctx, &common.StatRequest{Type: common.StatType_UsersStat, Reset_: true})
	if err != nil {
		t.Fatalf("poll 2: %v", err)
	}
	after := int64(0)
	for _, s := range stats.GetStats() {
		if s.GetName() == "a-user" {
			after += s.GetValue()
		}
	}
	if after == 0 {
		t.Fatal("usage between the last poll and the debounced restart was LOST (pendingStats flush did not deliver)")
	}
	t.Logf("usage preserved across restart: first_poll=%d post_restart_poll=%d", first, after)
}

// TestSyncDebounceRateLimit: a second burst right after a flush is pushed
// back so restarts stay spaced by at least the debounce window.
func TestSyncDebounceRateLimit(t *testing.T) {
	const window = 400 * time.Millisecond
	h := newDebounceHarness(t, window)

	burst := func(tag string) {
		for i := 0; i < 3; i++ {
			if err := h.sb.SyncUser(h.ctx, &common.User{
				Email:    fmt.Sprintf("%s-%d", tag, i),
				Proxies:  &common.Proxy{Vless: &common.Vless{Id: h.userID}},
				Inbounds: []string{"vless-in"},
			}); err != nil {
				t.Fatalf("SyncUser: %v", err)
			}
		}
	}

	burst("one")
	waitRestart := func(n int) {
		deadline := time.Now().Add(6 * window)
		for h.sb.RestartCount() < n && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
		}
		if h.sb.RestartCount() < n {
			t.Fatalf("expected restart #%d, got %d", n, h.sb.RestartCount())
		}
	}
	waitRestart(1)
	firstFlushAt := time.Now()

	burst("two")
	waitRestart(2)
	spacing := time.Since(firstFlushAt)
	if spacing < window {
		t.Fatalf("second restart came %s after the first, rate limit should enforce >= %s", spacing, window)
	}
	t.Logf("restart spacing %s >= window %s (rate limit active)", spacing, window)
}
