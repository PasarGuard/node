package controller

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/pasarguard/node/backend"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
)

type stubBackend struct {
	started     atomic.Bool
	shutdowns   atomic.Int32
	statsCalls  atomic.Int32
	statsErr    error
	statsBlocks bool // GetSysStats waits for its context to end
}

func (s *stubBackend) Started() bool { return s.started.Load() }
func (s *stubBackend) Version() string { return "test" }
func (s *stubBackend) SubscribeLogs(context.Context) <-chan string { return nil }
func (s *stubBackend) Restart() error { return nil }
func (s *stubBackend) Shutdown() { s.shutdowns.Add(1); s.started.Store(false) }
func (s *stubBackend) SyncUser(context.Context, *common.User) error { return nil }
func (s *stubBackend) SyncUsers(context.Context, []*common.User) error { return nil }
func (s *stubBackend) UpdateUsers(context.Context, []*common.User) error { return nil }
func (s *stubBackend) UpdateUsersAndRestart(context.Context, []*common.User) error { return nil }
func (s *stubBackend) GetSysStats(ctx context.Context) (*common.BackendStatsResponse, error) {
	s.statsCalls.Add(1)
	if s.statsBlocks {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if s.statsErr != nil {
		return nil, s.statsErr
	}
	return &common.BackendStatsResponse{}, nil
}
func (s *stubBackend) GetStats(context.Context, *common.StatRequest) (*common.StatResponse, error) {
	return &common.StatResponse{}, nil
}
func (s *stubBackend) GetOutboundsLatency(context.Context, *common.LatencyRequest) (*common.LatencyResponse, error) {
	return &common.LatencyResponse{}, nil
}
func (s *stubBackend) GetUserOnlineStats(context.Context, string) (*common.OnlineStatResponse, error) {
	return &common.OnlineStatResponse{}, nil
}
func (s *stubBackend) GetUserOnlineIpListStats(context.Context, string) (*common.StatsOnlineIpListResponse, error) {
	return &common.StatsOnlineIpListResponse{}, nil
}

func TestConnectCancelsPreviousStatsCollector(t *testing.T) {
	c := New(config.NewTestConfig(t.TempDir(), uuid.New()))
	t.Cleanup(c.Disconnect)

	ctx, cancel := context.WithCancel(context.Background())
	c.cancelFunc = cancel

	c.Connect(0)

	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("Connect did not cancel the previous stats collector")
	}
}

// TestStartOrAttachHeartbeat: same config + running backend → no restart, just refresh keep-alive.
func TestStartOrAttachHeartbeat(t *testing.T) {
	c := New(config.NewTestConfig(t.TempDir(), uuid.New()))
	t.Cleanup(c.Disconnect)

	running := &stubBackend{}
	running.started.Store(true)
	c.backend = running
	// Simulate that this backend was started with a specific config.
	c.activeData = &common.Backend{Type: common.BackendType_XRAY, Config: "cfg1", KeepAlive: 30}

	c.LockControl()
	err := c.StartOrAttach(context.Background(), &common.Backend{Type: common.BackendType_XRAY, Config: "cfg1", KeepAlive: 60})
	c.UnlockControl()
	if err != nil {
		t.Fatalf("StartOrAttach heartbeat: %v", err)
	}
	if c.Backend() != running {
		t.Fatal("heartbeat: StartOrAttach replaced a running backend with same config")
	}
	if running.shutdowns.Load() != 0 {
		t.Fatal("heartbeat: StartOrAttach shut down a running backend")
	}
	if running.statsCalls.Load() != 1 {
		t.Fatalf("heartbeat: GetSysStats calls = %d, want 1", running.statsCalls.Load())
	}
}

// startSameConfigOn sends a Start with the config the running stub was started with.
func startSameConfigOn(t *testing.T, running backend.Backend, started *atomic.Bool) (*Controller, error) {
	t.Helper()
	c := New(config.NewTestConfig(t.TempDir(), uuid.New()))
	t.Cleanup(c.Disconnect)

	started.Store(true)
	c.backend = running
	c.activeData = &common.Backend{Type: common.BackendType_WIREGUARD, Config: "cfg1", KeepAlive: 30}

	c.LockControl()
	defer c.UnlockControl()
	return c, c.StartOrAttach(context.Background(), &common.Backend{Type: common.BackendType_WIREGUARD, Config: "cfg1", KeepAlive: 30})
}

// TestStartOrAttachRestartsAnUnhealthyBackendWithSameConfig: a WireGuard
// backend keeps reporting started after its interface is gone, so a repair
// Start with the same config must restart it instead of acting as a heartbeat.
func TestStartOrAttachRestartsAnUnhealthyBackendWithSameConfig(t *testing.T) {
	broken := &stubBackend{statsErr: errors.New("wireguard interface not available")}
	c, err := startSameConfigOn(t, broken, &broken.started)
	if err == nil {
		t.Fatal("expected StartBackend to fail with fake config")
	}
	if broken.shutdowns.Load() != 1 {
		t.Fatalf("unhealthy backend shutdowns = %d, want 1", broken.shutdowns.Load())
	}
	if c.Backend() == broken {
		t.Fatal("unhealthy backend is still attached")
	}
}

// TestStartOrAttachBoundsTheHeartbeatHealthCheck: a hung core API must not
// hold LockControl for long; it counts as unhealthy.
func TestStartOrAttachBoundsTheHeartbeatHealthCheck(t *testing.T) {
	previous := heartbeatHealthTimeout
	heartbeatHealthTimeout = 50 * time.Millisecond
	t.Cleanup(func() { heartbeatHealthTimeout = previous })

	hung := &stubBackend{statsBlocks: true}
	begin := time.Now()
	if _, err := startSameConfigOn(t, hung, &hung.started); err == nil {
		t.Fatal("expected StartBackend to fail with fake config")
	}
	if elapsed := time.Since(begin); elapsed > 5*time.Second {
		t.Fatalf("StartOrAttach took %s with a hung health check", elapsed)
	}
	if hung.shutdowns.Load() != 1 {
		t.Fatalf("hung backend shutdowns = %d, want 1", hung.shutdowns.Load())
	}
}

// TestStartOrAttachConfigChanged: different config + running backend → restart.
func TestStartOrAttachConfigChanged(t *testing.T) {
	c := New(config.NewTestConfig(t.TempDir(), uuid.New()))
	t.Cleanup(c.Disconnect)

	running := &stubBackend{}
	running.started.Store(true)
	c.backend = running
	c.activeData = &common.Backend{Type: common.BackendType_XRAY, Config: "cfg1"}

	// Send a new config — StartBackend will fail (no real xray), but we only
	// care that the old backend was shut down first.
	c.LockControl()
	err := c.StartOrAttach(context.Background(), &common.Backend{Type: common.BackendType_XRAY, Config: "cfg2_changed"})
	c.UnlockControl()
	if err == nil {
		t.Fatal("expected StartBackend to fail with fake config")
	}
	if running.shutdowns.Load() != 1 {
		t.Fatalf("config change: running backend shutdowns = %d, want 1", running.shutdowns.Load())
	}
}

// TestStartOrAttachReplacesDeadBackend: backend exists but stopped → restart.
func TestStartOrAttachReplacesDeadBackend(t *testing.T) {
	c := New(config.NewTestConfig(t.TempDir(), uuid.New()))
	t.Cleanup(c.Disconnect)

	dead := &stubBackend{} // started = false
	c.backend = dead

	c.LockControl()
	err := c.StartOrAttach(context.Background(), &common.Backend{Type: common.BackendType(99)})
	c.UnlockControl()
	if err == nil {
		t.Fatal("expected StartBackend to fail on invalid type after replacing dead backend")
	}
	if dead.shutdowns.Load() != 1 {
		t.Fatalf("dead backend shutdowns = %d, want 1", dead.shutdowns.Load())
	}
	if c.Backend() != nil {
		t.Fatal("failed StartBackend left a backend attached")
	}
}

func TestKeepAliveStaleIncludesGrace(t *testing.T) {
	now := time.Now()
	last := now.Add(-10 * time.Second)

	if keepAliveStale(last, 10*time.Second) {
		t.Fatal("keep-alive must not fire when silence equals keep_alive")
	}
	if !keepAliveStale(last.Add(-keepAliveGrace), 10*time.Second) {
		t.Fatal("keep-alive must fire after keep_alive plus grace")
	}
}

type liveStubBackend struct {
	stubBackend
	applied bool
	err     error
	calls   atomic.Int32
}

func (s *liveStubBackend) ApplyConfigLive(context.Context, string, []string) (bool, error) {
	s.calls.Add(1)
	return s.applied, s.err
}

// TestStartOrAttachDoesNotApplyLiveToAnUnhealthyBackend: an unhealthy backend
// with the same config is restarted, not handed the config again live.
func TestStartOrAttachDoesNotApplyLiveToAnUnhealthyBackend(t *testing.T) {
	broken := &liveStubBackend{applied: true}
	broken.statsErr = errors.New("xray api unavailable")
	if _, err := startSameConfigOn(t, broken, &broken.started); err == nil {
		t.Fatal("expected StartBackend to fail with fake config")
	}
	if broken.calls.Load() != 0 {
		t.Fatalf("ApplyConfigLive calls = %d, want 0", broken.calls.Load())
	}
	if broken.shutdowns.Load() != 1 {
		t.Fatalf("unhealthy backend shutdowns = %d, want 1", broken.shutdowns.Load())
	}
}

func startOnLiveStub(t *testing.T, running *liveStubBackend) (*Controller, error) {
	t.Helper()
	c := New(config.NewTestConfig(t.TempDir(), uuid.New()))
	t.Cleanup(c.Disconnect)

	running.started.Store(true)
	c.backend = running
	c.activeData = &common.Backend{Type: common.BackendType_XRAY, Config: "cfg1"}

	c.LockControl()
	defer c.UnlockControl()
	return c, c.StartOrAttach(context.Background(), &common.Backend{Type: common.BackendType_XRAY, Config: "cfg2", KeepAlive: 60})
}

// TestStartOrAttachAppliesConfigLive: changed config that the backend takes live → no restart.
func TestStartOrAttachAppliesConfigLive(t *testing.T) {
	running := &liveStubBackend{applied: true}
	c, err := startOnLiveStub(t, running)
	if err != nil {
		t.Fatal(err)
	}
	if running.calls.Load() != 1 {
		t.Fatalf("ApplyConfigLive calls = %d, want 1", running.calls.Load())
	}
	if running.shutdowns.Load() != 0 || c.Backend() != running {
		t.Fatal("a live config update restarted the backend")
	}
	c.mu.RLock()
	got := c.activeData.GetConfig()
	c.mu.RUnlock()
	if got != "cfg2" {
		t.Fatalf("activeData config = %q, want cfg2 so the next heartbeat matches", got)
	}
}

// TestStartOrAttachRestartsWhenLiveUpdateIsNotPossible: declined or failed live update → restart.
func TestStartOrAttachRestartsWhenLiveUpdateIsNotPossible(t *testing.T) {
	for _, running := range []*liveStubBackend{{applied: false}, {err: errors.New("convert failed")}} {
		if _, err := startOnLiveStub(t, running); err == nil {
			t.Fatal("expected StartBackend to fail with fake config")
		}
		if running.shutdowns.Load() != 1 {
			t.Fatalf("running backend shutdowns = %d, want 1", running.shutdowns.Load())
		}
	}
}
