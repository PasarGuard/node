package controller

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
)

type stubBackend struct {
	started   atomic.Bool
	shutdowns atomic.Int32
}

func (s *stubBackend) Started() bool { return s.started.Load() }
func (s *stubBackend) Version() string { return "test" }
func (s *stubBackend) Logs() <-chan string { return nil }
func (s *stubBackend) Restart() error { return nil }
func (s *stubBackend) Shutdown() { s.shutdowns.Add(1); s.started.Store(false) }
func (s *stubBackend) SyncUser(context.Context, *common.User) error { return nil }
func (s *stubBackend) SyncUsers(context.Context, []*common.User) error { return nil }
func (s *stubBackend) UpdateUsers(context.Context, []*common.User) error { return nil }
func (s *stubBackend) UpdateUsersAndRestart(context.Context, []*common.User) error { return nil }
func (s *stubBackend) GetSysStats(context.Context) (*common.BackendStatsResponse, error) {
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

	if keepAliveStale(last, 10*time.Second, now) {
		t.Fatal("keep-alive must not fire when silence equals keep_alive")
	}
	if !keepAliveStale(last, 10*time.Second, now.Add(keepAliveGrace)) {
		t.Fatal("keep-alive must fire after keep_alive plus grace")
	}
}
