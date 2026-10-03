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

func (s *stubBackend) Started() bool                                               { return s.started.Load() }
func (s *stubBackend) Version() string                                             { return "test" }
func (s *stubBackend) Logs() <-chan string                                         { return nil }
func (s *stubBackend) Restart() error                                              { return nil }
func (s *stubBackend) Shutdown()                                                   { s.shutdowns.Add(1); s.started.Store(false) }
func (s *stubBackend) SyncUser(context.Context, *common.User) error                { return nil }
func (s *stubBackend) SyncUsers(context.Context, []*common.User) error             { return nil }
func (s *stubBackend) UpdateUsers(context.Context, []*common.User) error           { return nil }
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

// TestStartOrAttachStartWithNoUsersIsNotAHeartbeat: a Start carrying no users
// must not be mistaken for a heartbeat.
//
// The panel filters core_users by status, so once every user is limited the Start
// it sends has an empty user list. Treating that as "same config, keep what you
// have" left the core running with the users it already had; treating it as a
// restart built a config with no users at all. Either way the user that made
// the restart necessary lost their budget. The node must apply it.
func TestStartOrAttachStartWithNoUsersIsNotAHeartbeat(t *testing.T) {
	c := New(config.NewTestConfig(t.TempDir(), uuid.New()))
	t.Cleanup(c.Disconnect)

	running := &stubBackend{}
	running.started.Store(true)
	c.backend = running
	c.activeData = &common.Backend{
		Type:   common.BackendType_SINGBOX,
		Config: "cfg1",
		Users:  []*common.User{{Email: "1", Quota: 4_000_000}},
	}

	c.LockControl()
	// StartBackend fails on the fake config; what matters is that it was
	// attempted, i.e. the running backend was shut down and rebuilt.
	err := c.StartOrAttach(context.Background(), &common.Backend{Type: common.BackendType_SINGBOX, Config: "cfg1"})
	c.UnlockControl()
	if err == nil {
		t.Fatal("expected StartBackend to fail with the fake config")
	}
	if running.shutdowns.Load() != 1 {
		t.Fatalf("empty-user Start did not restart the core: shutdowns = %d, want 1", running.shutdowns.Load())
	}
}

// TestStartOrAttachChangedCredentialsIsNotAHeartbeat: a Start whose user carries
// different credentials must be applied, not skipped.
func TestStartOrAttachChangedCredentialsIsNotAHeartbeat(t *testing.T) {
	c := New(config.NewTestConfig(t.TempDir(), uuid.New()))
	t.Cleanup(c.Disconnect)

	running := &stubBackend{}
	running.started.Store(true)
	c.backend = running
	c.activeData = &common.Backend{
		Type:   common.BackendType_SINGBOX,
		Config: "cfg1",
		Users: []*common.User{{
			Email:   "1",
			Proxies: &common.Proxy{Vless: &common.Vless{Id: "aaaaaaaa-0000-0000-0000-000000000001"}},
		}},
	}

	c.LockControl()
	// StartBackend fails on the fake config; what matters is that it was
	// attempted, i.e. the running backend was shut down and rebuilt.
	err := c.StartOrAttach(context.Background(), &common.Backend{
		Type:   common.BackendType_SINGBOX,
		Config: "cfg1",
		Users: []*common.User{{
			Email:   "1",
			Proxies: &common.Proxy{Vless: &common.Vless{Id: "bbbbbbbb-0000-0000-0000-000000000002"}},
		}},
	})
	c.UnlockControl()
	if err == nil {
		t.Fatal("expected StartBackend to fail with the fake config")
	}
	if running.shutdowns.Load() != 1 {
		t.Fatalf("changed-credential Start did not restart the core: shutdowns = %d, want 1", running.shutdowns.Load())
	}
}

// TestStartOrAttachQuotaOnlyChangeIsAHeartbeat: a Start that differs only in the
// remaining budget must NOT restart the core.
//
// The panel recomputes quota on every usage tick, so a heartbeat would otherwise
// restart the core once per tick per node. A moved budget is carried by
// SyncUser/UpdateUsers, which exist precisely to deliver it without a restart.
func TestStartOrAttachQuotaOnlyChangeIsAHeartbeat(t *testing.T) {
	c := New(config.NewTestConfig(t.TempDir(), uuid.New()))
	t.Cleanup(c.Disconnect)

	running := &stubBackend{}
	running.started.Store(true)
	c.backend = running
	c.activeData = &common.Backend{
		Type:   common.BackendType_SINGBOX,
		Config: "cfg1",
		Users:  []*common.User{{Email: "1", Quota: 4_000_000}},
	}

	c.LockControl()
	err := c.StartOrAttach(context.Background(), &common.Backend{
		Type:   common.BackendType_SINGBOX,
		Config: "cfg1",
		Users:  []*common.User{{Email: "1", Quota: 1_000_000}},
	})
	c.UnlockControl()
	if err != nil {
		t.Fatalf("quota-only change should be a heartbeat, got: %v", err)
	}
	if running.shutdowns.Load() != 0 {
		t.Fatalf("quota-only change restarted the core: shutdowns = %d, want 0", running.shutdowns.Load())
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
