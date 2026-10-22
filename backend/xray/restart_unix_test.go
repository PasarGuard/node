//go:build !windows

package xray

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	statsCommand "github.com/xtls/xray-core/app/stats/command"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pasarguard/node/backend/xray/api"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
	"github.com/pasarguard/node/pkg/logstream"
	"github.com/pasarguard/node/pkg/netutil"
)

// fakeStatsService stands in for xray's StatsService. GetSysStats fails like a
// booting core until healthy is set, or blocks until the caller gives up.
type fakeStatsService struct {
	statsCommand.UnimplementedStatsServiceServer
	healthy atomic.Bool
	block   bool
	probes  chan struct{}
}

func (s *fakeStatsService) GetSysStats(ctx context.Context, _ *statsCommand.SysStatsRequest) (*statsCommand.SysStatsResponse, error) {
	if s.probes != nil {
		select {
		case s.probes <- struct{}{}:
		default:
		}
	}
	if s.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if !s.healthy.Load() {
		return nil, status.Error(codes.Unavailable, "xray is booting")
	}
	return &statsCommand.SysStatsResponse{}, nil
}

// newFakeCoreXray returns an Xray whose core runs a stand-in for the xray
// binary (a process that never opens the API) and whose API client talks to
// stats. The core is not started.
func newFakeCoreXray(t *testing.T, stats *fakeStatsService) *Xray {
	t.Helper()

	dir := t.TempDir()
	executable := filepath.Join(dir, "xray")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexec sleep 600\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	statsCommand.RegisterStatsServiceServer(server, stats)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	handler, err := api.NewXrayAPI(listener.Addr().(*net.TCPAddr).Port)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(handler.Close)

	cfg, err := NewConfig(`{"inbounds":[]}`, nil)
	if err != nil {
		t.Fatal(err)
	}

	core := &Core{
		executablePath: executable,
		assetsPath:     dir,
		configPath:     dir,
		logs:           logstream.NewBuffer(100),
		logPhase:       logPhaseRuntime,
		startupLogSize: 200,
		runtimeLogs:    newStartupLogRing(10),
	}
	t.Cleanup(core.Stop)

	_, cancel := context.WithCancel(context.Background())
	return &Xray{config: cfg, cfg: &config.Config{}, core: core, handler: handler, cancelFunc: cancel}
}

func waitUntil(t *testing.T, what string, condition func() bool) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting until %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The panel gives up on a full sync after its RPC timeout while a large user
// list is still loading. Rolling back then restarted xray a second time and
// left it on the old users.
func TestSyncUsersOutlivesTheCaller(t *testing.T) {
	stats := &fakeStatsService{}
	x := newFakeCoreXray(t, stats)
	previous := x.config

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	syncErr := make(chan error, 1)
	go func() { syncErr <- x.SyncUsers(ctx, nil) }()
	waitUntil(t, "the full sync starts its candidate core", x.core.Started)
	pid := corePID(x)

	cancel()
	// Let at least one readiness probe run after the caller left.
	time.Sleep(1500 * time.Millisecond)
	stats.healthy.Store(true)

	select {
	case err := <-syncErr:
		if err != nil {
			t.Fatalf("SyncUsers failed after its caller went away: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("SyncUsers still running 10s after the core answered")
	}
	if got := corePID(x); got != pid {
		t.Fatalf("xray was restarted again after the caller went away (pid %d, now %d)", pid, got)
	}
	x.mu.RLock()
	kept := x.config == previous
	x.mu.RUnlock()
	if kept {
		t.Fatal("the full sync left xray on the previous config")
	}
}

func TestSyncUsersDoesNotStartXrayAfterShutdown(t *testing.T) {
	x := newFakeCoreXray(t, &fakeStatsService{})

	syncErr := make(chan error, 1)
	go func() { syncErr <- x.SyncUsers(context.Background(), nil) }()
	waitUntil(t, "the full sync starts its candidate core", x.core.Started)

	// Stop while the candidate is still booting: Shutdown kills it, the sync
	// sees the core die and rolls back to the previous config.
	x.Shutdown()

	for start := time.Now(); time.Since(start) < 3*time.Second; time.Sleep(10 * time.Millisecond) {
		if x.core.Started() {
			t.Fatal("the full-sync rollback started xray again after Shutdown")
		}
	}
	select {
	case err := <-syncErr:
		if err == nil {
			t.Fatal("SyncUsers reported success after Shutdown")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("SyncUsers still running 10s after Shutdown")
	}
}

func TestHealthLoopStopsWhenCancelledDuringAProbe(t *testing.T) {
	stats := &fakeStatsService{block: true, probes: make(chan struct{}, 1)}
	x := newFakeCoreXray(t, stats)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		x.checkXrayHealth(ctx)
		close(done)
	}()

	select {
	case <-stats.probes:
	case <-time.After(5 * time.Second):
		t.Fatal("the health loop sent no probe")
	}
	// Shutdown cancels the health context while the probe is in flight.
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("the health loop still runs 1s after its context was cancelled (xray restarted: %v)", x.core.Started())
	}
	if x.core.Started() {
		t.Fatal("the health loop restarted xray after its context was cancelled")
	}
}

func TestHealthRestartLeavesACoreThatAFullSyncReplaced(t *testing.T) {
	stats := &fakeStatsService{probes: make(chan struct{}, 1)}
	x := newFakeCoreXray(t, stats)

	// A full sync holds syncMu while its candidate core boots.
	x.syncMu.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go x.checkXrayHealth(ctx)

	select {
	case <-stats.probes:
	case <-time.After(5 * time.Second):
		x.syncMu.Unlock()
		t.Fatal("the health loop sent no probe")
	}
	time.Sleep(300 * time.Millisecond)
	if x.core.Started() {
		x.syncMu.Unlock()
		t.Fatal("the health loop restarted xray while a full sync held syncMu")
	}

	// The sync's core comes up and answers, then the sync releases syncMu.
	if err := x.restartCoreWithConfig(x.config); err != nil {
		x.syncMu.Unlock()
		t.Fatal(err)
	}
	pid := corePID(x)
	stats.healthy.Store(true)
	x.syncMu.Unlock()

	time.Sleep(500 * time.Millisecond)
	if got := corePID(x); got != pid {
		t.Fatalf("the health loop restarted the core the full sync had just started (pid %d, now %d)", pid, got)
	}
}

func realXrayUsers(n int, inbounds []string) []*common.User {
	users := make([]*common.User, 0, n)
	for i := range n {
		users = append(users, &common.User{
			Email:    strconv.Itoa(i + 1),
			Inbounds: inbounds,
			Proxies: &common.Proxy{
				Vmess:  &common.Vmess{Id: uuid.NewString()},
				Vless:  &common.Vless{Id: uuid.NewString()},
				Trojan: &common.Trojan{Password: "trojan-" + strconv.Itoa(i)},
			},
		})
	}
	return users
}

func realXrayConfig(t *testing.T, tags []string) *Config {
	t.Helper()

	inbounds := make([]map[string]any, 0, len(tags))
	for _, tag := range tags {
		settings := map[string]any{"clients": []any{}}
		if tag == Vless {
			settings["decryption"] = "none"
		}
		inbounds = append(inbounds, map[string]any{
			"tag":      tag,
			"listen":   "127.0.0.1",
			"port":     netutil.FindFreePort(),
			"protocol": tag,
			"settings": settings,
		})
	}
	raw, err := json.Marshal(map[string]any{
		"log":       map[string]any{"loglevel": "warning"},
		"inbounds":  inbounds,
		"outbounds": []any{map[string]any{"protocol": "freedom", "tag": "DIRECT"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := NewConfig(string(raw), nil)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// Removals sent while xray boots after a restart used to fail against the
// booting core and be dropped, while the new core, built from the user list
// before the removal, kept the users live.
func TestRestartHoldsUserSyncsUntilTheXrayAPIIsUp(t *testing.T) {
	executable := resolveXrayBinary(t)
	tags := []string{Vless, Vmess, Trojan}
	users := realXrayUsers(1000, tags)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	nodeCfg := &config.Config{
		XrayExecutablePath:  executable,
		XrayAssetsPath:      assetsPath,
		GeneratedConfigPath: t.TempDir(),
		LogBufferSize:       1000,
	}
	x, err := New(ctx, realXrayConfig(t, tags), users, netutil.FindFreePort(), netutil.FindFreePort(), nodeCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(x.Shutdown)

	pid := corePID(x)
	restartErr := make(chan error, 1)
	go func() { restartErr <- x.Restart() }()
	waitUntil(t, "the restart spawns a new xray", func() bool {
		current := corePID(x)
		return current != 0 && current != pid
	})

	// The panel disables users while the new core boots: they are sent with no inbounds.
	removed := make([]*common.User, 0, 51)
	for _, user := range users[:51] {
		removed = append(removed, &common.User{Email: user.Email, Proxies: user.Proxies})
	}
	if err := x.UpdateUsers(ctx, removed[:50]); err != nil {
		t.Fatal(err)
	}
	if err := x.SyncUser(ctx, removed[50]); err != nil {
		t.Fatal(err)
	}
	if err := <-restartErr; err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the xray API answers", func() bool {
		probeCtx, probeCancel := context.WithTimeout(ctx, time.Second)
		defer probeCancel()
		_, err := x.GetSysStats(probeCtx)
		return err == nil
	})

	// Xray's RemoveUser returns nil only for a user it still has.
	live := 0
	for _, user := range removed {
		for _, tag := range tags {
			if x.handler.RemoveInboundUser(ctx, tag, user.GetEmail()) == nil {
				live++
			}
		}
	}
	if live > 0 {
		t.Fatalf("%d of %d removed user-inbound pairs are still accepted by xray", live, len(removed)*len(tags))
	}
}
