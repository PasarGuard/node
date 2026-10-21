//go:build !windows

package xray

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	statsCommand "github.com/xtls/xray-core/app/stats/command"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pasarguard/node/backend/xray/api"
	"github.com/pasarguard/node/config"
	"github.com/pasarguard/node/pkg/logstream"
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
