//go:build !windows

package xray

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman/command"
	statsCommand "github.com/xtls/xray-core/app/stats/command"
	"google.golang.org/grpc"

	"github.com/pasarguard/node/backend/xray/api"
	"github.com/pasarguard/node/config"
	"github.com/pasarguard/node/pkg/logstream"
)

type hungInboundService struct {
	command.UnimplementedHandlerServiceServer
	reached chan struct{}
	once    sync.Once
}

func (s *hungInboundService) AlterInbound(ctx context.Context, _ *command.AlterInboundRequest) (*command.AlterInboundResponse, error) {
	s.once.Do(func() { close(s.reached) })
	<-ctx.Done()
	return nil, ctx.Err()
}

func newHungInboundXray(t *testing.T) (*Xray, *hungInboundService, *fakeStatsService) {
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
	hung := &hungInboundService{reached: make(chan struct{})}
	stats := &fakeStatsService{}
	server := grpc.NewServer()
	command.RegisterHandlerServiceServer(server, hung)
	statsCommand.RegisterStatsServiceServer(server, stats)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	handler, err := api.NewXrayAPI(listener.Addr().(*net.TCPAddr).Port)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(handler.Close)

	cfg, err := NewConfig(recordingInbounds, nil)
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
	return &Xray{config: cfg, cfg: &config.Config{}, core: core, handler: handler}, hung, stats
}

func startHungUserSync(t *testing.T, x *Xray, hung *hungInboundService) (context.CancelFunc, <-chan error) {
	t.Helper()

	syncCtx, stopSync := context.WithCancel(context.Background())
	t.Cleanup(stopSync)
	synced := make(chan error, 1)
	go func() { synced <- x.SyncUser(syncCtx, recordingUser("1.alice", "vless")) }()
	select {
	case <-hung.reached:
	case <-time.After(10 * time.Second):
		t.Fatal("the user sync never reached the core")
	}
	return stopSync, synced
}

func TestRestartIsNotBlockedByAUserSyncOnAnUnresponsiveCore(t *testing.T) {
	x, hung, stats := newHungInboundXray(t)
	stopSync, synced := startHungUserSync(t, x, hung)

	restarted := make(chan error, 1)
	go func() { restarted <- x.Restart() }()

	deadline := time.Now().Add(10 * time.Second)
	for !x.core.Started() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	blocked := !x.core.Started()

	stopSync()
	stats.healthy.Store(true)
	select {
	case <-restarted:
	case <-time.After(45 * time.Second):
		t.Fatal("the restart never returned after the user sync was cancelled")
	}
	<-synced

	if blocked {
		t.Fatal("Restart did not start a new core within 10s: it is still waiting for syncMu, held by a user sync whose AlterInbound call the unresponsive core never answers")
	}
}

func TestHealthLoopRestartsAnUnresponsiveCoreWhileAUserSyncIsStuckOnIt(t *testing.T) {
	x, hung, stats := newHungInboundXray(t)
	stats.healthy.Store(true)
	if err := x.Restart(); err != nil {
		t.Fatal(err)
	}
	first := corePID(x)

	stopSync, synced := startHungUserSync(t, x, hung)
	stats.healthy.Store(false)

	loopCtx, stopLoop := context.WithCancel(context.Background())
	t.Cleanup(stopLoop)
	looped := make(chan struct{})
	go func() {
		x.checkXrayHealth(loopCtx)
		close(looped)
	}()

	replaced := false
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if pid := corePID(x); pid != 0 && pid != first {
			replaced = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	stopLoop()
	stopSync()
	stats.healthy.Store(true)
	select {
	case <-looped:
	case <-time.After(45 * time.Second):
		t.Fatal("the health loop never returned after it was cancelled")
	}
	<-synced

	if !replaced {
		t.Fatal("the health loop did not replace the unresponsive core within 60s: its restart is waiting for syncMu, held by a user sync whose AlterInbound call the core never answers")
	}
}

func TestHealthLoopRestartsAnUnresponsiveCoreWithNoUserSyncInFlight(t *testing.T) {
	x, _, stats := newHungInboundXray(t)
	stats.healthy.Store(true)
	if err := x.Restart(); err != nil {
		t.Fatal(err)
	}
	first := corePID(x)
	stats.healthy.Store(false)

	loopCtx, stopLoop := context.WithCancel(context.Background())
	t.Cleanup(stopLoop)
	looped := make(chan struct{})
	go func() {
		x.checkXrayHealth(loopCtx)
		close(looped)
	}()

	replaced := false
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if pid := corePID(x); pid != 0 && pid != first {
			replaced = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	stopLoop()
	stats.healthy.Store(true)
	select {
	case <-looped:
	case <-time.After(45 * time.Second):
		t.Fatal("the health loop never returned after it was cancelled")
	}

	if !replaced {
		t.Fatal("the health loop did not replace the unresponsive core within 60s")
	}
}
