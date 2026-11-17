//go:build !windows

package xray

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman/command"
	statsCommand "github.com/xtls/xray-core/app/stats/command"
	"google.golang.org/grpc"

	"github.com/pasarguard/node/backend"
	"github.com/pasarguard/node/backend/xray/api"
	"github.com/pasarguard/node/common"
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
	stats := &fakeStatsService{}
	x, hung := newHungInboundXrayWithStats(t, stats)
	return x, hung, stats
}

func newHungInboundXrayWithStats(t *testing.T, stats statsCommand.StatsServiceServer) (*Xray, *hungInboundService) {
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
	return &Xray{config: cfg, cfg: &config.Config{}, core: core, handler: handler}, hung
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

func TestRestartIsNotBlockedByAUserSyncQueuedBehindAStuckOne(t *testing.T) {
	x, hung, stats := newHungInboundXray(t)
	stopSync, synced := startHungUserSync(t, x, hung)

	queuedCtx, stopQueued := context.WithCancel(context.Background())
	t.Cleanup(stopQueued)
	queued := make(chan error, 1)
	go func() { queued <- x.SyncUser(queuedCtx, recordingUser("2.bob", "vless")) }()
	time.Sleep(300 * time.Millisecond)

	restarted := make(chan error, 1)
	go func() { restarted <- x.Restart() }()

	deadline := time.Now().Add(10 * time.Second)
	for !x.core.Started() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	blocked := !x.core.Started()

	stopSync()
	stopQueued()
	stats.healthy.Store(true)
	select {
	case <-restarted:
	case <-time.After(45 * time.Second):
		t.Fatal("the restart never returned after the user syncs were cancelled")
	}
	<-synced
	<-queued

	if blocked {
		t.Fatal("Restart did not start a new core within 10s: a second user sync queued on syncMu took the lock after the first one was aborted and is now stuck on the unresponsive core")
	}
}

type healingStatsService struct {
	*fakeStatsService
	failuresLeft atomic.Int32
}

func (s *healingStatsService) GetSysStats(ctx context.Context, req *statsCommand.SysStatsRequest) (*statsCommand.SysStatsResponse, error) {
	if s.failuresLeft.Add(-1) >= 0 {
		return nil, errors.New("core busy")
	}
	return s.fakeStatsService.GetSysStats(ctx, req)
}

func TestHealthLoopReplacesTheCoreAfterAbortingAUserSyncEvenWhenTheCoreAnswersAgain(t *testing.T) {
	stats := &healingStatsService{fakeStatsService: &fakeStatsService{}}
	stats.healthy.Store(true)
	x, hung := newHungInboundXrayWithStats(t, stats)
	if err := x.Restart(); err != nil {
		t.Fatal(err)
	}
	first := corePID(x)

	stopSync, synced := startHungUserSync(t, x, hung)
	stats.failuresLeft.Store(10)

	loopCtx, stopLoop := context.WithCancel(context.Background())
	t.Cleanup(stopLoop)
	looped := make(chan struct{})
	go func() {
		x.checkXrayHealth(loopCtx)
		close(looped)
	}()

	replaced := false
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		if pid := corePID(x); pid != 0 && pid != first {
			replaced = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	stopLoop()
	stopSync()
	select {
	case <-looped:
	case <-time.After(45 * time.Second):
		t.Fatal("the health loop never returned after it was cancelled")
	}
	<-synced

	if !replaced {
		t.Fatal("the health loop aborted a user sync and then skipped the restart because the core answered the re-probe: the core may now lack users that x.config holds")
	}
}

func TestRestartDuringAUserSyncKeepsTheUserForTheRebuiltCore(t *testing.T) {
	x, hung, stats := newHungInboundXray(t)
	stats.healthy.Store(true)
	_, synced := startHungUserSync(t, x, hung)

	restarted := make(chan error, 1)
	go func() { restarted <- x.Restart() }()
	select {
	case <-restarted:
	case <-time.After(45 * time.Second):
		t.Fatal("the restart never returned")
	}
	select {
	case err := <-synced:
		if !errors.Is(err, errSyncAborted) {
			t.Fatalf("the aborted user sync returned %v, want errSyncAborted", err)
		}
		if !backend.IsRetryLater(err) {
			t.Fatalf("the aborted user sync returned %v as a plain error, which the node answers as Internal / 500: want a backend.RetryLaterError, answered as Unavailable / 503", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the user sync never returned after the restart")
	}

	x.mu.RLock()
	cfg := x.config
	x.mu.RUnlock()
	for _, inbound := range cfg.InboundConfigs {
		if inbound.Tag != "vless" {
			continue
		}
		inbound.mu.RLock()
		_, ok := inbound.clients["1.alice"]
		inbound.mu.RUnlock()
		if !ok {
			t.Fatal("Restart aborted the user sync and the sync dropped 1.alice from x.config, so the rebuilt core does not have the user")
		}
		return
	}
	t.Fatal("no vless inbound in x.config")
}

func TestRestartDuringAUserUpdateAbortsItAsRetryLater(t *testing.T) {
	x, hung, stats := newHungInboundXray(t)
	stats.healthy.Store(true)

	updated := make(chan error, 1)
	go func() {
		updated <- x.UpdateUsers(context.Background(), []*common.User{recordingUser("1.alice", "vless")})
	}()
	select {
	case <-hung.reached:
	case <-time.After(10 * time.Second):
		t.Fatal("the user update never reached the core")
	}

	restarted := make(chan error, 1)
	go func() { restarted <- x.Restart() }()
	select {
	case <-restarted:
	case <-time.After(45 * time.Second):
		t.Fatal("the restart never returned")
	}
	select {
	case err := <-updated:
		if !errors.Is(err, errSyncAborted) {
			t.Fatalf("the aborted user update returned %v, want errSyncAborted", err)
		}
		if !backend.IsRetryLater(err) {
			t.Fatalf("the aborted user update returned %v as a plain error, which the node answers as Internal / 500: want a backend.RetryLaterError, answered as Unavailable / 503", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the user update never returned after the restart")
	}
}
