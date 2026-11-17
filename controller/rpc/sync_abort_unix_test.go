//go:build !windows

package rpc

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pasarguard/node/backend"
	"github.com/pasarguard/node/common"
)

func runningBackend(t *testing.T) backend.Backend {
	t.Helper()
	service := sharedTestCtx.service.(*Service)
	if back := service.Backend(); back != nil && back.Started() {
		return back
	}
	configFile, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(sharedTestCtx.ctxWithSession, 30*time.Second)
	defer cancel()
	if _, err := sharedTestCtx.client.Start(ctx, &common.Backend{
		Type:      common.BackendType_XRAY,
		Config:    string(configFile),
		KeepAlive: 10,
	}); err != nil {
		t.Fatalf("Failed to start backend: %v", err)
	}
	back := service.Backend()
	if back == nil || !back.Started() {
		t.Fatal("the backend did not start")
	}
	return back
}

func stopCoreProcess(t *testing.T) {
	t.Helper()
	out, err := exec.Command("pgrep", "-P", strconv.Itoa(os.Getpid())).Output()
	if err != nil {
		t.Fatalf("no core process under the test process: %v", err)
	}
	fields := strings.Fields(string(out))
	if len(fields) != 1 {
		t.Fatalf("want exactly one core process under the test process, got %q", fields)
	}
	pid, err := strconv.Atoi(fields[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(pid, syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGCONT) })
}

func TestGRPC_SyncUsersChunkedAbortedByACoreRestartIsUnavailable(t *testing.T) {
	back := runningBackend(t)
	stopCoreProcess(t)

	ctx, cancel := context.WithTimeout(sharedTestCtx.ctxWithSession, 90*time.Second)
	defer cancel()
	stream, err := sharedTestCtx.client.SyncUsersChunked(ctx)
	if err != nil {
		t.Fatalf("Failed to open chunked sync stream: %v", err)
	}
	if err = stream.Send(&common.UsersChunk{
		Index: 0,
		Users: []*common.User{{
			Email:    "abort_user1@example.com",
			Inbounds: []string{"VMESS TCP NOTLS"},
			Proxies:  &common.Proxy{Vmess: &common.Vmess{Id: uuid.New().String()}},
		}},
		Last: true,
	}); err != nil {
		t.Fatalf("Failed to send chunk: %v", err)
	}

	answered := make(chan error, 1)
	go func() {
		_, err := stream.CloseAndRecv()
		answered <- err
	}()
	select {
	case err := <-answered:
		t.Fatalf("the chunked sync returned %v while the core was stopped, want it stuck until the restart", err)
	case <-time.After(2 * time.Second):
	}

	restarted := make(chan error, 1)
	go func() { restarted <- back.Restart() }()

	select {
	case err := <-answered:
		if got := status.Code(err); got != codes.Unavailable {
			t.Errorf("the chunked sync aborted by a core restart answered %s (%v), want Unavailable so the bridge retries the batch instead of splitting it", got, err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the chunked sync never returned after the restart")
	}
	select {
	case err := <-restarted:
		if err != nil {
			t.Fatalf("restart failed: %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("the restart never returned")
	}
	if !back.Started() {
		t.Fatal("the backend has no running core after the restart")
	}
}
