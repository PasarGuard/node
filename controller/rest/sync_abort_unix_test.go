//go:build !windows

package rest

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

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
	var info common.BaseInfoResponse
	if err := sharedTestCtx.createAuthenticatedRequest("POST", "/start", &common.Backend{
		Type:   common.BackendType_XRAY,
		Config: string(configFile),
	}, &info); err != nil {
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

type syncAnswer struct {
	status int
	body   string
	err    error
}

func TestREST_SyncUserAbortedByACoreRestartIsServiceUnavailable(t *testing.T) {
	back := runningBackend(t)
	stopCoreProcess(t)

	body, err := proto.Marshal(&common.User{
		Email:    "abort_rest_user1@example.com",
		Inbounds: []string{"VMESS TCP NOTLS"},
		Proxies:  &common.Proxy{Vmess: &common.Vmess{Id: uuid.New().String()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("PUT", sharedTestCtx.url+"/user/sync", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("x-api-key", apiKey.String())
	req.Header.Set("Content-Type", "application/x-protobuf")

	answered := make(chan syncAnswer, 1)
	go func() {
		resp, err := sharedTestCtx.client.Do(req)
		if err != nil {
			answered <- syncAnswer{err: err}
			return
		}
		defer resp.Body.Close()
		text, _ := io.ReadAll(resp.Body)
		answered <- syncAnswer{status: resp.StatusCode, body: string(text)}
	}()
	select {
	case got := <-answered:
		t.Fatalf("the user sync returned %d %q %v while the core was stopped, want it stuck until the restart", got.status, got.body, got.err)
	case <-time.After(2 * time.Second):
	}

	restarted := make(chan error, 1)
	go func() { restarted <- back.Restart() }()

	select {
	case got := <-answered:
		if got.err != nil {
			t.Fatalf("the user sync request failed: %v", got.err)
		}
		if got.status != http.StatusServiceUnavailable {
			t.Errorf("the user sync aborted by a core restart answered %d %q, want 503 so the bridge retries instead of splitting the batch", got.status, strings.TrimSpace(got.body))
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the user sync never returned after the restart")
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
