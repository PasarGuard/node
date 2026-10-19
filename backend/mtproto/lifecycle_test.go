//go:build !windows

package mtproto

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
)

// newTestBackend starts the backend against the fake telemt and shuts it
// down when the test ends.
func newTestBackend(t *testing.T, cfg *config.Config, users []*common.User) *MTProto {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	mt, err := New(ctx, cfg, testMTConfig(t), users)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(mt.Shutdown)
	return mt
}

func TestStartFailureIncludesLogTail(t *testing.T) {
	exe := writeFakeTelemt(t, fakeTelemt{
		NoAPI:     true,
		Stderr:    []string{"[telemt] Error: Config error: bad listener"},
		ExitAfter: 10 * time.Millisecond,
		ExitCode:  1,
	})

	mt, err := New(context.Background(), testNodeConfig(t, exe), testMTConfig(t), nil)
	if err == nil {
		mt.Shutdown()
		t.Fatal("New succeeded although telemt exited")
	}
	if !strings.Contains(err.Error(), "bad listener") {
		t.Errorf("error %q does not include telemt's output", err)
	}
	if strings.TrimSpace(err.Error()) == "exit status 1" {
		t.Error("the startup error is a bare exit status")
	}
}

// TestStartTimeoutIncludesLogTail covers telemt that never binds its API
// (Telegram unreachable): New gives up after telemtStartupTimeout, reports
// the output so far, and leaves no telemt running.
func TestStartTimeoutIncludesLogTail(t *testing.T) {
	// Long enough for the fake (a race-instrumented test binary) to start and
	// print its line before the deadline.
	lowerStartupTimeout(t, 5*time.Second)
	record := filepath.Join(t.TempDir(), "record.json")
	exe := writeFakeTelemt(t, fakeTelemt{
		NoAPI:      true,
		RecordFile: record,
		Stderr:     []string{"checking Telegram DC connectivity"},
	})

	mt, err := New(context.Background(), testNodeConfig(t, exe), testMTConfig(t), nil)
	if err == nil {
		mt.Shutdown()
		t.Fatal("New succeeded although the telemt API never came up")
	}
	for _, want := range []string{"did not become healthy within 5s", "checking Telegram DC connectivity"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}

	pid := readFakeTelemtRecord(t, record).PID
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Errorf("telemt %d is still running after the failed start (kill 0: %v)", pid, err)
	}
}

func TestStartWaitsForSlowAPI(t *testing.T) {
	// The API binds 2 s after the fake starts; the timeout leaves room for a
	// slow start of the fake itself under -race.
	lowerStartupTimeout(t, 10*time.Second)
	exe := writeFakeTelemt(t, fakeTelemt{HealthDelay: 2 * time.Second})

	mt := newTestBackend(t, testNodeConfig(t, exe), nil)
	if !mt.Started() {
		t.Fatal("backend not started")
	}
	if got := mt.Version(); got != "3.5.14" {
		t.Errorf("Version() = %q, want 3.5.14", got)
	}
}

func TestGeneratedDirSymlinkResolved(t *testing.T) {
	realDir := t.TempDir()
	link := filepath.Join(t.TempDir(), "generated")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(t.TempDir(), "record.json")
	cfg := testNodeConfig(t, writeFakeTelemt(t, fakeTelemt{RecordFile: record}))
	cfg.GeneratedConfigPath = link

	newTestBackend(t, cfg, nil)

	args := readFakeTelemtRecord(t, record).Args
	if len(args) != 2 {
		t.Fatalf("telemt argv = %q", args)
	}
	resolvedRoot, err := filepath.EvalSymlinks(realDir)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(resolvedRoot, "telemt", "config.toml"); args[1] != want {
		t.Errorf("config path = %q, want %q", args[1], want)
	}
	if resolved, err := filepath.EvalSymlinks(args[1]); err != nil || resolved != args[1] {
		t.Errorf("config path %q still has a symlink component (resolves to %q, %v)", args[1], resolved, err)
	}
}

func TestTelemtDirIsPrivate(t *testing.T) {
	cfg := testNodeConfig(t, writeFakeTelemt(t, fakeTelemt{}))
	telemtDir := filepath.Join(cfg.GeneratedConfigPath, "telemt")
	// A directory left by an older node build may be world readable.
	if err := os.MkdirAll(telemtDir, 0o755); err != nil {
		t.Fatal(err)
	}

	newTestBackend(t, cfg, nil)

	info, err := os.Stat(telemtDir)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o700 {
		t.Errorf("telemt dir mode = %o, want 700", mode)
	}
}

func TestShutdownRemovesRenderedConfig(t *testing.T) {
	cfg := testNodeConfig(t, writeFakeTelemt(t, fakeTelemt{}))
	mt := newTestBackend(t, cfg, []*common.User{mtUser("alice", "mtproto", testSecret)})

	configPath := mt.configPath
	if _, err := os.Stat(configPath); err != nil {
		t.Fatalf("rendered config missing while running: %v", err)
	}

	mt.Shutdown()

	if _, err := os.Stat(configPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("config.toml still exists after Shutdown (stat: %v)", err)
	}
	if mt.Started() {
		t.Error("Started() is true after Shutdown")
	}
	mt.Shutdown() // a second Shutdown is a no-op
}

// TestSyncAfterShutdownReturnsErrClosed is the regression for a sync that
// reached a shut-down backend, started a new telemt and crashed the node
// with "send on closed channel".
func TestSyncAfterShutdownReturnsErrClosed(t *testing.T) {
	cfg := testNodeConfig(t, writeFakeTelemt(t, fakeTelemt{}))
	mt := newTestBackend(t, cfg, nil)
	mt.Shutdown()

	ctx := context.Background()
	users := []*common.User{mtUser("alice", "mtproto", testSecret)}
	calls := map[string]func() error{
		"SyncUsers":             func() error { return mt.SyncUsers(ctx, users) },
		"UpdateUsers":           func() error { return mt.UpdateUsers(ctx, users) },
		"SyncUser":              func() error { return mt.SyncUser(ctx, users[0]) },
		"UpdateUsersAndRestart": func() error { return mt.UpdateUsersAndRestart(ctx, users) },
		"Restart":               mt.Restart,
	}
	for name, call := range calls {
		if err := call(); !errors.Is(err, errClosed) {
			t.Errorf("%s after Shutdown = %v, want errClosed", name, err)
		}
	}

	if mt.Started() || mt.process.Generation() != 1 {
		t.Errorf("a telemt was started after Shutdown (started %v, generation %d)", mt.Started(), mt.process.Generation())
	}
	if _, err := os.Stat(mt.configPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a call after Shutdown wrote the config again (stat: %v)", err)
	}
}

func TestSupervisorRestartsCrashedTelemt(t *testing.T) {
	exe := writeFakeTelemt(t, fakeTelemt{
		ExitAfter:    time.Second,
		ExitCode:     1,
		ExitOnceFile: filepath.Join(t.TempDir(), "crashed-once"),
	})
	mt := newTestBackend(t, testNodeConfig(t, exe), nil)
	if mt.process.Generation() != 1 {
		t.Fatalf("Generation() = %d after New, want 1", mt.process.Generation())
	}

	waitFor(t, 10*time.Second, "the supervisor to restart telemt", func() bool {
		return mt.Started() && mt.process.Generation() == 2
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	logs := mt.SubscribeLogs(ctx)
	for {
		select {
		case line := <-logs:
			if strings.HasPrefix(line, "telemt exited unexpectedly: exit status 1") {
				return
			}
		case <-ctx.Done():
			t.Fatal(`no "telemt exited unexpectedly" line was published`)
		}
	}
}

func TestPickInternalPorts(t *testing.T) {
	sequence := func(ports ...int) func() int {
		return func() int {
			port := ports[0]
			if len(ports) > 1 {
				ports = ports[1:]
			}
			return port
		}
	}

	apiPort, metricsPort, err := pickInternalPorts([]int{443, 8443}, sequence(443, 65536, 20000, 20000, 8443, 30000))
	if err != nil {
		t.Fatalf("pickInternalPorts: %v", err)
	}
	if apiPort != 20000 || metricsPort != 30000 {
		t.Errorf("ports = %d, %d; want 20000, 30000", apiPort, metricsPort)
	}

	if _, _, err := pickInternalPorts([]int{443}, sequence(443)); err == nil || !strings.Contains(err.Error(), "API port") {
		t.Errorf("an endless clash with the listen port must fail naming the API port, got %v", err)
	}
	if _, _, err := pickInternalPorts([]int{443}, sequence(20000)); err == nil || !strings.Contains(err.Error(), "metrics port") {
		t.Errorf("an endless clash with the API port must fail naming the metrics port, got %v", err)
	}
}

func TestAPIClientReady(t *testing.T) {
	status := http.StatusServiceUnavailable
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/health/ready" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		if status == http.StatusOK {
			_, _ = w.Write([]byte(`{"ok":true,"data":{"ready":true,"status":"ready"},"revision":"r"}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true,"data":{"ready":false,"status":"not_ready","reason":"admission_closed"},"revision":"r"}`))
	}))
	defer server.Close()

	client := newAPIClient(server.URL, "Bearer test")
	err := client.Ready(context.Background())
	if err == nil || !strings.Contains(err.Error(), "admission_closed") {
		t.Errorf("Ready on 503 = %v, want an error naming the reason", err)
	}

	status = http.StatusOK
	if err := client.Ready(context.Background()); err != nil {
		t.Errorf("Ready on 200 = %v, want nil", err)
	}
}

// TestWaitForReadyGivesUp checks the readiness wait is bounded and reports
// the reason; New only logs this, so Start never fails on Telegram egress.
func TestWaitForReadyGivesUp(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"ok":true,"data":{"ready":false,"reason":"no_healthy_upstreams"},"revision":"r"}`))
	}))
	defer server.Close()

	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	mt := &MTProto{apiClient: newAPIClient(server.URL, ""), lifetime: lifetime}

	err := mt.waitForReady(context.Background(), 300*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "no_healthy_upstreams") {
		t.Errorf("waitForReady = %v, want an error naming the reason", err)
	}
}
