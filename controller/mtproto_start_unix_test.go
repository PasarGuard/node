//go:build !windows

package controller

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pelletier/go-toml/v2"
	"google.golang.org/protobuf/proto"

	"github.com/pasarguard/node/backend"
	"github.com/pasarguard/node/backend/mtproto"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
	"github.com/pasarguard/node/pkg/netutil"
)

// The fake telemt is this test binary run as TestHelperFakeTelemt through a
// wrapper script, so the node starts, signals and reaps a real child process.
const (
	// fakeTelemtHealthDelayEnv holds how long the fake waits before it binds
	// its API, like telemt waiting for Telegram DCs; "never" means it never does.
	fakeTelemtHealthDelayEnv = "CONTROLLER_FAKE_TELEMT_HEALTH_DELAY"
	// fakeTelemtPIDFileEnv names the file the fake writes its pid to.
	fakeTelemtPIDFileEnv = "CONTROLLER_FAKE_TELEMT_PID_FILE"
)

// TestHelperFakeTelemt is not a real test: it is the fake telemt process.
func TestHelperFakeTelemt(t *testing.T) {
	delay, ok := os.LookupEnv(fakeTelemtHealthDelayEnv)
	if !ok {
		t.Skip("helper process for the fake telemt; runs only when re-executed by a test")
	}
	os.Exit(runFakeTelemt(delay, os.Getenv(fakeTelemtPIDFileEnv), os.Args))
}

func runFakeTelemt(delay, pidFile string, args []string) int {
	// The wrapper passes telemt's own arguments after "--".
	for i, arg := range args {
		if arg == "--" {
			args = args[i+1:]
			break
		}
	}
	if len(args) > 0 && args[0] == "--version" {
		fmt.Println("telemt 3.5.14")
		return 0
	}
	if len(args) != 2 || args[0] != "run" {
		fmt.Fprintln(os.Stderr, "fake telemt: unexpected arguments", args)
		return 2
	}
	if pidFile != "" {
		if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "fake telemt:", err)
			return 2
		}
	}
	// Catch SIGHUP like telemt, whose hot reload it starts; by default it
	// would end this process.
	signal.Notify(make(chan os.Signal, 1), syscall.SIGHUP)
	// Never outlive a broken test by much.
	go func() {
		time.Sleep(2 * time.Minute)
		os.Exit(3)
	}()

	if delay == "never" {
		select {}
	}
	wait, err := time.ParseDuration(delay)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fake telemt: bad health delay:", err)
		return 2
	}
	time.Sleep(wait)

	listen, err := fakeTelemtAPIListen(args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "fake telemt:", err)
		return 2
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true,"data":{"status":"ok","read_only":false},"revision":"r"}`))
	})
	mux.HandleFunc("/v1/health/ready", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true,"data":{"ready":true,"status":"ready"},"revision":"r"}`))
	})
	if err := http.ListenAndServe(listen, mux); err != nil {
		fmt.Fprintln(os.Stderr, "fake telemt: api:", err)
		return 1
	}
	return 0
}

// fakeTelemtAPIListen reads server.api.listen from the rendered config.
func fakeTelemtAPIListen(configPath string) (string, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", err
	}
	var rendered struct {
		Server struct {
			API struct {
				Listen string `toml:"listen"`
			} `toml:"api"`
		} `toml:"server"`
	}
	if err := toml.Unmarshal(data, &rendered); err != nil {
		return "", err
	}
	if rendered.Server.API.Listen == "" {
		return "", errors.New("server.api.listen not found in " + configPath)
	}
	return rendered.Server.API.Listen, nil
}

// newFakeTelemtController returns a controller whose telemt is the fake. It
// binds its API after healthDelay ("never" for a start that never ends on
// its own) and writes its pid to the returned file.
func newFakeTelemtController(t *testing.T, healthDelay string) (*Controller, string) {
	t.Helper()
	cfg, pidFile := fakeTelemtConfig(t, healthDelay)
	c := New(cfg)
	t.Cleanup(c.Disconnect)
	return c, pidFile
}

// fakeTelemtConfig returns a node config whose telemt is the fake (see
// newFakeTelemtController) and the file the fake writes its pid to.
func fakeTelemtConfig(t *testing.T, healthDelay string) (*config.Config, string) {
	t.Helper()
	testBinary, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "telemt.pid")
	script := fmt.Sprintf("#!/bin/sh\nexport %s=%s %s=%s\nexec %s -test.run='^TestHelperFakeTelemt$' -- \"$@\"\n",
		fakeTelemtHealthDelayEnv, shellQuote(healthDelay), fakeTelemtPIDFileEnv, shellQuote(pidFile), shellQuote(testBinary))
	executable := filepath.Join(dir, "telemt")
	if err := os.WriteFile(executable, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	cfg := config.NewTestConfig(t.TempDir(), uuid.New())
	cfg.TelemtExecutablePath = executable
	return cfg, pidFile
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

func mtprotoStartRequest() *common.Backend {
	return &common.Backend{
		Type: common.BackendType_MTPROTO,
		Config: fmt.Sprintf(`{"inbound_tag": "mtproto", "server": {"port": %d, "listeners": [{"ip": "127.0.0.1"}]}}`,
			netutil.FindFreePort()),
		KeepAlive: 60,
		Users: []*common.User{{
			Email:    "1",
			Inbounds: []string{"mtproto"},
			Proxies:  &common.Proxy{Mtproto: &common.Mtproto{Secret: "0123456789abcdef0123456789abcdef"}},
		}},
	}
}

// readFakeTelemtPID waits for the fake to write its pid.
func readFakeTelemtPID(t *testing.T, pidFile string) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if data, err := os.ReadFile(pidFile); err == nil {
			if pid, err := strconv.Atoi(string(data)); err == nil {
				return pid
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("the fake telemt did not start within 10s")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A slow MTProto Start (telemt waits for Telegram DCs before it binds its
// API) must not die with the panel's request, like an xray start.
func TestMTProtoStartOutlivesItsCaller(t *testing.T) {
	c, _ := newFakeTelemtController(t, "1s")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.LockControl()
	err := c.StartOrAttach(ctx, mtprotoStartRequest())
	back := c.Backend()
	c.UnlockControl()
	if err != nil {
		t.Fatalf("an MTProto Start whose caller went away failed: %v", err)
	}
	if back == nil || !back.Started() {
		t.Fatal("no running telemt after a Start whose caller went away")
	}
	// The start context ends when StartOrAttach returns: telemt must not
	// follow it.
	time.Sleep(500 * time.Millisecond)
	if !back.Started() {
		t.Fatal("telemt stopped once StartOrAttach returned")
	}
}

// The panel retries a timed-out MTProto Start with the same config. The retry
// waits for the start in progress and attaches to it: a same-config Start is
// a heartbeat once the running backend passes its health check.
func TestMTProtoRetryAttachesToAStartInProgress(t *testing.T) {
	c, _ := newFakeTelemtController(t, "1s")
	first := mtprotoStartRequest()
	retry := proto.Clone(first).(*common.Backend)

	type result struct {
		err  error
		back backend.Backend
	}
	start := func(ctx context.Context, data *common.Backend, locked chan<- struct{}, out chan<- result) {
		c.LockControl()
		if locked != nil {
			close(locked)
		}
		err := c.StartOrAttach(ctx, data)
		back := c.Backend()
		c.UnlockControl()
		out <- result{err, back}
	}

	gaveUp, cancel := context.WithCancel(context.Background())
	cancel()
	locked := make(chan struct{})
	firstDone := make(chan result, 1)
	go start(gaveUp, first, locked, firstDone)
	<-locked
	waitForStartInProgress(t, c)

	retryCtx, cancelRetry := context.WithTimeout(context.Background(), time.Minute)
	defer cancelRetry()
	retryDone := make(chan result, 1)
	go start(retryCtx, retry, nil, retryDone)

	r1, r2 := <-firstDone, <-retryDone
	if r1.err != nil {
		t.Fatalf("first Start: %v", r1.err)
	}
	if r2.err != nil {
		t.Fatalf("retried Start: %v", r2.err)
	}
	if r2.back != r1.back {
		t.Fatal("the retried Start restarted telemt instead of attaching to it")
	}
	if !r2.back.Started() {
		t.Fatal("no running telemt after the retried Start")
	}
}

// Process shutdown calls Disconnect without LockControl. It must abort an
// MTProto start that waits for telemt's API instead of waiting up to the
// telemt startup timeout (90 s), and it must leave no telemt running.
func TestDisconnectAbortsAnMTProtoStartInProgress(t *testing.T) {
	c, pidFile := newFakeTelemtController(t, "never")

	startErr := make(chan error, 1)
	go func() {
		c.LockControl()
		defer c.UnlockControl()
		startErr <- c.StartOrAttach(context.Background(), mtprotoStartRequest())
	}()
	pid := readFakeTelemtPID(t, pidFile)
	waitForStartInProgress(t, c)

	disconnected := make(chan struct{})
	go func() {
		c.Disconnect()
		close(disconnected)
	}()

	select {
	case err := <-startErr:
		if err == nil {
			t.Fatal("an MTProto start aborted by Disconnect reported success")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the MTProto start still runs 10s after Disconnect")
	}
	select {
	case <-disconnected:
	case <-time.After(10 * time.Second):
		t.Fatal("Disconnect still blocked 10s after the start ended")
	}
	if c.Backend() != nil {
		t.Fatal("an aborted start left a backend attached")
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Errorf("telemt %d still runs after the aborted start (kill 0: %v)", pid, err)
	}
}

// telemt cannot take a changed core config live (MTProto does not implement
// backend.LiveConfigApplier), so a Start with another config restarts it on
// the new one instead of keeping the old telemt.
func TestMTProtoConfigChangeRestartsTelemt(t *testing.T) {
	c, pidFile := newFakeTelemtController(t, "0s")
	if _, live := any(&mtproto.MTProto{}).(backend.LiveConfigApplier); live {
		t.Fatal("MTProto implements LiveConfigApplier: check that a live apply is correct for telemt")
	}

	start := func(data *common.Backend) backend.Backend {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		c.LockControl()
		defer c.UnlockControl()
		if err := c.StartOrAttach(ctx, data); err != nil {
			t.Fatalf("Start: %v", err)
		}
		return c.Backend()
	}

	first := start(mtprotoStartRequest())
	oldPID := readFakeTelemtPID(t, pidFile)
	second := start(mtprotoStartRequest()) // another listener port
	if second == first {
		t.Fatal("a Start with another MTProto config kept the running backend")
	}
	if !second.Started() {
		t.Fatal("no running telemt after the config change")
	}
	if err := syscall.Kill(oldPID, 0); !errors.Is(err, syscall.ESRCH) {
		t.Errorf("the old telemt %d still runs after the config change (kill 0: %v)", oldPID, err)
	}
}

// The panel tells an old node from a broken one by the exact error text
// "invalid backend type", which nodes without the MTProto backend answer to
// an MTProto Start. The start runs detached from the request now (#116),
// and only a start that runs out of startTimeout gets its error wrapped, so
// that text must reach the caller unchanged, even when the request is gone.
func TestUnknownBackendTypeKeepsItsError(t *testing.T) {
	c := New(config.NewTestConfig(t.TempDir(), uuid.New()))
	t.Cleanup(c.Disconnect)

	gone, cancel := context.WithCancel(context.Background())
	cancel()
	for name, ctx := range map[string]context.Context{"live request": context.Background(), "request gone": gone} {
		c.LockControl()
		err := c.StartOrAttach(ctx, &common.Backend{Type: common.BackendType(99), Config: "{}"})
		c.UnlockControl()
		if err == nil || err.Error() != "invalid backend type" {
			t.Errorf("%s: Start with an unknown backend type = %v, want exactly %q", name, err, "invalid backend type")
		}
	}
}
