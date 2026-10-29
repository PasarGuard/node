//go:build !windows

package controller

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/pasarguard/node/backend"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
	"github.com/pasarguard/node/pkg/netutil"
)

func xrayStartRequest(t *testing.T) *common.Backend {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"tag":      "vless",
			"listen":   "127.0.0.1",
			"port":     netutil.FindFreePort(),
			"protocol": "vless",
			"settings": map[string]any{"clients": []any{}, "decryption": "none"},
		}},
		"outbounds": []any{map[string]any{"protocol": "freedom", "tag": "DIRECT"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &common.Backend{
		Type:      common.BackendType_XRAY,
		Config:    string(raw),
		KeepAlive: 60,
		Users: []*common.User{{
			Email:    "1",
			Inbounds: []string{"vless"},
			Proxies:  &common.Proxy{Vless: &common.Vless{Id: uuid.NewString()}},
		}},
	}
}

// newXrayController returns a controller that runs the real xray binary. CI
// and the Docker suite install it at the default path.
func newXrayController(t *testing.T) *Controller {
	t.Helper()
	cfg := config.NewTestConfig(t.TempDir(), uuid.New())
	if _, err := os.Stat(cfg.XrayExecutablePath); err != nil {
		t.Skipf("no xray binary at %s", cfg.XrayExecutablePath)
	}
	c := New(cfg)
	t.Cleanup(c.Disconnect)
	return c
}

// newFakeXrayController returns a controller whose xray never opens its API,
// so a Start stays in progress until it is cancelled.
func newFakeXrayController(t *testing.T) *Controller {
	t.Helper()
	dir := t.TempDir()
	executable := filepath.Join(dir, "xray")
	script := "#!/bin/sh\nif [ \"$1\" = version ]; then echo 'Xray 26.1.1 (fake)'; exit 0; fi\nexec sleep 60\n"
	if err := os.WriteFile(executable, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := config.NewTestConfig(dir, uuid.New())
	cfg.XrayExecutablePath = executable
	cfg.XrayAssetsPath = dir
	c := New(cfg)
	t.Cleanup(c.Disconnect)
	return c
}

// waitForStartInProgress waits until StartBackend holds mu.
func waitForStartInProgress(t *testing.T, c *Controller) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for c.mu.TryRLock() {
		c.mu.RUnlock()
		if time.Now().After(deadline) {
			t.Fatal("no start in progress after 5s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The panel gives up on Start after its RPC timeout (10 s by default) and then
// attaches to the core if it came up. A large user list takes xray longer than
// that to load, so the start must not die with the request.
func TestStartOutlivesItsCaller(t *testing.T) {
	c := newXrayController(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.LockControl()
	err := c.StartOrAttach(ctx, xrayStartRequest(t))
	c.UnlockControl()
	if err != nil {
		t.Fatalf("a Start whose caller went away failed: %v", err)
	}

	back := c.Backend()
	if back == nil || !back.Started() {
		t.Fatal("no running core after a Start whose caller went away")
	}
	// Connect, which starts the keep-alive tracker, is the only writer here.
	c.mu.RLock()
	connected := !c.lastRequest.IsZero()
	c.mu.RUnlock()
	if !connected {
		t.Fatal("the keep-alive session was not started")
	}
}

func TestSecondStartAttachesToAStartInProgress(t *testing.T) {
	c := newXrayController(t)
	first := xrayStartRequest(t)
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
	// Make sure the first Start really holds the core while the retry arrives.
	waitForStartInProgress(t, c)

	// The panel's retry arrives while the first Start is still running.
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
		t.Fatal("the retried Start restarted the core instead of attaching to it")
	}
	if !r2.back.Started() {
		t.Fatal("no running core after the retried Start")
	}
}

// Process shutdown calls Disconnect without LockControl; it must not wait for
// a start that ignores its caller's cancellation.
func TestDisconnectAbortsAStartInProgress(t *testing.T) {
	c := newFakeXrayController(t)
	data := xrayStartRequest(t)

	startErr := make(chan error, 1)
	go func() {
		c.LockControl()
		defer c.UnlockControl()
		startErr <- c.StartOrAttach(context.Background(), data)
	}()
	waitForStartInProgress(t, c)

	disconnected := make(chan struct{})
	go func() {
		c.Disconnect()
		close(disconnected)
	}()

	select {
	case err := <-startErr:
		if err == nil {
			t.Fatal("a start aborted by Disconnect reported success")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the start still runs 10s after Disconnect")
	}
	select {
	case <-disconnected:
	case <-time.After(10 * time.Second):
		t.Fatal("Disconnect still blocked 10s after the start ended")
	}
	if c.Backend() != nil {
		t.Fatal("an aborted start left a backend attached")
	}
}
