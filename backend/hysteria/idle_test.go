package hysteria

// Zero-user idle behaviour, driven against the pinned hysteria binary
// (HYSTERIA_TEST_BINARY). The round-2 E2E found that starting a userpass core
// with no users is fatal upstream ("auth.userpass: empty auth userpass") and
// the panel then re-applied Start every health tick — a crash-loop. The
// contract now is:
//
//   - New() with zero eligible users: no child spawned, backend answers RPCs,
//     spawn count stays 0 however long it sits;
//   - SyncUsers with a real roster: the core starts (spawn +1) and serves;
//   - SyncUsers with an emptied roster: the core stops and idles (no respawn);
//   - rapid flapping 1->0->1->0: exactly one spawn per wake, no crash-loop.
//
// Restart counts are asserted on Core.SpawnCount, per-core logs on the
// core-1.log the node's logger binds.

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
	"github.com/google/uuid"
)

func idleUser(email, auth string) *common.User {
	return &common.User{
		Email:    email,
		Proxies:  &common.Proxy{Hysteria: &common.Hysteria{Auth: auth}},
		Inbounds: []string{},
	}
}

func newIdleBackend(t *testing.T, exe, serverConfig string, users []*common.User, apiPort int) *Hysteria {
	t.Helper()
	cfg, err := NewConfig(serverConfig, nil)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	nodeCfg := config.NewTestConfig(t.TempDir(), uuid.New())
	t.Setenv(hysteriaExecutablePathEnv, exe)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	h, err := New(ctx, cfg, users, apiPort, nodeCfg)
	if err != nil {
		t.Fatalf("New backend: %v", err)
	}
	t.Cleanup(h.Shutdown)
	return h
}

// TestHysteriaZeroUsersIdlesWithoutSpawning is the core claim: a userpass core
// with no eligible users must not spawn the child, must answer the RPCs the
// panel's health and usage jobs call, and must stay that way (no crash-loop).
func TestHysteriaZeroUsersIdlesWithoutSpawning(t *testing.T) {
	exe := requirePinnedBinary(t)

	apiPort := freePort(t)
	serverPort := freeUDPPort(t)
	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir)

	h := newIdleBackend(t, exe, serverConfigJSON("127.0.0.1:"+strconv.Itoa(serverPort), certPath, keyPath, nil), nil, apiPort)

	if !h.Started() {
		t.Fatal("idle backend must report Started()=true so the panel health check stays green")
	}
	if !h.isIdle() {
		t.Fatal("backend must be marked idle")
	}
	if got := h.core.SpawnCount(); got != 0 {
		t.Fatalf("spawn count = %d, want 0 (no child for an empty roster)", got)
	}

	// The RPCs the panel's jobs actually call must answer, not error.
	ctx := context.Background()
	stats, err := h.GetSysStats(ctx)
	if err != nil {
		t.Fatalf("GetSysStats on idle core: %v", err)
	}
	if stats.GetUptime() != 0 {
		t.Errorf("idle uptime = %d, want 0", stats.GetUptime())
	}
	if _, err := h.GetStats(ctx, &common.StatRequest{Type: common.StatType_UsersStat, Reset_: true}); err != nil {
		t.Errorf("GetStats on idle core: %v", err)
	}
	if _, err := h.GetUserOnlineStats(ctx, "anyone"); err != nil {
		t.Errorf("GetUserOnlineStats on idle core: %v", err)
	}
	if err := h.Restart(); err != nil {
		t.Errorf("Restart on idle core: %v", err)
	}

	// Sit longer than a health tick: still zero spawns. This is the
	// anti-crash-loop assertion — the old behaviour FATAL-spawned every retry.
	time.Sleep(3 * time.Second)
	if got := h.core.SpawnCount(); got != 0 {
		t.Fatalf("spawn count after idling = %d, want 0", got)
	}

	// SyncUsers([]) while idle is a no-op, not a start attempt.
	if err := h.SyncUsers(ctx, nil); err != nil {
		t.Fatalf("SyncUsers(nil) on idle core: %v", err)
	}
	if got := h.core.SpawnCount(); got != 0 {
		t.Fatalf("spawn count after empty sync = %d, want 0", got)
	}

	// Per-core log: the idle core must not have written a FATAL into its own
	// log file — that line is the crash-loop signature the old behaviour left.
	// hysteria writes its per-core log next to the generated config dir; the
	// exact file is the logger's business, the assertion is "no FATAL anywhere
	// in the core's log directory".
	// Scan the core's config dir and its parent: the per-core log is a sibling
	// of the generated-config dir, and the exact layout is the logger's
	// business — the assertion is "no FATAL anywhere near this core".
	for _, logDir := range []string{h.core.configDir, filepath.Dir(h.core.configDir)} {
		entries, err := os.ReadDir(logDir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".log") {
				continue
			}
			buf, err := os.ReadFile(filepath.Join(logDir, e.Name()))
			if err != nil {
				t.Fatalf("read %s: %v", e.Name(), err)
			}
			if bytes.Contains(buf, []byte("FATAL")) {
				t.Fatalf("per-core log %s contains FATAL while idle", filepath.Join(logDir, e.Name()))
			}
		}
	}
}

// TestHysteriaIdleWakesOnFirstUserAndSleepsOnLast: 0 -> 1 -> 0 -> 1 with a real
// child each wake and a clean stop when the roster empties.
func TestHysteriaIdleWakesOnFirstUserAndSleepsOnLast(t *testing.T) {
	exe := requirePinnedBinary(t)

	apiPort := freePort(t)
	serverPort := freeUDPPort(t)
	targetPort := startHTTPOrigin(t, 4096)
	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir)

	h := newIdleBackend(t, exe, serverConfigJSON("127.0.0.1:"+strconv.Itoa(serverPort), certPath, keyPath, nil), nil, apiPort)
	ctx := context.Background()

	const email = "77"
	const password = "idle-wake-secret"
	user := idleUser(email, password)

	// 0 -> 1: wake.
	if err := h.SyncUsers(ctx, []*common.User{user}); err != nil {
		t.Fatalf("SyncUsers(1 user) from idle: %v", err)
	}
	if h.isIdle() {
		t.Fatal("core must leave idle after the first user arrives")
	}
	if !h.core.Started() {
		t.Fatal("child must be running after the wake")
	}
	if got := h.core.SpawnCount(); got != 1 {
		t.Fatalf("spawn count after wake = %d, want 1", got)
	}

	// Real traffic through the woken core, with the auth a stock client sends.
	clientPort := freePort(t)
	clientCfg := writeClientConfig(t, dir, "wake-client.json", clientConfigJSON(
		"127.0.0.1:"+strconv.Itoa(serverPort), email+":"+password, clientPort, nil))
	clientLog := hysteriaClient(t, exe, clientCfg, clientPort, true)
	if got := httpGetViaProxy(clientPort, targetPort, 20*time.Second); got == 0 {
		t.Fatalf("no traffic through the woken core\nclient log:\n%s", tailFile(t, clientLog))
	}

	// 1 -> 0: sleep, not crash.
	if err := h.SyncUsers(ctx, nil); err != nil {
		t.Fatalf("SyncUsers(nil) to empty the roster: %v", err)
	}
	if !h.isIdle() {
		t.Fatal("core must return to idle when the last user leaves")
	}
	if h.core.Started() {
		t.Fatal("child must be stopped after the roster emptied")
	}
	if got := h.core.SpawnCount(); got != 1 {
		t.Fatalf("spawn count after sleep = %d, want 1 (stop is not a spawn)", got)
	}

	// 0 -> 1 again: second wake, second spawn.
	if err := h.SyncUsers(ctx, []*common.User{user}); err != nil {
		t.Fatalf("SyncUsers(1 user) on re-wake: %v", err)
	}
	if h.isIdle() || !h.core.Started() {
		t.Fatal("core must be running after the re-wake")
	}
	if got := h.core.SpawnCount(); got != 2 {
		t.Fatalf("spawn count after re-wake = %d, want 2", got)
	}
}

// TestHysteriaRapidFlappingSpawnsOncePerWake: alternating rosters must produce
// exactly one spawn per wake and zero errors — no hidden retry loop.
func TestHysteriaRapidFlappingSpawnsOncePerWake(t *testing.T) {
	exe := requirePinnedBinary(t)

	apiPort := freePort(t)
	serverPort := freeUDPPort(t)
	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir)

	h := newIdleBackend(t, exe, serverConfigJSON("127.0.0.1:"+strconv.Itoa(serverPort), certPath, keyPath, nil), nil, apiPort)
	ctx := context.Background()
	user := idleUser("55", "flap-secret")

	const cycles = 5
	for i := 0; i < cycles; i++ {
		if err := h.SyncUsers(ctx, []*common.User{user}); err != nil {
			t.Fatalf("cycle %d wake: %v", i, err)
		}
		if err := h.SyncUsers(ctx, nil); err != nil {
			t.Fatalf("cycle %d sleep: %v", i, err)
		}
	}
	if !h.isIdle() {
		t.Fatal("core must be idle after the last empty sync")
	}
	if got := h.core.SpawnCount(); got != cycles {
		t.Fatalf("spawn count after %d flap cycles = %d, want exactly %d (one per wake)", cycles, got, cycles)
	}
}
