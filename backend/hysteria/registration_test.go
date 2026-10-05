package hysteria

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pasarguard/node/backend"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
)

// TestHysteriaRegisteredInSeam is scope test 8: the package registers through
// the backend seam, so a new core is one package and one init() and the
// controller keeps no per-type dispatch.
//
// It asks the registry for HYSTERIA2; a core that forgot its init() fails here
// instead of at runtime on the first Start.
func TestHysteriaRegisteredInSeam(t *testing.T) {
	factory, ok := backend.For(common.BackendType_HYSTERIA2)
	if !ok {
		t.Fatal("HYSTERIA2 has no registered Factory; this package's init() did not run")
	}
	if factory == nil {
		t.Fatal("HYSTERIA2 registered a nil Factory")
	}
}

// TestHysteriaFactoryBuildsThroughSeam goes through the seam end to end rather
// than calling New directly, so a Factory that forgets to honour its Ports
// argument is caught here.
func TestHysteriaFactoryBuildsThroughSeam(t *testing.T) {
	exe := requirePinnedBinary(t)

	apiPort := freePort(t)
	serverPort := freeUDPPort(t)
	metricPort := freePort(t)

	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir)

	nodeCfg := config.NewTestConfig(dir, uuid.New())
	t.Setenv(hysteriaExecutablePathEnv, exe)

	factory, ok := backend.For(common.BackendType_HYSTERIA2)
	if !ok {
		t.Fatal("HYSTERIA2 has no registered Factory")
	}

	in := &common.Backend{
		Type:   common.BackendType_HYSTERIA2,
		Config: serverConfigJSON("127.0.0.1:"+strconv.Itoa(serverPort), certPath, keyPath, nil),
		Users: []*common.User{
			{Email: "seam-user", Proxies: &common.Proxy{Hysteria: &common.Hysteria{Auth: "seam-pw"}}},
		},
		CoreId: 7,
	}
	// ForCore is the controller's job; the Factory receives a scoped cfg and
	// must use it rather than the process-global (CONTRACT §1.3).
	coreCfg := nodeCfg.ForCore(in.GetCoreId())

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	b, err := factory(ctx, in, backend.Ports{ApiPort: apiPort, MetricPort: metricPort}, coreCfg)
	if err != nil {
		t.Fatalf("Factory: %v", err)
	}
	defer b.Shutdown()

	if !b.Started() {
		t.Fatal("core built through the seam reports not started")
	}
	if b.Version() != pinnedVersion {
		t.Errorf("Version() = %q, want %q", b.Version(), pinnedVersion)
	}

	// The config must have landed in core-7/, proving the Factory used the
	// scoped cfg it was handed (CONTRACT §1.5).
	written := filepath.Join(coreCfg.GeneratedConfigPath, "hysteria.json")
	if !strings.Contains(coreCfg.GeneratedConfigPath, "core-7") {
		t.Errorf("config path %q is not the per-core directory", coreCfg.GeneratedConfigPath)
	}
	if _, err := os.Stat(written); err != nil {
		t.Errorf("no config written at %s: %v", written, err)
	}
}

// TestHysteriaTrafficStatsSurvivesOutboundsPoll is scope test 7's trap: a
// UsersStat poll followed by an Outbounds poll must not lose the user counters.
//
// sing-box had this bug (backend/singbox/stats.go:77-84): pending rows are
// per-user, the node-stats job's Outbounds poll consumes them, and the usage
// job 15s later bills the user nothing. A hysteria2 core re-applies the rule.
func TestHysteriaTrafficStatsSurvivesOutboundsPoll(t *testing.T) {
	exe := requirePinnedBinary(t)

	apiPort := freePort(t)
	serverPort := freeUDPPort(t)
	targetPort := startHTTPOrigin(t, 4096)

	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir)

	const email = "pending-user"

	h := newTestBackend(t, exe, serverConfigJSON("127.0.0.1:"+strconv.Itoa(serverPort), certPath, keyPath, nil), []*common.User{
		{Email: email, Proxies: &common.Proxy{Hysteria: &common.Hysteria{Auth: "pw"}}},
	}, apiPort)

	clientPort := freePort(t)
	clientCfg := writeClientConfig(t, dir, "client.json", clientConfigJSON(
		"127.0.0.1:"+strconv.Itoa(serverPort), email+":pw", clientPort, nil))
	hysteriaClient(t, exe, clientCfg, clientPort, true)

	if got := httpGetViaProxy(clientPort, targetPort, 20*time.Second); got == 0 {
		t.Fatalf("client moved no bytes")
	}

	ctx := context.Background()

	// A user change drains the counters into pendingStats, exactly as the core
	// is about to lose them with its memory.
	if err := h.UpdateUsers(ctx, []*common.User{
		{Email: email, Proxies: &common.Proxy{Hysteria: &common.Hysteria{Auth: "pw"}}},
	}); err != nil {
		t.Fatalf("UpdateUsers: %v", err)
	}

	// The node-stats job ticks first and polls Outbounds with reset=true.
	if _, err := h.GetStats(ctx, &common.StatRequest{Type: common.StatType_Outbounds, Reset_: true}); err != nil {
		t.Fatalf("GetStats(Outbounds): %v", err)
	}

	// The usage job must still see the traffic.
	deadline := time.Now().Add(15 * time.Second)
	var total int64
	for time.Now().Before(deadline) {
		stats, err := h.GetStats(ctx, &common.StatRequest{Type: common.StatType_UsersStat, Reset_: true})
		if err != nil {
			t.Fatalf("GetStats(UsersStat): %v", err)
		}
		total = 0
		for _, s := range stats.GetStats() {
			if s.GetName() == email {
				total += s.GetValue()
			}
		}
		if total > 0 {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if total == 0 {
		t.Fatalf("user %q was billed zero after an Outbounds poll consumed the pending rows; "+
			"only a user-facing read may consume pendingStats", email)
	}
	t.Logf("pending traffic survived an Outbounds poll: %d bytes", total)

	// And consuming it twice must not double-bill: the second user poll starts
	// from whatever the core has counted since.
	second, err := h.GetStats(ctx, &common.StatRequest{Type: common.StatType_UsersStat, Reset_: true})
	if err != nil {
		t.Fatalf("GetStats(UsersStat) again: %v", err)
	}
	var secondTotal int64
	for _, s := range second.GetStats() {
		if s.GetName() == email {
			secondTotal += s.GetValue()
		}
	}
	if secondTotal != 0 {
		t.Errorf("a second user poll re-reported %d bytes; the first poll must have consumed them", secondTotal)
	}
}

// TestHysteriaUserPassInjection is the config half of the auth story: the panel's
// users land in auth.userpass keyed by email, and a user the panel assigned to
// another inbound does not.
func TestHysteriaUserPassInjection(t *testing.T) {
	cfg, err := NewConfig(`{"auth": {"type": "userpass", "userpass": {}}}`, nil)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}

	cfg.syncUsers([]*common.User{
		{Email: "alice", Proxies: &common.Proxy{Hysteria: &common.Hysteria{Auth: "alice-pw"}}},
		{Email: "bob", Proxies: &common.Proxy{Hysteria: &common.Hysteria{Auth: "bob-pw"}}},
		// No hysteria credential: nothing to inject.
		{Email: "carol"},
	})

	got := cfg.userNames()
	want := []string{"alice", "bob"}
	if len(got) != len(want) {
		t.Fatalf("injected %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("injected %v, want %v", got, want)
		}
	}
}

// TestHysteriaPasswordAuthIsNotInjected documents why syncUsers leaves
// `password` mode alone: upstream returns the fixed id "user" for every client
// (extras/auth/password.go:21), so injecting per-user passwords there would be
// a no-op that reads like it worked.
func TestHysteriaPasswordAuthIsNotInjected(t *testing.T) {
	cfg, err := NewConfig(`{"auth": {"type": "password", "password": "shared"}}`, nil)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if got := cfg.AuthType(); got != "password" {
		t.Fatalf("AuthType() = %q", got)
	}
	if got := cfg.Password(); got != "shared" {
		t.Fatalf("Password() = %q", got)
	}

	cfg.syncUsers([]*common.User{
		{Email: "alice", Proxies: &common.Proxy{Hysteria: &common.Hysteria{Auth: "alice-pw"}}},
	})
	if names := cfg.userNames(); len(names) != 0 {
		t.Errorf("password auth gained userpass entries %v; it has one id for every client", names)
	}
}

// TestHysteriaExcludeInboundsSkipsUser proves exclude_inbound_tags reaches the
// backend: a user assigned only to an excluded inbound must not authenticate.
func TestHysteriaExcludeInboundsSkipsUser(t *testing.T) {
	cfg, err := NewConfig(`{"auth": {"type": "userpass", "userpass": {}}}`, []string{"excluded-in"})
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}

	cfg.syncUsers([]*common.User{
		{Email: "included", Proxies: &common.Proxy{Hysteria: &common.Hysteria{Auth: "pw"}}, Inbounds: []string{"other-in"}},
		{Email: "excluded", Proxies: &common.Proxy{Hysteria: &common.Hysteria{Auth: "pw"}}, Inbounds: []string{"excluded-in"}},
	})

	got := cfg.userNames()
	if len(got) != 1 || got[0] != "included" {
		t.Errorf("injected %v, want [included]", got)
	}
}

// TestHysteriaTrafficStatsSecretIsGenerated proves the node installs its own
// secret rather than trusting one in a stored config: an endpoint that reads and
// zeroes every user's counters must not be reachable with a known key.
func TestHysteriaTrafficStatsSecretIsGenerated(t *testing.T) {
	exe := requirePinnedBinary(t)

	apiPort := freePort(t)
	serverPort := freeUDPPort(t)

	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir)

	// A stored config that already carries a secret the operator knows.
	stolen := "secret-from-the-database"
	serverCfg := serverConfigJSON("127.0.0.1:"+strconv.Itoa(serverPort), certPath, keyPath, map[string]any{
		"trafficStats": map[string]any{"listen": "127.0.0.1:1", "secret": stolen},
	})

	h := newTestBackend(t, exe, serverCfg, []*common.User{
		{Email: "u", Proxies: &common.Proxy{Hysteria: &common.Hysteria{Auth: "pw"}}},
	}, apiPort)

	// The node's own client works, so it knows the real secret.
	if _, err := h.GetUserOnlineStats(context.Background(), "u"); err != nil {
		t.Fatalf("the node cannot read its own stats api: %v", err)
	}

	// The stored secret is refused.
	if code, err := rawStatsStatus(apiPort, stolen); err != nil {
		t.Fatalf("raw probe: %v", err)
	} else if code != http.StatusUnauthorized {
		t.Errorf("a request with the stored config secret got status %d, want 401; "+
			"EnableTrafficStats must replace it", code)
	}

	// And it is bound to loopback, never a routable address.
	rendered, err := h.getConfig().ToBytes()
	if err != nil {
		t.Fatalf("ToBytes: %v", err)
	}
	if !containsAll(string(rendered), "127.0.0.1:"+strconv.Itoa(apiPort)) {
		t.Errorf("traffic stats listener is not on loopback:\n%s", rendered)
	}
	if containsAll(string(rendered), stolen) {
		t.Errorf("the operator's stored secret survived into the running config:\n%s", rendered)
	}
}
