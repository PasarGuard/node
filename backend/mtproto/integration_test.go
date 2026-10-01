package mtproto

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
	"github.com/pasarguard/node/pkg/netutil"
)

// Gated integration test: runs only when MTPROTO_TELEMT_BIN points at a real
// telemt binary. Exercises the full lifecycle (start, health, users, stats,
// sentinel/empty-users) against the actual proxy.
//
//	MTPROTO_TELEMT_BIN=/path/to/telemt go test ./backend/mtproto/ -run Integration -v
func telemtBinOrSkip(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("MTPROTO_TELEMT_BIN")
	if bin == "" {
		t.Skip("set MTPROTO_TELEMT_BIN to a telemt binary to run telemt integration tests")
	}
	return bin
}

func integrationConfig(t *testing.T, bin string) *config.Config {
	return &config.Config{
		TelemtExecutablePath: bin,
		GeneratedConfigPath:  t.TempDir(),
		LogBufferSize:        1000,
	}
}

func integrationMTConfig(t *testing.T) *Config {
	port := netutil.FindFreePort()
	raw := fmt.Sprintf(`{
		"inbound_tag": "mtproto",
		"general": {"use_middle_proxy": false, "modes": {"classic": true, "secure": true, "tls": false}},
		"server": {"port": %d, "listeners": [{"ip": "127.0.0.1"}]}
	}`, port)
	cfg, err := NewConfig(raw)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	return cfg
}

func TestIntegration_LifecycleAndUsers(t *testing.T) {
	bin := telemtBinOrSkip(t)

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	users := []*common.User{mtUser("alice", "mtproto", testSecret)}
	mt, err := New(ctx, integrationConfig(t, bin), integrationMTConfig(t), users)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer mt.Shutdown()

	if !mt.Started() {
		t.Fatal("backend not started")
	}
	if v := mt.Version(); v == "" {
		t.Error("empty telemt version")
	} else {
		t.Logf("telemt version: %s", v)
	}

	// alice was rendered into the config; she must be present in telemt's runtime.
	if _, err := mt.apiClient.GetUser(ctx, "alice"); err != nil {
		t.Fatalf("alice not in telemt runtime: %v", err)
	}

	// add bob at runtime via the API path
	if err := mt.SyncUser(ctx, mtUser("bob", "mtproto", "ffeeddccbbaa00112233445566778899")); err != nil {
		t.Fatalf("SyncUser(bob): %v", err)
	}
	if _, err := mt.apiClient.GetUser(ctx, "bob"); err != nil {
		t.Fatalf("bob not added: %v", err)
	}

	// remove alice (untag her)
	aliceGone := &common.User{Email: "alice", Inbounds: []string{}, Proxies: &common.Proxy{Mtproto: &common.Mtproto{Secret: testSecret}}}
	if err := mt.SyncUser(ctx, aliceGone); err != nil {
		t.Fatalf("SyncUser(remove alice): %v", err)
	}
	if _, err := mt.apiClient.GetUser(ctx, "alice"); err == nil {
		t.Fatal("alice should have been removed")
	} else {
		var apiErr *apiStatusError
		if !errors.As(err, &apiErr) || !apiErr.NotFound() {
			t.Fatalf("expected alice lookup to return not found, got %v", err)
		}
	}

	// Traffic + online-count stats come from telemt's Prometheus endpoint, which
	// only binds once the data plane is up (needs Telegram connectivity). A miss
	// must still succeed with empty/zero results so the panel poll does not fail.
	if stats, err := mt.GetStats(ctx, &common.StatRequest{Type: common.StatType_UsersStat}); err != nil {
		t.Errorf("GetStats: %v", err)
	} else if stats == nil {
		t.Error("GetStats returned nil")
	}
	if online, err := mt.GetUserOnlineStats(ctx, "bob"); err != nil {
		t.Errorf("GetUserOnlineStats: %v", err)
	} else if online == nil || online.GetName() != "bob" {
		t.Errorf("GetUserOnlineStats = %+v", online)
	}

	// These do not depend on metrics: IP list comes from the control API, sys
	// stats from the OS process — both must work against a live telemt.
	if _, err := mt.GetUserOnlineIpListStats(ctx, "bob"); err != nil {
		t.Errorf("GetUserOnlineIpListStats: %v", err)
	}
	if _, err := mt.GetSysStats(ctx); err != nil {
		t.Errorf("GetSysStats: %v", err)
	}
}

func TestIntegration_EmptyUsersSentinel(t *testing.T) {
	bin := telemtBinOrSkip(t)

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	// Zero real users: telemt rejects an empty [access.users], so the sentinel
	// user must keep it alive.
	mt, err := New(ctx, integrationConfig(t, bin), integrationMTConfig(t), nil)
	if err != nil {
		t.Fatalf("New with zero users (sentinel path): %v", err)
	}
	defer mt.Shutdown()

	if !mt.Started() {
		t.Fatal("backend not started with sentinel user")
	}
}
