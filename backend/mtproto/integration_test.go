package mtproto

import (
	"context"
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
// marker user/empty-users) against the actual proxy.
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

// waitTelemtUser waits up to 5 s until telemt's running config has username
// (present) or lacks it. GET /v1/users lists the users in the config file;
// in_runtime tells whether the running config has them too.
func waitTelemtUser(ctx context.Context, t *testing.T, mt *MTProto, username string, present bool) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for {
		users, err := mt.apiClient.ListUsers(ctx)
		if err != nil {
			t.Fatalf("ListUsers: %v", err)
		}
		inRuntime := false
		for _, user := range users {
			if user.Username == username && user.InRuntime {
				inRuntime = true
			}
		}
		if inRuntime == present {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("telemt runtime has %s = %v, want %v", username, inRuntime, present)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestIntegration_LifecycleAndUsers(t *testing.T) {
	bin := telemtBinOrSkip(t)

	// telemt binds its API only after the Telegram DC check (up to about 60 s
	// with slow DCs), and New allows it telemtStartupTimeout.
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
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
	waitTelemtUser(ctx, t, mt, "alice", true)

	// add bob at runtime via the API path
	if err := mt.SyncUser(ctx, mtUser("bob", "mtproto", "ffeeddccbbaa00112233445566778899")); err != nil {
		t.Fatalf("SyncUser(bob): %v", err)
	}
	waitTelemtUser(ctx, t, mt, "bob", true)

	// remove alice (untag her)
	aliceGone := &common.User{Email: "alice", Inbounds: []string{}, Proxies: &common.Proxy{Mtproto: &common.Mtproto{Secret: testSecret}}}
	if err := mt.SyncUser(ctx, aliceGone); err != nil {
		t.Fatalf("SyncUser(remove alice): %v", err)
	}
	waitTelemtUser(ctx, t, mt, "alice", false)

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
	// stats from the OS process; both must work against a live telemt.
	if _, err := mt.GetUserOnlineIpListStats(ctx, "bob"); err != nil {
		t.Errorf("GetUserOnlineIpListStats: %v", err)
	}
	if _, err := mt.GetSysStats(ctx); err != nil {
		t.Errorf("GetSysStats: %v", err)
	}
}

func TestIntegration_EmptyUsersMarker(t *testing.T) {
	bin := telemtBinOrSkip(t)

	// telemt binds its API only after the Telegram DC check (up to about 60 s
	// with slow DCs), and New allows it telemtStartupTimeout.
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()

	// Zero real users: telemt rejects an empty [access.users], so the marker
	// user must keep it alive.
	mt, err := New(ctx, integrationConfig(t, bin), integrationMTConfig(t), nil)
	if err != nil {
		t.Fatalf("New with zero users (marker only): %v", err)
	}
	defer mt.Shutdown()

	if !mt.Started() {
		t.Fatal("backend not started with the marker user only")
	}
}
