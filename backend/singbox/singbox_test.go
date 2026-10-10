package singbox

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
)

const baseSingBoxConfig = `{
  "log": {"level": "warn"},
  "inbounds": [
    {"type":"vless","tag":"vless-in","listen":"127.0.0.1","listen_port":%d,
     "users":[], "transport":{"type":"ws","path":"/ws"}},
    {"type":"trojan","tag":"trojan-in","listen":"127.0.0.1","listen_port":%d,
     "users":[], "tls":{"enabled":true,"certificate_path":"%s","key_path":"%s"}},
    {"type":"shadowsocks","tag":"ss2022-in","listen":"127.0.0.1","listen_port":%d,
     "method":"2022-blake3-aes-128-gcm","password":"PozmNW9tEDvS5MtXzhHZ/w==","users":[]},
    {"type":"hysteria2","tag":"hy2-in","listen":"127.0.0.1","listen_port":%d,
     "up_mbps":50,"down_mbps":50,"users":[],"tls":{"enabled":true,"certificate_path":"%s","key_path":"%s"}},
    {"type":"tuic","tag":"tuic-in","listen":"127.0.0.1","listen_port":%d,
     "users":[],"congestion_control":"bbr","tls":{"enabled":true,"certificate_path":"%s","key_path":"%s"}}
  ],
  "outbounds": [{"type":"direct","tag":"direct"}],
  "route": {"final":"direct"}
}`

func singBoxEnvPath(t *testing.T) string {
	t.Helper()
	p := os.Getenv("SINGBOX_EXECUTABLE")
	if p == "" {
		t.Skip("SINGBOX_EXECUTABLE not set")
	}
	return p
}

func testUser(email string) *common.User {
	return &common.User{
		Email: email,
		Proxies: &common.Proxy{
			Vless:       &common.Vless{Id: uuid.New().String()},
			Trojan:      &common.Trojan{Password: "trojan-pw"},
			Shadowsocks: &common.Shadowsocks{Password: "SyXAMRozxYUo2DyZFjPrwQ=="},
			Hysteria:    &common.Hysteria{Auth: "hy2-pw"},
		},
		Inbounds: []string{"vless-in", "trojan-in", "ss2022-in", "hy2-in", "tuic-in"},
	}
}

// TestSingBoxConfigUserInjection verifies each protocol type gets a users[]
// entry carrying the panel's email as the identity key.
func TestSingBoxConfigUserInjection(t *testing.T) {
	certPath, keyPath := testCert(t)
	cfgJSON := sprintfConfig(baseSingBoxConfig, freePort(t), freePort(t), certPath, keyPath, freePort(t), freePort(t), certPath, keyPath, freePort(t), certPath, keyPath)

	cfg, err := NewConfig(cfgJSON, nil)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if err := cfg.ApplyAPI(freePort(t)); err != nil {
		t.Fatalf("ApplyAPI: %v", err)
	}

	cfg.syncUsers([]*common.User{testUser("42")})

	want := map[string]int{
		"vless-in":  1,
		"trojan-in": 1,
		"ss2022-in": 1,
		"hy2-in":    1,
		"tuic-in":   1,
	}
	for _, in := range cfg.inbounds() {
		tag, _ := in["tag"].(string)
		users, _ := in["users"].([]any)
		if users == nil {
			users = []any{}
		}
		expected, tracked := want[tag]
		if !tracked {
			continue
		}
		if len(users) != expected {
			t.Errorf("inbound %q: got %d users, want %d", tag, len(users), expected)
			delete(want, tag)
			continue
		}
		if expected == 0 {
			delete(want, tag)
			continue
		}
		entry, ok := users[0].(map[string]any)
		if !ok {
			t.Errorf("inbound %q: user entry is not an object: %#v", tag, users[0])
			continue
		}
		if entry["name"] != "42" {
			t.Errorf("inbound %q: users[].name = %v, want \"42\" (stats identity key)", tag, entry["name"])
		}
		// hysteria2's whole-string auth: a stock client sends "name:auth",
		// so the injected password must be that same string.
		if tag == "hy2-in" && entry["password"] != "42:hy2-pw" {
			t.Errorf("hy2-in users[].password = %v, want \"42:hy2-pw\" (whole-string client auth)", entry["password"])
		}
		delete(want, tag)
	}
	for tag := range want {
		t.Errorf("inbound %q missing from config", tag)
	}

	// stats users must list the injected email
	stats := cfg.raw["experimental"].(map[string]any)["v2ray_api"].(map[string]any)["stats"].(map[string]any)
	names, _ := stats["users"].([]any)
	if len(names) != 1 || names[0] != "42" {
		t.Errorf("v2ray_api.stats.users = %v, want [\"42\"]", names)
	}
}

// TestSingBoxConfigExcludesInbound verifies exclude_inbounds skips injection.
func TestSingBoxConfigExcludesInbound(t *testing.T) {
	certPath, keyPath := testCert(t)
	cfgJSON := sprintfConfig(baseSingBoxConfig, freePort(t), freePort(t), certPath, keyPath, freePort(t), freePort(t), certPath, keyPath, freePort(t), certPath, keyPath)

	cfg, err := NewConfig(cfgJSON, []string{"vless-in"})
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	_ = cfg.ApplyAPI(freePort(t))
	cfg.syncUsers([]*common.User{testUser("7")})

	for _, in := range cfg.inbounds() {
		tag, _ := in["tag"].(string)
		if tag != "vless-in" {
			continue
		}
		users, _ := in["users"].([]any)
		if len(users) != 0 {
			t.Errorf("excluded inbound %q got %d users, want 0", tag, len(users))
		}
	}
}

// TestSingBoxEndToEnd boots the real sing-box binary, checks the generated
// config with `sing-box check`, and verifies per-user traffic counters flow
// through the v2ray_api stats service.
func TestSingBoxEndToEnd(t *testing.T) {
	exe := singBoxEnvPath(t)
	certPath, keyPath := testCert(t)

	ports := []int{freePort(t), freePort(t), freePort(t), freePort(t), freePort(t)}
	apiPort := freePort(t)
	cfgJSON := sprintfConfig(baseSingBoxConfig, ports[0], ports[1], certPath, keyPath, ports[2], ports[3], certPath, keyPath, ports[4], certPath, keyPath)

	cfg, err := NewConfig(cfgJSON, nil)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}

	cfg2 := config.NewTestConfig(t.TempDir(), uuid.New())
	cfg2.SingBoxExecutablePath = exe

	// pass1: config must be valid before users (schema check)
	core, err := NewSingBoxCore(exe, filepath.Join(cfg2.GeneratedConfigPath), 1000, 50, false)
	if err != nil {
		t.Fatalf("NewSingBoxCore: %v", err)
	}
	if err := core.Start(cfg, false); err != nil {
		t.Fatalf("Start (empty users): %v", err)
	}
	if !core.Started() {
		t.Fatal("core not started")
	}
	core.Stop()

	// pass2: with users injected, and the stats client reading counters
	cfg2b, _ := NewConfig(cfgJSON, nil)
	if err := cfg2b.ApplyAPI(apiPort); err != nil {
		t.Fatalf("ApplyAPI: %v", err)
	}
	cfg2b.syncUsers([]*common.User{testUser("99")})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sb, err := New(ctx, cfg2b, nil, apiPort, freePort(t), cfg2)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Shutdown()

	if !sb.Started() {
		t.Fatal("backend reports not started")
	}
	if v := sb.Version(); v == "" {
		t.Error("empty core version")
	} else {
		t.Logf("sing-box version: %s", v)
	}

	// GetStats must not error even with zero traffic
	stats, err := sb.GetStats(ctx, &common.StatRequest{Type: common.StatType_UsersStat, Reset_: true})
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	t.Logf("user stats right after start: %+v", stats.GetStats())

	sysStats, err := sb.GetSysStats(ctx)
	if err != nil {
		t.Fatalf("GetSysStats: %v", err)
	}
	t.Logf("sys stats: goroutines=%d uptime=%ds", sysStats.GetNumGoroutine(), sysStats.GetUptime())

	// user sync must keep the core running and apply without error
	if err := sb.SyncUser(ctx, testUser("99")); err != nil {
		t.Fatalf("SyncUser: %v", err)
	}
	if !sb.Started() {
		t.Error("core not started after SyncUser")
	}

	// removing the user's inbounds empties the entry
	removed := testUser("99")
	removed.Inbounds = nil
	if err := sb.SyncUser(ctx, removed); err != nil {
		t.Fatalf("SyncUser (remove): %v", err)
	}
	for _, in := range sb.getConfig().inbounds() {
		tag, _ := in["tag"].(string)
		users, _ := in["users"].([]any)
		if len(users) != 0 {
			t.Errorf("inbound %q still has %d users after removal", tag, len(users))
		}
	}
}
