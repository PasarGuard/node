package singbox

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
)

// TestSS2022MultiUserStats proves that a single shadowsocks 2022 inbound with
// TWO users authenticates both clients and attributes traffic per user:
//
//   - server keeps its PSK at the inbound top level
//   - each users[] entry carries the user's own EIH key
//   - clients connect with password "serverKey:userKey"
//     (sing-shadowsocks shadowaead_2022/protocol.go NewWithPassword splits
//     on ':')
//
// Requires a sing-box built with -tags with_v2ray_api.
func TestSS2022MultiUserStats(t *testing.T) {
	exe := singBoxEnvPath(t)
	dir := t.TempDir()

	const (
		serverPSK = "8JCsPssfgS8tiRwiMlhARg=="
		userKey1  = "PCD2Z4o12bKUoFa3cC97Hw=="
		userKey2  = "SyXAMRozxYUo2DyZFjPrwQ=="
	)

	p := freePorts(t, 7)
	serverPort, apiPort, metricPort, targetPort := p[0], p[1], p[2], p[3]
	socks1, socks2 := p[4], p[5]

	startOrigin(t, targetPort)

	serverCfg := sprintfConfig(`{
  "log": {"level": "error"},
  "inbounds": [
    {"type":"shadowsocks","tag":"ss-in","listen":"127.0.0.1","listen_port":%d,
     "method":"2022-blake3-aes-128-gcm","password":%q,"network":["tcp","udp"],"users":[]}
  ],
  "outbounds": [{"type":"direct","tag":"direct"}],
  "route": {"final":"direct"}
}`, serverPort, serverPSK)

	cfg, err := NewConfig(serverCfg, nil)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if err := cfg.ApplyAPI(apiPort); err != nil {
		t.Fatalf("ApplyAPI: %v", err)
	}

	cfg.syncUsers([]*common.User{
		{Email: "u1", Proxies: &common.Proxy{Shadowsocks: &common.Shadowsocks{Password: userKey1}}, Inbounds: []string{"ss-in"}},
		{Email: "u2", Proxies: &common.Proxy{Shadowsocks: &common.Shadowsocks{Password: userKey2}}, Inbounds: []string{"ss-in"}},
	})

	// both users must be injected into the single inbound
	for _, in := range cfg.inbounds() {
		users, _ := in["users"].([]any)
		if len(users) != 2 {
			t.Fatalf("ss-in users = %d, want 2 (%#v)", len(users), in["users"])
		}
	}

	nodeCfg := config.NewTestConfig(dir, uuid.New())
	nodeCfg.SingBoxExecutablePath = exe

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	sb, err := New(ctx, cfg, nil, apiPort, metricPort, nodeCfg)
	if err != nil {
		t.Fatalf("New backend: %v", err)
	}
	defer sb.Shutdown()
	go func() {
		for range sb.Logs() {
		}
	}()

	// two clients, one per user, both via "serverKey:userKey"
	for i, uc := range []struct {
		userKey string
		socks   int
	}{{userKey1, socks1}, {userKey2, socks2}} {
		clientCfg := map[string]any{
			"log":      map[string]any{"level": "error"},
			"inbounds": []any{map[string]any{"type": "mixed", "tag": "socks", "listen": "127.0.0.1", "listen_port": uc.socks}},
			"outbounds": []any{map[string]any{
				"type": "shadowsocks", "tag": "proxy", "server": "127.0.0.1", "server_port": serverPort,
				"method": "2022-blake3-aes-128-gcm",
				// the multi-user form: server PSK + this user's EIH key
				"password": serverPSK + ":" + uc.userKey,
			}, map[string]any{"type": "direct", "tag": "direct"}},
			"route": map[string]any{"final": "proxy"},
		}
		buf, _ := json.Marshal(clientCfg)
		cfgPath := filepath.Join(dir, "client.json")
		if err := os.WriteFile(cfgPath, buf, 0o644); err != nil {
			t.Fatalf("write client %d: %v", i, err)
		}
		if out, err := exec.Command(exe, "check", "-c", cfgPath).CombinedOutput(); err != nil {
			t.Fatalf("client %d config invalid: %v\n%s", i, err, out)
		}
		logPath := filepath.Join(dir, "client.log")
		logFile, err := os.Create(logPath)
		if err != nil {
			t.Fatalf("client log: %v", err)
		}
		client := exec.Command(exe, "run", "-c", cfgPath)
		client.Stdout = logFile
		client.Stderr = logFile
		if err := client.Start(); err != nil {
			t.Fatalf("start client %d: %v", i, err)
		}
		t.Cleanup(func() {
			_ = client.Process.Kill()
			_, _ = client.Process.Wait()
			_ = logFile.Close()
		})
		if err := waitForPort(uc.socks, 15*time.Second); err != nil {
			t.Fatalf("client %d socks: %v (log: %s)", i, err, readTail(logPath))
		}
	}

	// drive traffic through BOTH clients
	for _, port := range []int{socks1, socks2} {
		socksFetch(t, port, targetPort, 2048)
	}

	// per-user counters must be distinct and non-zero
	deadline := time.Now().Add(20 * time.Second)
	totals := map[string]int64{"u1": 0, "u2": 0}
	for time.Now().Before(deadline) {
		for user := range totals {
			stats, err := sb.GetStats(ctx, &common.StatRequest{Type: common.StatType_UserStat, Name: user, Reset_: false})
			if err != nil {
				t.Fatalf("GetStats(%s): %v", user, err)
			}
			for _, st := range stats.GetStats() {
				if st.GetName() == user && st.GetLink() == "traffic" {
					totals[user] += st.GetValue()
				}
			}
		}
		if totals["u1"] > 0 && totals["u2"] > 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if totals["u1"] == 0 || totals["u2"] == 0 {
		t.Fatalf("per-user SS-2022 counters missing: u1=%d u2=%d", totals["u1"], totals["u2"])
	}
	t.Logf("SS-2022 per-user counters: u1=%d u2=%d", totals["u1"], totals["u2"])
}

// TestRealityTLSDefaultsFilled proves the node fills server_name/alpn for a
// Reality inbound that omits them. Found by passing live traffic through a
// panel-managed Reality core: without these, clients fail with
// "reality verification failed" even though `sing-box check` passes.
func TestRealityTLSDefaultsFilled(t *testing.T) {
	cfg, err := NewConfig(`{
      "inbounds": [
        {"type":"vless","tag":"r","listen":"0.0.0.0","listen_port":443,"users":[],
         "tls":{"enabled":true,
           "reality":{"enabled":true,
             "handshake":{"server":"www.microsoft.com","server_port":443},
             "private_key":"aDDe6dyBwu2nRFwnalSvl2JcGOU_ajXw1ya-LXoJdEw",
             "short_id":["0123456789abcdef"]}}}
      ],
      "outbounds": [{"type":"direct","tag":"direct"}]
    }`, nil)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	tls := cfg.inbounds()[0]["tls"].(map[string]any)
	if tls["server_name"] != "www.microsoft.com" {
		t.Errorf("server_name = %v, want www.microsoft.com", tls["server_name"])
	}
	alpn, _ := tls["alpn"].([]any)
	if len(alpn) != 2 {
		t.Errorf("alpn = %v, want [h2 http/1.1]", tls["alpn"])
	}
}

// TestVlessFlowFromInboundTemplate proves users inherit `flow` from the
// admin-authored inbound template (the panel models flow per-inbound).
func TestVlessFlowFromInboundTemplate(t *testing.T) {
	cfg, err := NewConfig(`{
      "inbounds": [
        {"type":"vless","tag":"r","listen":"0.0.0.0","listen_port":443,
         "users":[{"name":"template","uuid":"00000000-0000-0000-0000-000000000000","flow":"xtls-rprx-vision"}]}
      ],
      "outbounds": [{"type":"direct","tag":"direct"}]
    }`, nil)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	cfg.syncUsers([]*common.User{{
		Email:    "1",
		Proxies:  &common.Proxy{Vless: &common.Vless{Id: uuid.New().String()}},
		Inbounds: []string{"r"},
	}})
	users, _ := cfg.inbounds()[0]["users"].([]any)
	if len(users) != 1 {
		t.Fatalf("injected %d users, want 1", len(users))
	}
	entry := users[0].(map[string]any)
	if entry["flow"] != "xtls-rprx-vision" {
		t.Errorf("injected flow = %v, want xtls-rprx-vision", entry["flow"])
	}
}

// TestRealityFlowDefault: even with an empty users template, users injected
// into a Reality inbound must carry xtls-rprx-vision.
func TestRealityFlowDefault(t *testing.T) {
	cfg, err := NewConfig(`{
      "inbounds": [
        {"type":"vless","tag":"r","listen":"0.0.0.0","listen_port":443,"users":[],
         "tls":{"enabled":true,
           "reality":{"enabled":true,
             "handshake":{"server":"www.microsoft.com","server_port":443},
             "private_key":"aDDe6dyBwu2nRFwnalSvl2JcGOU_ajXw1ya-LXoJdEw",
             "short_id":["0123456789abcdef"]}}}
      ],
      "outbounds": [{"type":"direct","tag":"direct"}]
    }`, nil)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	cfg.syncUsers([]*common.User{{
		Email:    "1",
		Proxies:  &common.Proxy{Vless: &common.Vless{Id: uuid.New().String()}},
		Inbounds: []string{"r"},
	}})
	users, _ := cfg.inbounds()[0]["users"].([]any)
	entry := users[0].(map[string]any)
	if entry["flow"] != "xtls-rprx-vision" {
		t.Errorf("flow = %v, want default xtls-rprx-vision on a reality inbound", entry["flow"])
	}
}
