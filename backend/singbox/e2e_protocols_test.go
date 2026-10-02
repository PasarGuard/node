package singbox

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
)

// TestSingBoxProtocolMatrix boots the backend with one inbound per supported
// protocol and drives real traffic through each via a single long-lived
// sing-box client (one socks inbound per protocol), asserting the per-user
// counter moved for that connection.
//
// Requires a sing-box built with -tags with_v2ray_api.
func TestSingBoxProtocolMatrix(t *testing.T) {
	exe := singBoxEnvPath(t)
	dir := t.TempDir()
	userID := uuid.New().String()

	certPath, keyPath := testCert(t)
	// one shot: five server ports + api + metric + target + five socks ports,
	// guaranteed pairwise-distinct (sequential freePort() calls can return the
	// same freshly-released port on Windows)
	p := freePorts(t, 13)
	ports := map[string]int{
		"vless":  p[0],
		"trojan": p[1],
		"ss":     p[2],
		"hy2":    p[3],
		"tuic":   p[4],
	}
	apiPort := p[5]
	metricPort := p[6]
	targetPort := p[7]

	// local origin standing in for the internet
	origin, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", targetPort))
	if err != nil {
		t.Fatalf("origin listen: %v", err)
	}
	defer origin.Close()
	go func() {
		for {
			c, err := origin.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write(make([]byte, 2048))
				// Drain the client's upload before closing: an early close
				// turns the client's in-flight write into an RST, which
				// discards the receive buffer on loopback and shows up as a
				// flaky EOF with partial data.
				_, _ = io.Copy(io.Discard, c)
			}(c)
		}
	}()

	serverCfg := fmt.Sprintf(`{
  "log": {"level": "info"},
  "inbounds": [
    {"type":"vless","tag":"vless-in","listen":"127.0.0.1","listen_port":%d,
     "users":[{"name":"vless-user","uuid":%q}]},
    {"type":"trojan","tag":"trojan-in","listen":"127.0.0.1","listen_port":%d,
     "users":[{"name":"trojan-user","password":"tj-pw"}],
     "tls":{"enabled":true,"certificate_path":%q,"key_path":%q}},
    {"type":"shadowsocks","tag":"ss-in","listen":"127.0.0.1","listen_port":%d,
     "method":"2022-blake3-aes-128-gcm",
     "password":"8JCsPssfgS8tiRwiMlhARg==",
     "users":[]},
    {"type":"hysteria2","tag":"hy2-in","listen":"127.0.0.1","listen_port":%d,
     "up_mbps":100,"down_mbps":100,"users":[{"name":"hy2-user","password":"hy2-pw"}],
     "tls":{"enabled":true,"certificate_path":%q,"key_path":%q}},
    {"type":"tuic","tag":"tuic-in","listen":"127.0.0.1","listen_port":%d,
     "congestion_control":"bbr",
     "users":[{"name":"tuic-user","uuid":%q,"password":"tuic-pw"}],
     "tls":{"enabled":true,"certificate_path":%q,"key_path":%q}}
  ],
  "outbounds": [{"type":"direct","tag":"direct"}],
  "route": {"final":"direct"}
}`,
		ports["vless"], userID,
		ports["trojan"], certPath, keyPath,
		ports["ss"],
		ports["hy2"], certPath, keyPath,
		ports["tuic"], userID, certPath, keyPath)

	cfg, err := NewConfig(serverCfg, nil)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if err := cfg.ApplyAPI(apiPort); err != nil {
		t.Fatalf("ApplyAPI: %v", err)
	}

	fullProxies := &common.Proxy{
		Vless:       &common.Vless{Id: userID},
		Trojan:      &common.Trojan{Password: "tj-pw"},
		Shadowsocks: &common.Shadowsocks{Password: "8JCsPssfgS8tiRwiMlhARg=="},
		Hysteria:    &common.Hysteria{Auth: "hy2-pw"},
	}
	// SS-2022 is server-PSK scoped: no per-user identity, so its traffic is
	// attributed to the inbound, not to a user. Every other inbound gets its
	// own user entry.
	cfg.syncUsers([]*common.User{
		{Email: "vless-user", Proxies: fullProxies, Inbounds: []string{"vless-in"}},
		{Email: "trojan-user", Proxies: fullProxies, Inbounds: []string{"trojan-in"}},
		{Email: "hy2-user", Proxies: fullProxies, Inbounds: []string{"hy2-in"}},
		{Email: "tuic-user", Proxies: fullProxies, Inbounds: []string{"tuic-in"}},
	})

	nodeCfg := config.NewTestConfig(dir, uuid.New())
	nodeCfg.SingBoxExecutablePath = exe

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	sb, err := New(ctx, cfg, nil, apiPort, metricPort, nodeCfg)
	if err != nil {
		t.Fatalf("New backend: %v", err)
	}
	defer sb.Shutdown()

	// drain the backend's log channel (normally consumed by the GetLogs RPC)
	// and keep the tail for failure diagnosis
	serverLogTail := make([]string, 0, 64)
	go func() {
		for line := range sb.Logs() {
			if len(serverLogTail) >= 64 {
				serverLogTail = serverLogTail[1:]
			}
			serverLogTail = append(serverLogTail, line)
		}
	}()

	for name, wantUser := range map[string]string{
		"vless": "vless-user", "trojan": "trojan-user", "hy2": "hy2-user", "tuic": "tuic-user", "ss": "",
	} {
		t.Run(name, func(t *testing.T) {
			port := freePort(t)
			cfgPath, logPath := filepath.Join(dir, "client-"+name+".json"), filepath.Join(dir, "client-"+name+".log")
			writeClientConfig(t, exe, cfgPath, logPath, name, port, ports[name], targetPort, userID)

			defer func() {
				if t.Failed() {
					t.Logf("client log: %s", readTail(logPath))
					if len(serverLogTail) > 0 {
						t.Logf("server log tail: %v", serverLogTail)
					}
				}
			}()

			received := socksFetch(t, port, targetPort, 2048)
			t.Logf("%s: received %d bytes", name, received)
			if wantUser == "" {
				// SS-2022 has no per-user identity; connectivity is the assertion
				return
			}

			deadline := time.Now().Add(20 * time.Second)
			var up, down int64
			for time.Now().Before(deadline) {
				stats, err := sb.GetStats(ctx, &common.StatRequest{Type: common.StatType_UserStat, Name: wantUser, Reset_: true})
				if err != nil {
					t.Fatalf("GetStats: %v", err)
				}
				for _, st := range stats.GetStats() {
					if st.GetName() != wantUser || st.GetLink() != "traffic" {
						continue
					}
					if st.GetType() == "uplink" {
						up += st.GetValue()
					}
					if st.GetType() == "downlink" {
						down += st.GetValue()
					}
				}
				if up > 0 && down > 0 {
					break
				}
				time.Sleep(500 * time.Millisecond)
			}
			if up == 0 && down == 0 {
				t.Fatalf("%s: no per-user traffic counted for %q", name, wantUser)
			}
			t.Logf("%s: counters uplink=%d downlink=%d", name, up, down)
		})
	}
}

// writeClientConfig starts a single-purpose sing-box client: one socks inbound
// routing through the outbound for proto, to targetPort.
func writeClientConfig(t *testing.T, exe, cfgPath, logPath, proto string, socksPort, serverPort, targetPort int, userID string) {
	t.Helper()
	clientCfg := map[string]any{
		"log":      map[string]any{"level": "debug"},
		"inbounds": []any{map[string]any{"type": "mixed", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": socksPort}},
		"outbounds": []any{
			clientOutboundFor(proto, serverPort, userID),
			map[string]any{"type": "direct", "tag": "direct"},
		},
		"route": map[string]any{"final": "proxy"},
	}
	buf, _ := json.Marshal(clientCfg)
	if err := os.WriteFile(cfgPath, buf, 0o644); err != nil {
		t.Fatalf("write client config: %v", err)
	}
	if out, err := exec.Command(exe, "check", "-c", cfgPath).CombinedOutput(); err != nil {
		t.Fatalf("client config invalid: %v\n%s", err, out)
	}

	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("client log: %v", err)
	}
	client := exec.Command(exe, "run", "-c", cfgPath)
	client.Stdout = logFile
	client.Stderr = logFile
	if err := client.Start(); err != nil {
		t.Fatalf("start client: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Process.Kill()
		_, _ = client.Process.Wait()
		_ = logFile.Close()
	})

	if err := waitForPort(socksPort, 15*time.Second); err != nil {
		t.Fatalf("client socks %d never came up: %v", socksPort, err)
	}
}

func clientOutboundFor(name string, serverPort int, userID string) map[string]any {
	switch name {
	case "vless":
		return map[string]any{"type": "vless", "tag": "proxy", "server": "127.0.0.1", "server_port": serverPort, "uuid": userID}
	case "trojan":
		return map[string]any{
			"type": "trojan", "tag": "proxy", "server": "127.0.0.1", "server_port": serverPort, "password": "tj-pw",
			"tls": map[string]any{"enabled": true, "server_name": "localhost", "insecure": true},
		}
	case "ss":
		return map[string]any{
			"type": "shadowsocks", "tag": "proxy", "server": "127.0.0.1", "server_port": serverPort,
			"method": "2022-blake3-aes-128-gcm", "password": "8JCsPssfgS8tiRwiMlhARg==",
		}
	case "hy2":
		return map[string]any{
			"type": "hysteria2", "tag": "proxy", "server": "127.0.0.1", "server_port": serverPort, "password": "hy2-pw",
			"tls": map[string]any{"enabled": true, "server_name": "localhost", "insecure": true},
		}
	case "tuic":
		return map[string]any{
			"type": "tuic", "tag": "proxy", "server": "127.0.0.1", "server_port": serverPort,
			"uuid": userID, "password": "hy2-pw",
			"tls": map[string]any{"enabled": true, "server_name": "localhost", "insecure": true},
		}
	default:
		panic("unknown protocol " + name)
	}
}

// socksFetch performs a SOCKS5 CONNECT through proxyPort and reads n bytes.
func socksFetch(t *testing.T, proxyPort, targetPort, n int) int {
	t.Helper()
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort))
	if err != nil {
		t.Fatalf("dial socks: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(25 * time.Second))

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("socks greeting: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("socks greeting reply: %v", err)
	}
	if resp[0] != 0x05 {
		t.Fatalf("unexpected socks version 0x%02x", resp[0])
	}

	req := append([]byte{0x05, 0x01, 0x00, 0x01}, net.ParseIP("127.0.0.1").To4()...)
	req = append(req, byte(targetPort>>8), byte(targetPort))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("socks connect: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("socks reply: %v", err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("socks connect failed: %d", reply[1])
	}

	payload := make([]byte, 4096)
	go func() { _, _ = conn.Write(payload) }()

	received := 0
	buf := make([]byte, 4096)
	for received < n {
		got, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read through tunnel: %v (got %d)", err, received)
		}
		received += got
	}
	return received
}

func readTail(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if len(data) > 1200 {
		data = data[len(data)-1200:]
	}
	return string(data)
}
