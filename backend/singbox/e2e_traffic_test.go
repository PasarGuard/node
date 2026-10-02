package singbox

import (
	"context"
	"encoding/json"
	"fmt"
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

// TestSingBoxTrafficCounted boots a real sing-box server through the backend,
// drives real traffic through it with a second sing-box client, and asserts the
// per-user counter (user>>>{email}>>>traffic>>>{uplink,downlink}) moved.
//
// Requires a sing-box built with -tags with_v2ray_api.
func TestSingBoxTrafficCounted(t *testing.T) {
	exe := singBoxEnvPath(t)
	dir := t.TempDir()

	email := "4242"
	uuidVal := uuid.New().String()

	serverPort := freePort(t)
	apiPort := freePort(t)
	clientPort := freePort(t)
	targetPort := freePort(t)

	// A local origin server stands in for "the internet".
	origin, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", targetPort))
	if err != nil {
		t.Fatalf("origin listen: %v", err)
	}
	defer origin.Close()
	originDone := make(chan struct{})
	defer close(originDone)
	go func() {
		for {
			conn, err := origin.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// send a fixed payload the client can verify
				_, _ = c.Write(make([]byte, 4096))
			}(conn)
		}
	}()

	serverCfg := fmt.Sprintf(`{
  "log": {"level": "error"},
  "inbounds": [
    {"type":"vless","tag":"vless-in","listen":"127.0.0.1","listen_port":%d,
     "users":[{"name":%q,"uuid":%q}]}
  ],
  "outbounds": [{"type":"direct","tag":"direct"}],
  "route": {"final":"direct"}
}`, serverPort, email, uuidVal)

	cfg, err := NewConfig(serverCfg, nil)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if err := cfg.ApplyAPI(apiPort); err != nil {
		t.Fatalf("ApplyAPI: %v", err)
	}
	cfg.syncUsers([]*common.User{{
		Email:    email,
		Proxies:  &common.Proxy{Vless: &common.Vless{Id: uuidVal}},
		Inbounds: []string{"vless-in"},
	}})

	nodeCfg := config.NewTestConfig(dir, uuid.New())
	nodeCfg.SingBoxExecutablePath = exe

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sb, err := New(ctx, cfg, nil, apiPort, freePort(t), nodeCfg)
	if err != nil {
		t.Fatalf("New backend: %v", err)
	}
	defer sb.Shutdown()

	// sing-box client: socks inbound -> vless outbound to our server
	clientCfgPath := filepath.Join(dir, "client.json")
	clientCfg := fmt.Sprintf(`{
  "log": {"level": "error"},
  "inbounds": [{"type":"mixed","tag":"socks-in","listen":"127.0.0.1","listen_port":%d}],
  "outbounds": [
    {"type":"vless","tag":"proxy","server":"127.0.0.1","server_port":%d,"uuid":%q},
    {"type":"direct","tag":"direct"}
  ],
  "route": {"rules":[{"protocol":["dns"],"action":"hijack-dns"}],"final":"proxy"}
}`, clientPort, serverPort, uuidVal)
	if err := os.WriteFile(clientCfgPath, []byte(clientCfg), 0o644); err != nil {
		t.Fatalf("write client config: %v", err)
	}
	if out, err := exec.Command(exe, "check", "-c", clientCfgPath).CombinedOutput(); err != nil {
		t.Fatalf("client config invalid: %v\n%s", err, out)
	}

	client := exec.Command(exe, "run", "-c", clientCfgPath)
	clientOut, err := os.Create(filepath.Join(dir, "client.log"))
	if err != nil {
		t.Fatalf("client log: %v", err)
	}
	client.Stdout = clientOut
	client.Stderr = clientOut
	if err := client.Start(); err != nil {
		t.Fatalf("start client: %v", err)
	}
	defer func() {
		_ = client.Process.Kill()
		_, _ = client.Process.Wait()
		_ = clientOut.Close()
	}()

	// wait for the client's socks port
	if err := waitForPort(clientPort, 15*time.Second); err != nil {
		t.Fatalf("client socks never came up: %v", err)
	}

	// drive traffic through the tunnel
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", targetPort))
	if err == nil {
		_ = conn.Close()
	}
	proxyConn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", clientPort))
	if err != nil {
		t.Fatalf("dial client socks: %v", err)
	}
	defer proxyConn.Close()

	// minimal SOCKS5 CONNECT to 127.0.0.1:targetPort
	handshake := []byte{0x05, 0x01, 0x00}
	if _, err := proxyConn.Write(handshake); err != nil {
		t.Fatalf("socks greeting: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := proxyConn.Read(resp); err != nil {
		t.Fatalf("socks greeting reply: %v", err)
	}
	if resp[0] != 0x05 {
		t.Fatalf("unexpected socks version byte 0x%02x", resp[0])
	}

	req := append([]byte{0x05, 0x01, 0x00, 0x01}, net.ParseIP("127.0.0.1").To4()...)
	req = append(req, byte(targetPort>>8), byte(targetPort))
	req = append(req, 0x00)
	if _, err := proxyConn.Write(req); err != nil {
		t.Fatalf("socks connect request: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := proxyConn.Read(reply); err != nil {
		t.Fatalf("socks connect reply: %v", err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("socks connect failed with code %d", reply[1])
	}

	payload := make([]byte, 8*1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	go func() { _, _ = proxyConn.Write(payload) }()

	_ = proxyConn.SetReadDeadline(time.Now().Add(20 * time.Second))
	received := 0
	buf := make([]byte, 8192)
	for received < 4096 {
		n, err := proxyConn.Read(buf)
		if err != nil {
			t.Fatalf("read through tunnel: %v (received %d bytes)", err, received)
		}
		received += n
	}
	t.Logf("received %d bytes through the VLESS tunnel", received)

	// the per-user counter must reflect the traffic
	deadline := time.Now().Add(20 * time.Second)
	var (
		up, down int64
		seen     bool
	)
	for time.Now().Before(deadline) {
		stats, err := sb.GetStats(ctx, &common.StatRequest{Type: common.StatType_UsersStat, Reset_: true})
		if err != nil {
			t.Fatalf("GetStats: %v", err)
		}
		for _, s := range stats.GetStats() {
			if s.GetName() != email {
				continue
			}
			seen = true
			if s.GetLink() == "traffic" && s.GetType() == "uplink" {
				up = s.GetValue()
			}
			if s.GetLink() == "traffic" && s.GetType() == "downlink" {
				down = s.GetValue()
			}
		}
		if seen && (up > 0 || down > 0) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if !seen {
		t.Fatalf("no per-user stats for %q; the user name must reach metadata.User", email)
	}
	if up == 0 && down == 0 {
		t.Fatalf("per-user counters stayed zero after %d bytes of tunneled traffic (up=%d down=%d)", received, up, down)
	}
	t.Logf("per-user counters: uplink=%d downlink=%d", up, down)

	// the panel-facing shape must parse into name=email/link=traffic/type=uplink
	stats, err := sb.GetStats(ctx, &common.StatRequest{Type: common.StatType_UserStat, Name: email, Reset_: false})
	if err != nil {
		t.Fatalf("GetStats(UserStat): %v", err)
	}
	raw, _ := json.Marshal(stats.GetStats())
	t.Logf("UserStat payload: %s", raw)
	if len(stats.GetStats()) == 0 {
		t.Error("UserStat returned no counters after traffic was counted")
	}
}

func waitForPort(port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err == nil {
			_ = c.Close()
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("port %d not reachable within %s", port, timeout)
}
