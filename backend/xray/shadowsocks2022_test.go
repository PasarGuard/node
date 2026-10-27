//go:build !windows

package xray

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
	"github.com/pasarguard/node/pkg/netutil"
)

const (
	shadowsocks2022TestInbound   = "SS2022 SESSION"
	shadowsocks2022TestMethod    = "2022-blake3-aes-128-gcm"
	shadowsocks2022TestServerKey = "MDEyMzQ1Njc4OWFiY2RlZg=="
)

const shadowsocks2022TestConfig = `{
	"log": {"loglevel": "warning"},
	"inbounds": [{
		"tag": "SS2022 SESSION",
		"listen": "127.0.0.1",
		"port": %d,
		"protocol": "shadowsocks",
		"settings": {"clients": [], "method": "2022-blake3-aes-128-gcm", "password": "MDEyMzQ1Njc4OWFiY2RlZg==", "network": "tcp"}
	}],
	"outbounds": [{
		"tag": "direct",
		"protocol": "freedom",
		"settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.1"]}]}
	}]
}`

// startShadowsocks2022Client runs a second Xray that forwards a local SOCKS5 port
// to the inbound with the given password and returns that port.
func startShadowsocks2022Client(t *testing.T, exe string, serverPort int, password string) int {
	t.Helper()

	socksPort := netutil.FindFreePort()
	clientConfig := fmt.Sprintf(`{
		"log": {"loglevel": "warning"},
		"inbounds": [{"listen": "127.0.0.1", "port": %d, "protocol": "socks", "settings": {"auth": "noauth", "udp": false}}],
		"outbounds": [{"protocol": "shadowsocks", "settings": {"servers": [
			{"address": "127.0.0.1", "port": %d, "method": %q, "password": %q}
		]}}]
	}`, socksPort, serverPort, shadowsocks2022TestMethod, password)

	path := filepath.Join(t.TempDir(), "client.json")
	if err := os.WriteFile(path, []byte(clientConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(exe, "run", "-c", path)
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start the xray client: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort))
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp4", address, time.Second)
		if err == nil {
			_ = conn.Close()
			return socksPort
		}
		if time.Now().After(deadline) {
			t.Fatalf("xray client did not listen on %s: %v", address, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// openSocksStream opens a SOCKS5 CONNECT to target and consumes the reply, so
// only bytes from the target are left to read.
func openSocksStream(t *testing.T, socksPort int, target *net.TCPAddr) net.Conn {
	t.Helper()

	conn, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort)), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(conn, method); err != nil || method[1] != 0 {
		t.Fatalf("socks method reply %v, err %v", method, err)
	}

	request := []byte{5, 1, 0, 1}
	request = append(request, target.IP.To4()...)
	request = append(request, byte(target.Port>>8), byte(target.Port))
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil || reply[1] != 0 {
		t.Fatalf("socks connect reply %v, err %v", reply, err)
	}

	_ = conn.SetDeadline(time.Time{})
	return conn
}

func TestShadowsocks2022InboundStartedWithoutUsers(t *testing.T) {
	exe := resolveXrayBinary(t)
	source := startByteSource(t)
	inboundPort := netutil.FindFreePort()

	xrayConfig, err := NewConfig(fmt.Sprintf(shadowsocks2022TestConfig, inboundPort), nil)
	if err != nil {
		t.Fatal(err)
	}

	back, err := New(
		context.Background(),
		xrayConfig,
		nil,
		netutil.FindFreePort(),
		netutil.FindFreePort(),
		&config.Config{
			XrayExecutablePath:  exe,
			XrayAssetsPath:      assetsPath,
			GeneratedConfigPath: configPath,
			LogBufferSize:       1000,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer back.Shutdown()

	// Every Shadowsocks 2022 link the panel hands out starts with the server key.
	bareKey := startShadowsocks2022Client(t, exe, inboundPort, shadowsocks2022TestServerKey)
	if received, _ := receive(openSocksStream(t, bareKey, source), time.Second); received != 0 {
		t.Errorf("the bare server key opened a connection and received %d bytes", received)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	user := &common.User{
		Email:    "1",
		Inbounds: []string{shadowsocks2022TestInbound},
		Proxies:  &common.Proxy{Shadowsocks: &common.Shadowsocks{Password: "user-one-password"}},
	}
	if err := back.SyncUser(ctx, user); err != nil {
		t.Fatalf("adding the first user to the inbound failed: %v", err)
	}

	userKey := common.EnsureBase64Password("user-one-password", shadowsocks2022TestMethod)
	userClient := startShadowsocks2022Client(t, exe, inboundPort, shadowsocks2022TestServerKey+":"+userKey)
	if received, err := receive(openSocksStream(t, userClient, source), time.Second); received == 0 {
		t.Fatalf("the added user received nothing (err %v)", err)
	}
}
