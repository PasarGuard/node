package openvpn

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/pasarguard/node/backend"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
)

// The session lifecycle against a real openvpn binary: connect, kill, gone.
//
// Gated the way backend/hysteria's live suite is gated, and for the same
// reason — it needs a kernel tun device and a pinned binary that a developer
// machine may not have. Two skips, each naming what is missing, so nobody has
// to guess whether a green run meant anything.
const liveUser = "4242"

func TestLiveSessionKillAgainstARealBinary(t *testing.T) {
	binary := os.Getenv("OPENVPN_TEST_BINARY")
	if binary == "" {
		t.Skip("OPENVPN_TEST_BINARY is not set — set it to an openvpn 2.6.x binary on a Linux host to prove connect → kill → session gone")
	}
	if runtime.GOOS != "linux" {
		t.Skipf("OPENVPN_TEST_BINARY is set but this is %s: openvpn needs /dev/net/tun and CAP_NET_ADMIN, so the session lifecycle can only be proven on a Linux host", runtime.GOOS)
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skipf("OPENVPN_TEST_BINARY is set but /dev/net/tun is missing (%v): the tunnel cannot be created here", err)
	}

	authExe := mustAuthExe(t)
	t.Setenv(openvpnExecutableEnv, binary)
	t.Setenv(authExecutableEnv, authExe)
	// A pool nothing else on this host will be using, so a stray openvpn on
	// 10.8.0.0/24 cannot make this test pass or fail for the wrong reason.
	t.Setenv(mgmtPasswordEnv, "live-mgmt-password")

	port := freeUDPPort(t)
	root := t.TempDir()
	// core-1, not a bare directory: logger.BindOnce keys the per-core log off
	// that name, so this is also the live proof that core-<id>.log is written.
	genDir := filepath.Join(root, "core-1")
	cfg, err := NewConfig(fmt.Sprintf(`{
		"port": %d,
		"protocol": "udp",
		"server": "10.63.241.0/24",
		"dns": ["10.63.241.1"]
	}`, port), nil)
	if err != nil {
		t.Fatal(err)
	}

	users := []*common.User{{
		Email: liveUser,
		Proxies: &common.Proxy{
			Openvpn: &common.Openvpn{Username: liveUser, Password: "live-password"},
		},
	}}
	nodeCfg := &config.Config{
		GeneratedConfigPath: genDir,
		LogBufferSize:       100,
		StartupLogTailSize:  200,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	ovpn, err := New(ctx, cfg, users, backendPorts(), nodeCfg)
	if err != nil {
		t.Fatalf("New (look at the startup tail — it is the reason the child refused to start): %v", err)
	}
	t.Cleanup(ovpn.Shutdown)
	if !ovpn.Started() {
		t.Fatal("core reports not started")
	}

	clientLog, clientDone := startLiveClient(t, ctx, binary, genDir, port)
	t.Cleanup(func() { _ = clientDone() })

	m := ovpn.Management()
	if m == nil {
		t.Fatal("management handle is nil on a running core")
	}

	deadline := time.Now().Add(40 * time.Second)
	var session Session
	for {
		sessions, err := m.Sessions(ctx)
		if err == nil {
			if s, ok := sessions[liveUser]; ok {
				session = s
				break
			}
		}
		if time.Now().After(deadline) {
			dumpLiveFailure(t, sessions, err, clientLog, filepath.Join(root, "core-1.log"))
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
	if session.VirtualAddr == "" {
		raw, rawErr := m.Exec(ctx, "status 2")
		t.Fatalf("session has no tunnel address: %+v\n--- status 2 (err=%v) ---\n%s\n--- server log ---\n%s\n--- client log ---\n%s",
			session, rawErr, raw,
			readFileOrNone(filepath.Join(root, "core-1.log")),
			readFileOrNone(clientLog))
	}
	if want := ovpn.AssignedIPs()[liveUser]; session.VirtualAddr != want {
		t.Errorf("connected from %s, the CCD pinned %s", session.VirtualAddr, want)
	}
	t.Logf("connected: %+v", session)

	if err := m.Kill(ctx, liveUser); err != nil {
		t.Fatalf("kill: %v", err)
	}
	deadline = time.Now().Add(15 * time.Second)
	for {
		sessions, err := m.Sessions(ctx)
		if err == nil {
			if _, still := sessions[liveUser]; !still {
				t.Logf("session gone after kill (was %s)", session.VirtualAddr)
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("session survived kill: %v", sessions)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func backendPorts() backend.Ports {
	return backend.Ports{}
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

// startLiveClient runs the official client against the core this test just
// started. The client is the same pinned binary: openvpn serves both roles
// (LEGACY-VPN.md 2).
func startLiveClient(t *testing.T, ctx context.Context, binary, genDir string, port int) (string, func() error) {
	t.Helper()
	clientDir := t.TempDir()
	for _, name := range []string{caCertFile, tlsCryptFile} {
		body, err := os.ReadFile(filepath.Join(genDir, name))
		if err != nil {
			t.Fatalf("reading %s from the server directory: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(clientDir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// via-file needs the same two-line layout the server writes for itself.
	if err := os.WriteFile(filepath.Join(clientDir, "userpass"),
		[]byte(liveUser+"\nlive-password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conf := fmt.Sprintf(`client
dev tun
proto udp
remote 127.0.0.1 %d
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth-user-pass userpass
ca ca.crt
tls-crypt tls-crypt.key
tls-version-min 1.2
data-ciphers AES-256-GCM:CHACHA20-POLY1305
verb 3
`, port)
	if err := os.WriteFile(filepath.Join(clientDir, "client.conf"), []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}

	logPath := filepath.Join(clientDir, "client.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, binary, "--cd", clientDir, "--config", "client.conf")
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		logFile.Close()
		t.Fatalf("starting the openvpn client: %v", err)
	}
	return logPath, func() error {
		_ = cmd.Process.Kill()
		waitErr := cmd.Wait()
		logFile.Close()
		return waitErr
	}
}

// dumpLiveFailure is what the panel would never see but a test must: the
// server's own captured output and the client's, side by side. A client that
// refuses to connect and a server that refuses a client look identical from
// the session list alone.
func dumpLiveFailure(t *testing.T, sessions map[string]Session, err error, clientLog, serverLog string) {
	t.Helper()
	t.Fatalf("client never connected (sessions=%v err=%v)\n--- server log %s ---\n%s\n--- client log ---\n%s",
		sessions, err, serverLog, readFileOrNone(serverLog), readFileOrNone(clientLog))
}

func readFileOrNone(path string) string {
	body, readErr := os.ReadFile(path)
	if readErr != nil {
		return "(no client log: " + readErr.Error() + ")"
	}
	return string(body)
}
