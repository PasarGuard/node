package tunnel_test

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pasarguard/node/backend/tunnel"
	"github.com/pasarguard/node/backend/tunnel/plain"
)

// managerSpec builds a minimal plain side-a spec: it listens, dials whatever
// is in peer, and declares PLAIN_TOKEN as a secret whose value comes from the
// environment at Start.
func managerSpec(id string) tunnel.Spec {
	return tunnel.Spec{
		TunnelID: id,
		Tool:     plain.Tool,
		Side:     tunnel.SideA,
		Mode:     tunnel.ModeRelay,
		Params: map[string]string{
			"listen_host": "127.0.0.1",
			"peer":        "127.0.0.1:1", // never dialled: no traffic in this test
		},
		Secrets: map[string]string{plain.SecretToken: ""},
		Enabled: true,
	}
}

func mustStart(t *testing.T, m *tunnel.Manager, spec tunnel.Spec, ports tunnel.Ports) {
	t.Helper()
	if err := m.Start(context.Background(), spec, ports); err != nil {
		t.Fatalf("Start %s: %v", spec.TunnelID, err)
	}
}

// TestManagerPersistsSecretNamesNotValues is the on-disk rule: the config
// file carries the secret's NAME with an empty value, never the value (the
// same standard as SINGBOX_QUOTA_SECRET — config files end up in crash dumps).
func TestManagerPersistsSecretNamesNotValues(t *testing.T) {
	const secret = "super-secret-token-value"
	t.Setenv(plain.SecretToken, secret)

	dir := t.TempDir()
	alloc := tunnel.NewAllocator()
	ports := alloc.AllocPair()
	m := tunnel.NewManager(tunnel.ManagerOptions{Dir: dir, Allocator: alloc})
	defer m.Shutdown()

	spec := managerSpec("persist-1")
	mustStart(t, m, spec, ports)

	files, err := filepath.Glob(filepath.Join(dir, "*.tunnel.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("persisted files = %v, err = %v (want exactly one)", files, err)
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) {
		t.Fatalf("secret value landed on disk:\n%s", data)
	}
	if !strings.Contains(string(data), plain.SecretToken) {
		t.Fatalf("secret NAME must survive on disk so Restore can re-resolve it:\n%s", data)
	}
}

// TestManagerRestoreBringsTunnelBack: a second Manager pointed at the same
// directory starts the tunnel from the file alone — no RPC, no in-memory state
// carried over. This is the in-process half of the node-process restart test.
func TestManagerRestoreBringsTunnelBack(t *testing.T) {
	t.Setenv(plain.SecretToken, "restore-token")

	dir := t.TempDir()
	alloc := tunnel.NewAllocator()
	ports := alloc.AllocPair()

	m1 := tunnel.NewManager(tunnel.ManagerOptions{Dir: dir, Allocator: alloc})
	spec := managerSpec("restore-1")
	mustStart(t, m1, spec, ports)
	m1.Shutdown() // process goes away; only the file is left

	// The port must actually be free again before restore can prove it rebound.
	waitPortFree(t, ports.Listen)

	m2 := tunnel.NewManager(tunnel.ManagerOptions{Dir: dir})
	started, err := m2.Restore(context.Background())
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if started != 1 {
		t.Fatalf("Restore started %d tunnel(s), want 1", started)
	}
	defer m2.Shutdown()

	st, ok := m2.Status("restore-1")
	if !ok || st.State != "healthy" {
		t.Fatalf("status after restore = %+v ok=%v, want healthy", st, ok)
	}
	// The listener is really back: a dial to the persisted port is accepted.
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(ports.Listen)), 3*time.Second)
	if err != nil {
		t.Fatalf("dial restored tunnel: %v", err)
	}
	_ = conn.Close()
}

// TestManagerStopForgetsTheTunnel: Stop removes the persisted config, so a
// later Restore brings back only what the panel still asks for.
func TestManagerStopForgetsTheTunnel(t *testing.T) {
	t.Setenv(plain.SecretToken, "stop-token")

	dir := t.TempDir()
	alloc := tunnel.NewAllocator()
	ports := alloc.AllocPair()
	m := tunnel.NewManager(tunnel.ManagerOptions{Dir: dir, Allocator: alloc})
	defer m.Shutdown()

	mustStart(t, m, managerSpec("stop-1"), ports)
	if err := m.Stop("stop-1"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if st, ok := m.Status("stop-1"); ok {
		t.Fatalf("tunnel still reported after Stop: %+v", st)
	}

	m2 := tunnel.NewManager(tunnel.ManagerOptions{Dir: dir})
	started, err := m2.Restore(context.Background())
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if started != 0 {
		t.Fatalf("Restore started %d tunnel(s) after Stop, want 0", started)
	}

	// Stopping a tunnel that is not running is an explicit error, not a no-op.
	if err := m2.Stop("never-existed"); !errors.Is(err, tunnel.ErrNotRunning) {
		t.Fatalf("Stop of unknown tunnel: want ErrNotRunning, got %v", err)
	}
}

// TestManagerRefusesUnresolvableSecret: a declared secret with no environment
// value is refused at Start rather than running the tunnel unauthenticated.
func TestManagerRefusesUnresolvableSecret(t *testing.T) {
	t.Setenv(plain.SecretToken, "") // declared, empty, no value anywhere

	m := tunnel.NewManager(tunnel.ManagerOptions{Dir: t.TempDir()})
	defer m.Shutdown()

	ports := tunnel.NewAllocator().AllocPair()
	err := m.Start(context.Background(), managerSpec("secretless"), ports)
	if !errors.Is(err, tunnel.ErrSecretUnresolved) {
		t.Fatalf("want ErrSecretUnresolved, got %v", err)
	}
	if len(m.List()) != 0 {
		t.Fatalf("a refused Start must leave nothing running: %+v", m.List())
	}
}

func waitPortFree(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", itoa(port)))
		if err == nil {
			_ = ln.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("port %d never became free", port)
}

func itoa(n int) string { return strconv.Itoa(n) }
