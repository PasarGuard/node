package plain

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/pasarguard/node/backend/tunnel"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/pkg/tlsutil"
)

// TestNodeProcessRestoresTunnelFromConfig is the node-process half of scope
// test 1: a plain tunnel comes back after the node PROCESS restarts, from the
// persisted config alone, and a wrong API key on StartTunnel starts nothing.
//
// It builds and runs the real node binary inside the normal `go test ./...`
// run — no flag, no build tag. Budget: well under a minute on a warm cache.
func TestNodeProcessRestoresTunnelFromConfig(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()

	certFile, keyFile := writeTestCerts(t, work)
	apiKey := uuid.New()
	genDir := filepath.Join(work, "generated")

	bin := filepath.Join(work, nodeExeName())
	buildNode(t, repoRoot, bin)

	const tunnelID = "proc-restart-1"
	const allocID = "proc-alloc-1"
	secret := "process-level-secret"
	run1Port := freeTCPPort(t)
	pinnedPort := freeTCPPort(t)

	env1 := nodeEnv(apiKey, run1Port, certFile, keyFile, genDir, secret)
	p1 := startNode(t, bin, env1, work)
	client1 := dialNode(t, run1Port, certFile, apiKey)
	ctx1 := withKey(apiKey)

	// 1. A wrong API key is refused and starts nothing.
	badCtx := withKey(uuid.New())
	_, err = client1.StartTunnel(badCtx, plainTunnelSpec(tunnelID, 0))
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("wrong api key on StartTunnel: code=%v err=%v, want PermissionDenied", status.Code(err), err)
	}
	list, err := client1.ListTunnels(badCtx, &common.Empty{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("wrong api key on ListTunnels: code=%v err=%v, want PermissionDenied", status.Code(err), err)
	}
	if list != nil && len(list.GetTunnels()) != 0 {
		t.Fatalf("a refused call reported tunnels: %v", list)
	}
	list, err = client1.ListTunnels(ctx1, &common.Empty{})
	if err != nil || len(list.GetTunnels()) != 0 {
		t.Fatalf("after a refused StartTunnel, ListTunnels = %v, %v — want empty", list, err)
	}

	// A listen_port that is not a port number is refused before anything binds.
	if _, err := client1.StartTunnel(ctx1, plainTunnelSpec("proc-badport", -1)); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("listen_port=abc: code=%v err=%v, want InvalidArgument", status.Code(err), err)
	}

	// 2. The right key starts two tunnels: one on a panel-pinned port (how the
	// panel writes the other side's `peer`), one on a node-allocated port.
	st, err := client1.StartTunnel(ctx1, plainTunnelSpec(tunnelID, pinnedPort))
	if err != nil {
		t.Fatalf("StartTunnel (pinned port): %v", err)
	}
	if st.GetState() != "healthy" {
		t.Fatalf("state = %q, want healthy", st.GetState())
	}
	if _, err := client1.StartTunnel(ctx1, plainTunnelSpec(allocID, 0)); err != nil {
		t.Fatalf("StartTunnel (allocated port): %v", err)
	}
	allocPort := persistedListenPort(t, genDir, allocID)
	if got := persistedListenPort(t, genDir, tunnelID); got != pinnedPort {
		t.Fatalf("persisted listen port = %d, want the pinned %d", got, pinnedPort)
	}
	waitDialable(t, pinnedPort)
	waitDialable(t, allocPort)

	// 3. A tunnel node refuses the user fan-out over the wire (CONTRACT §1.7).
	_, err = client1.SyncUsers(ctx1, &common.Users{Users: []*common.User{{Email: "x@example.com"}}})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(status.Convert(err).Message(), "tunnel") {
		t.Fatalf("SyncUsers on a tunnel node: code=%v err=%v, want FailedPrecondition naming the role", status.Code(err), err)
	}

	// 4. Kill the process. Only the config directory survives.
	stopNode(t, p1)
	waitPortFree(t, pinnedPort)
	waitPortFree(t, allocPort)

	// 5. Restart with the same config dir and NO StartTunnel call: both
	// tunnels must be back on their own.
	run2Port := freeTCPPort(t)
	p2 := startNode(t, bin, nodeEnv(apiKey, run2Port, certFile, keyFile, genDir, secret), work)
	defer stopNode(t, p2)
	client2 := dialNode(t, run2Port, certFile, apiKey)
	ctx2 := withKey(apiKey)

	list, err = client2.ListTunnels(ctx2, &common.Empty{})
	if err != nil {
		t.Fatalf("ListTunnels after restart: %v", err)
	}
	if len(list.GetTunnels()) != 2 {
		t.Fatalf("after restart, %d tunnel(s) reported, want 2 (config alone): %v", len(list.GetTunnels()), list)
	}
	for _, got := range list.GetTunnels() {
		if got.GetState() != "healthy" {
			t.Fatalf("restored tunnel %s state = %q, want healthy", got.GetTunnelId(), got.GetState())
		}
	}
	waitDialable(t, pinnedPort)
	waitDialable(t, allocPort)

	// 6. The secret's value never reached the config file, in either run.
	data, err := os.ReadFile(filepath.Join(genDir, "tunnels", tunnelID+"-a.tunnel.json"))
	if err != nil {
		t.Fatalf("persisted config: %v", err)
	}
	if strings.Contains(string(data), secret) {
		t.Fatalf("secret value is on disk:\n%s", data)
	}
	if !strings.Contains(string(data), SecretToken) {
		t.Fatalf("secret name must be on disk for the restore to re-resolve it:\n%s", data)
	}
}

// plainTunnelSpec builds the wire spec for one side. listenPort > 0 pins the
// listen port (Params["listen_port"]); 0 lets the node allocate one; a
// negative value is spelled out to exercise the validation.
func plainTunnelSpec(id string, listenPort int) *common.TunnelSpec {
	params := map[string]string{
		"listen_host": "127.0.0.1",
		"peer":        "127.0.0.1:1", // unreachable: nothing dials it here
	}
	switch {
	case listenPort > 0:
		params[tunnel.ParamListenPort] = strconv.Itoa(listenPort)
	case listenPort < 0:
		params[tunnel.ParamListenPort] = "not-a-port"
	}
	return &common.TunnelSpec{
		TunnelId:    id,
		Tool:        Tool,
		ToolVersion: Version,
		Side:        "a",
		Mode:        tunnel.ModeRelay,
		Params:      params,
		SecretNames: []string{SecretToken},
		Enabled:     true,
	}
}

// persistedListenPort reads the node's own persisted state for the port it
// bound — the panel learns it the same way, from the node, never from a guess.
func persistedListenPort(t *testing.T, genDir, id string) int {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(genDir, "tunnels", id+"-a.tunnel.json"))
	if err != nil {
		t.Fatalf("persisted config: %v", err)
	}
	var rec struct {
		Ports tunnel.Ports `json:"ports"`
	}
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse persisted config: %v\n%s", err, data)
	}
	if rec.Ports.Listen == 0 {
		t.Fatalf("persisted config has no listen port:\n%s", data)
	}
	return rec.Ports.Listen
}

func nodeEnv(apiKey uuid.UUID, servicePort int, certFile, keyFile, genDir, secret string) []string {
	return append(os.Environ(),
		"API_KEY="+apiKey.String(),
		"SERVICE_PORT="+strconv.Itoa(servicePort),
		"NODE_HOST=127.0.0.1",
		"NODE_ROLE=tunnel",
		"SSL_CERT_FILE="+certFile,
		"SSL_KEY_FILE="+keyFile,
		"GENERATED_CONFIG_PATH="+genDir,
		"SERVICE_PROTOCOL=grpc",
		SecretToken+"="+secret,
	)
}

func nodeExeName() string {
	if runtime.GOOS == "windows" {
		return "node.exe"
	}
	return "node"
}

func buildNode(t *testing.T, repoRoot, out string) {
	t.Helper()
	cmd := exec.Command("go", "build", "-o", out, "./cmd/node")
	cmd.Dir = repoRoot
	if outStr, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build ./cmd/node: %v\n%s", err, outStr)
	}
}

type nodeProc struct {
	cmd  *exec.Cmd
	logs *strings.Builder
}

func startNode(t *testing.T, bin string, env []string, work string) *nodeProc {
	t.Helper()
	cmd := exec.Command(bin)
	cmd.Env = env
	cmd.Dir = work
	logs := &strings.Builder{}
	cmd.Stdout = logs
	cmd.Stderr = logs
	if err := cmd.Start(); err != nil {
		t.Fatalf("start node: %v", err)
	}
	p := &nodeProc{cmd: cmd, logs: logs}
	port := envPort(env)
	waitGRPC(t, p, port)
	return p
}

func envPort(env []string) int {
	for _, kv := range env {
		if strings.HasPrefix(kv, "SERVICE_PORT=") {
			var n int
			_, _ = fmt.Sscanf(strings.TrimPrefix(kv, "SERVICE_PORT="), "%d", &n)
			return n
		}
	}
	return 0
}

func stopNode(t *testing.T, p *nodeProc) {
	t.Helper()
	if p == nil || p.cmd.Process == nil {
		return
	}
	_ = p.cmd.Process.Kill()
	_, _ = p.cmd.Process.Wait()
}

func waitGRPC(t *testing.T, p *nodeProc, port int) {
	t.Helper()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			// The listener is up; give gRPC a beat to serve, then probe with a
			// real RPC from dialNode's own retry.
			return
		}
		if p.cmd.ProcessState != nil && p.cmd.ProcessState.Exited() {
			t.Fatalf("node exited during startup:\n%s", p.logs.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("node never listened on %s:\n%s", addr, p.logs.String())
}

func dialNode(t *testing.T, port int, certFile string, apiKey uuid.UUID) common.NodeServiceClient {
	t.Helper()
	pool, err := tlsutil.LoadClientPool(certFile)
	if err != nil {
		t.Fatal(err)
	}
	creds := credentials.NewClientTLSFromCert(pool, "")
	conn, err := grpc.NewClient(fmt.Sprintf("127.0.0.1:%d", port),
		grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := common.NewNodeServiceClient(conn)

	// The server's listener may be accepting before gRPC serves; retry until
	// GetBaseInfo answers so the test never races process startup.
	deadline := time.Now().Add(10 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(withKey(apiKey), 2*time.Second)
		_, err := client.GetBaseInfo(ctx, &common.Empty{})
		cancel()
		if err == nil {
			return client
		}
		if time.Now().After(deadline) {
			t.Fatalf("gRPC never became ready: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func withKey(key uuid.UUID) context.Context {
	return metadata.NewOutgoingContext(context.Background(), metadata.Pairs("x-api-key", key.String()))
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func waitDialable(t *testing.T, port int) {
	t.Helper()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("nothing is listening on %s", addr)
}

func waitPortFree(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			_ = ln.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("port %d never became free", port)
}

// writeTestCerts self-signs a certificate for 127.0.0.1 in the temp dir, so
// this test does not depend on `make generate_server_cert` having been run —
// a fresh clone must pass it.
func writeTestCerts(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	writePEM(t, certFile, "CERTIFICATE", der)
	writePEM(t, keyFile, "EC PRIVATE KEY", keyDER)
	return certFile, keyFile
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		t.Fatal(err)
	}
}
