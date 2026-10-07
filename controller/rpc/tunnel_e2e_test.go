package rpc

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
	"github.com/pasarguard/node/pkg/netutil"
	"github.com/pasarguard/node/pkg/tlsutil"
)

// TestTunnelRPCEndToEndOnATunnelNode closes the gap3.0 left open: its UNVERIFIED
// said "no live gRPC call against a node — only the generated route table". This
// starts a second gRPC server with NODE_ROLE_TUNNEL, dials it, and drives all
// four tunnel RPCs over the wire, plus the negative control that matters most:
// a wrong API key must not start anything.
//
// The traffic itself is proven by the four-part kit in backend/tunnel/plain;
// what is proven *here* is the wiring — panel shape in, running side out.
func TestTunnelRPCEndToEndOnATunnelNode(t *testing.T) {
	// plain resolves its secret from the environment at Start (CONTRACT §2.1):
	// the wire carries the name only.
	t.Setenv("PLAIN_TOKEN", "e2e-tunnel-token")

	cfg := config.NewTestConfig(t.TempDir(), uuid.New())
	cfg.Role = common.NodeRole_NODE_ROLE_TUNNEL

	tlsConfig, err := tlsutil.LoadTLSCredentials(sslCertFile, sslKeyFile)
	if err != nil {
		t.Fatalf("tls credentials: %v", err)
	}
	port := netutil.FindFreePort()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	shutdown, _, err := StartGRPCListener(tlsConfig, addr, cfg)
	if err != nil {
		t.Fatalf("start listener on %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = shutdown(context.Background()) })

	certPool, err := tlsutil.LoadClientPool(sslCertFile)
	if err != nil {
		t.Fatalf("client pool: %v", err)
	}
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(certPool, "")))
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := common.NewNodeServiceClient(conn)

	call := func(key string) (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithTimeout(
			metadata.NewOutgoingContext(context.Background(),
				metadata.Pairs("x-api-key", key)),
			15*time.Second)
		return ctx, cancel
	}

	spec := &common.TunnelSpec{
		TunnelId:    "rpc-e2e-1",
		Tool:        "plain",
		ToolVersion: "test",
		Side:        "a",
		Mode:        "relay",
		Params:      map[string]string{"listen_host": "127.0.0.1", "peer": "127.0.0.1:1"},
		SecretNames: []string{"PLAIN_TOKEN"},
		Enabled:     true,
	}

	// Negative control first: a wrong API key must be refused by the wire, and
	// nothing may be left running because of the attempt.
	{
		ctx, cancel := call(uuid.New().String())
		defer cancel()
		if _, err := client.StartTunnel(ctx, spec); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("wrong api key: code = %v (%v), want PermissionDenied", status.Code(err), err)
		}
	}
	listHas := func(ctx context.Context, id string) (bool, error) {
		list, err := client.ListTunnels(ctx, &common.Empty{})
		if err != nil {
			return false, err
		}
		for _, tn := range list.GetTunnels() {
			if tn.GetTunnelId() == id {
				return true, nil
			}
		}
		return false, nil
	}

	ctx, cancel := call(cfg.ApiKey.String())
	defer cancel()

	got, err := client.StartTunnel(ctx, spec)
	if err != nil {
		t.Fatalf("StartTunnel: %v", err)
	}
	if got.GetTunnelId() != "rpc-e2e-1" {
		t.Fatalf("tunnel_id = %q, want rpc-e2e-1", got.GetTunnelId())
	}
	if got.GetState() == "" || got.GetState() == "stopped" {
		t.Fatalf("state = %q after a successful start", got.GetState())
	}
	if got.GetBytesUp() != 0 || got.GetBytesDown() != 0 {
		t.Fatalf("fresh tunnel already reports bytes: up=%d down=%d",
			got.GetBytesUp(), got.GetBytesDown())
	}
	// The one number the panel cannot choose on the node's behalf: the port
	// this side actually bound, which the peer side's `peer`/`publish` are
	// written from. A 0 here leaves the panel unable to bring up the far end.
	if got.GetListenPort() == 0 {
		t.Fatal("listen_port = 0 after a successful start; the panel writes the other side's peer from it")
	}

	present, err := listHas(ctx, "rpc-e2e-1")
	if err != nil {
		t.Fatalf("ListTunnels: %v", err)
	}
	if !present {
		t.Fatal("ListTunnels does not contain the tunnel that was just started")
	}

	// GetTunnelLogs must hand back what the tunnel logged *before* the stream
	// opened — the panel's GET /api/tunnel/{id}/logs is a history read, and a
	// live-only stream answers an operator's "show me the logs" with nothing
	// (no tunnel activity happens while a logs page sits open).
	// Both streams read the same ring with no further activity at all, which
	// is the whole guarantee: history first, then whatever arrives live.
	firstCtx, firstCancel := call(cfg.ApiKey.String())
	stream1, err := client.GetTunnelLogs(firstCtx, &common.Empty{})
	if err != nil {
		t.Fatalf("GetTunnelLogs (first): %v", err)
	}
	seed, err := stream1.Recv()
	if err != nil {
		t.Fatalf("GetTunnelLogs (first) Recv: %v", err)
	}
	if seed.GetTunnelId() != "rpc-e2e-1" {
		t.Fatalf("first record tunnel_id = %q, want rpc-e2e-1", seed.GetTunnelId())
	}
	firstCancel()
	stream1.CloseSend()

	replayCtx, replayCancel := call(cfg.ApiKey.String())
	defer replayCancel()
	stream2, err := client.GetTunnelLogs(replayCtx, &common.Empty{})
	if err != nil {
		t.Fatalf("GetTunnelLogs (replay): %v", err)
	}
	replayed, err := stream2.Recv()
	if err != nil {
		t.Fatalf("GetTunnelLogs (replay) Recv: %v (the ring is never replayed, so a quiet node answers nothing)", err)
	}
	if replayed.GetTunnelId() != seed.GetTunnelId() || replayed.GetDetail() != seed.GetDetail() {
		t.Fatalf("replay = %q/%q, want the earlier %q/%q",
			replayed.GetTunnelId(), replayed.GetDetail(), seed.GetTunnelId(), seed.GetDetail())
	}

	// A panel-pinned port must come back as pinned, not as whatever the
	// allocator picked — the peer side is written from this number before the
	// other side ever starts.
	pinned := netutil.FindFreePort()
	pinnedSpec := &common.TunnelSpec{
		TunnelId:    "rpc-e2e-pinned",
		Tool:        "plain",
		ToolVersion: "test",
		Side:        "a",
		Mode:        "relay",
		Params: map[string]string{
			"listen_host": "127.0.0.1",
			"peer":        "127.0.0.1:1",
			"listen_port": strconv.Itoa(pinned),
		},
		SecretNames: []string{"PLAIN_TOKEN"},
		Enabled:     true,
	}
	pinnedStatus, err := client.StartTunnel(ctx, pinnedSpec)
	if err != nil {
		t.Fatalf("StartTunnel with a pinned port: %v", err)
	}
	if got := int(pinnedStatus.GetListenPort()); got != pinned {
		t.Fatalf("listen_port = %d, want the pinned %d", got, pinned)
	}
	if _, err := client.StopTunnel(ctx, &common.TunnelId{TunnelId: "rpc-e2e-pinned"}); err != nil {
		t.Fatalf("StopTunnel(pinned): %v", err)
	}

	if _, err := client.StopTunnel(ctx, &common.TunnelId{TunnelId: "rpc-e2e-1"}); err != nil {
		t.Fatalf("StopTunnel: %v", err)
	}
	present, err = listHas(ctx, "rpc-e2e-1")
	if err != nil {
		t.Fatalf("ListTunnels after stop: %v", err)
	}
	if present {
		t.Fatal("tunnel still listed after StopTunnel")
	}
	// Stopping twice is a NotFound, not a silent success — the panel reads it.
	if _, err := client.StopTunnel(ctx, &common.TunnelId{TunnelId: "rpc-e2e-1"}); status.Code(err) != codes.NotFound {
		t.Fatalf("second StopTunnel: code = %v (%v), want NotFound", status.Code(err), err)
	}

	// A spec the adapter refuses comes back as InvalidArgument, not as a
	// half-started tunnel.
	bad := &common.TunnelSpec{
		TunnelId: "rpc-e2e-bad", Tool: "plain", Side: "z", Mode: "relay", Enabled: true,
	}
	if _, err := client.StartTunnel(ctx, bad); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("side z: code = %v (%v), want InvalidArgument", status.Code(err), err)
	}

	// A secret declared by name but absent from the environment is a
	// precondition failure the panel can act on, not a crash.
	declaredNoEnv := &common.TunnelSpec{
		TunnelId: "rpc-e2e-nosecret", Tool: "plain", Side: "a", Mode: "relay",
		Params:      map[string]string{"listen_host": "127.0.0.1", "peer": "127.0.0.1:1"},
		SecretNames: []string{"PLAIN_TOKEN_THAT_IS_NOT_SET"}, Enabled: true,
	}
	if _, err := client.StartTunnel(ctx, declaredNoEnv); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("unset secret: code = %v (%v), want FailedPrecondition", status.Code(err), err)
	}
}
