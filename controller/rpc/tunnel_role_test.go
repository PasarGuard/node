package rpc

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
)

func testService(t *testing.T, role common.NodeRole) (*Service, context.Context) {
	t.Helper()
	cfg := config.NewTestConfig(t.TempDir(), uuid.New())
	cfg.Role = role
	s := New(cfg)
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("x-api-key", cfg.ApiKey.String()))
	return s, ctx
}

// TestRoleGateRefusesCoreRPCsOnTunnelNode is Phase 1 defect #2 handled
// deliberately: every core-facing unary RPC was gated on the default core,
// which a tunnel node does not have. The gate now answers with the role
// refusal — and Start, which was never in backendMethods at all, is refused
// too. The handler must not run.
func TestRoleGateRefusesCoreRPCsOnTunnelNode(t *testing.T) {
	s, ctx := testService(t, common.NodeRole_NODE_ROLE_TUNNEL)
	interceptor := ConditionalMiddleware(s)

	for _, method := range []string{
		"/service.NodeService/Start",
		"/service.NodeService/SyncUsers",
		"/service.NodeService/SyncUser",
		"/service.NodeService/GetStats",
		"/service.NodeService/GetLogs",
	} {
		called := false
		_, err := interceptor(ctx, &common.Backend{}, &grpc.UnaryServerInfo{FullMethod: method},
			func(context.Context, any) (any, error) { called = true; return nil, nil })

		st, _ := status.FromError(err)
		if st.Code() != codes.FailedPrecondition {
			t.Fatalf("%s: code = %v (%v), want FailedPrecondition", method, st.Code(), err)
		}
		if !strings.Contains(st.Message(), "tunnel") {
			t.Fatalf("%s: message %q does not state the tunnel role", method, st.Message())
		}
		if called {
			t.Fatalf("%s: handler ran on a tunnel node", method)
		}
	}
}

// TestRoleGateLetsTunnelRPCsThrough: the four tunnel RPCs are the whole point
// of a tunnel node — the role gate must not touch them.
func TestRoleGateLetsTunnelRPCsThrough(t *testing.T) {
	s, ctx := testService(t, common.NodeRole_NODE_ROLE_TUNNEL)
	interceptor := ConditionalMiddleware(s)

	for _, method := range []string{
		"/service.NodeService/StartTunnel",
		"/service.NodeService/StopTunnel",
		"/service.NodeService/ListTunnels",
		"/service.NodeService/GetBaseInfo",
	} {
		called := false
		_, err := interceptor(ctx, &common.Empty{}, &grpc.UnaryServerInfo{FullMethod: method},
			func(context.Context, any) (any, error) { called = true; return nil, nil })
		if err != nil {
			t.Fatalf("%s: role gate refused a tunnel RPC: %v", method, err)
		}
		if !called {
			t.Fatalf("%s: handler did not run", method)
		}
	}
}

// TestRoleGateRunsAfterApiKey: an unauthenticated caller must not learn
// anything about the node's role.
func TestRoleGateRunsAfterApiKey(t *testing.T) {
	s, _ := testService(t, common.NodeRole_NODE_ROLE_TUNNEL)
	interceptor := ConditionalMiddleware(s)

	badKey := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("x-api-key", uuid.New().String()))
	_, err := interceptor(badKey, &common.Backend{}, &grpc.UnaryServerInfo{FullMethod: "/service.NodeService/SyncUsers"},
		func(context.Context, any) (any, error) { return nil, nil })
	st, _ := status.FromError(err)
	if st.Code() != codes.PermissionDenied {
		t.Fatalf("wrong api key: code = %v, want PermissionDenied (%v)", st.Code(), err)
	}
}

// TestProxyNodeGateUnchanged: on a proxy node with no core started the
// message stays "backend not initialized" — the role work changes nothing
// for every existing row (CONTRACT §1.7 default).
func TestProxyNodeGateUnchanged(t *testing.T) {
	s, ctx := testService(t, common.NodeRole_NODE_ROLE_PROXY)
	interceptor := ConditionalMiddleware(s)

	_, err := interceptor(ctx, &common.Backend{}, &grpc.UnaryServerInfo{FullMethod: "/service.NodeService/GetStats"},
		func(context.Context, any) (any, error) { return nil, nil })
	st, _ := status.FromError(err)
	if st.Code() != codes.Unavailable || !strings.Contains(st.Message(), "backend not initialized") {
		t.Fatalf("proxy node gate changed: code=%v msg=%q", st.Code(), st.Message())
	}
}
