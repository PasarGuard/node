package rpc

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
)

func TestRoutingMethodsAreBackendGated(t *testing.T) {
	methods := []string{
		"/service.NodeService/ListRoutingRules",
		"/service.NodeService/GetBalancerInfo",
		"/service.NodeService/TestRoute",
		"/service.NodeService/AddRoutingRule",
		"/service.NodeService/RemoveRoutingRule",
		"/service.NodeService/OverrideBalancerTarget",
	}
	for _, m := range methods {
		if !backendMethods[m] {
			t.Errorf("%s missing from backendMethods (skips backend-started gating)", m)
		}
	}
}

func newKeepAliveTestService(t *testing.T) (*Service, uuid.UUID) {
	t.Helper()
	key := uuid.New()
	s := New(config.NewTestConfig(t.TempDir(), key))
	t.Cleanup(s.Disconnect)
	return s, key
}

func withAPIKey(key string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-api-key", key))
}

type fakeServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (f *fakeServerStream) Context() context.Context { return f.ctx }

// Any call the panel makes proves the panel is alive, even one that fails or
// is still running, so keep-alive counts it when it arrives.
func TestKeepAliveRefreshedWhenAuthenticatedCallArrives(t *testing.T) {
	s, key := newKeepAliveTestService(t)

	info := &grpc.UnaryServerInfo{FullMethod: "/service.NodeService/GetBaseInfo"}
	var atArrival time.Time
	_, err := ConditionalMiddleware(s)(withAPIKey(key.String()), &common.Empty{}, info, func(context.Context, any) (any, error) {
		atArrival = s.LastRequest()
		return nil, status.Error(codes.NotFound, "user not found.")
	})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("err = %v, want NotFound", err)
	}
	if atArrival.IsZero() {
		t.Fatal("keep-alive was not refreshed when the call arrived")
	}
}

func TestKeepAliveRefreshedWhenBackendGateRejects(t *testing.T) {
	s, key := newKeepAliveTestService(t)

	info := &grpc.UnaryServerInfo{FullMethod: "/service.NodeService/GetBackendStats"}
	_, err := ConditionalMiddleware(s)(withAPIKey(key.String()), &common.Empty{}, info, func(context.Context, any) (any, error) {
		t.Error("handler ran without a backend")
		return nil, nil
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("err = %v, want Unavailable", err)
	}
	if s.LastRequest().IsZero() {
		t.Fatal("keep-alive was not refreshed for an authenticated call the backend gate rejected")
	}
}

func TestKeepAliveNotRefreshedWithoutValidKey(t *testing.T) {
	s, _ := newKeepAliveTestService(t)

	cases := map[string]context.Context{
		"no metadata":   context.Background(),
		"no key header": metadata.NewIncomingContext(context.Background(), metadata.Pairs("other", "x")),
		"not a uuid":    withAPIKey("not-a-uuid"),
		"wrong key":     withAPIKey(uuid.NewString()),
	}
	info := &grpc.UnaryServerInfo{FullMethod: "/service.NodeService/GetBaseInfo"}
	streamInfo := &grpc.StreamServerInfo{FullMethod: "/service.NodeService/GetLogs", IsServerStream: true}
	for name, ctx := range cases {
		_, err := ConditionalMiddleware(s)(ctx, &common.Empty{}, info, func(context.Context, any) (any, error) {
			return &common.Empty{}, nil
		})
		if err == nil {
			t.Fatalf("%s: unary call passed auth", name)
		}
		err = ConditionalStreamMiddleware(s)(nil, &fakeServerStream{ctx: ctx}, streamInfo, func(any, grpc.ServerStream) error {
			return nil
		})
		if err == nil {
			t.Fatalf("%s: stream passed auth", name)
		}
		if !s.LastRequest().IsZero() {
			t.Fatalf("%s: an unauthenticated call refreshed keep-alive", name)
		}
	}
}

func TestKeepAliveRefreshedWhenStreamOpensAndEnds(t *testing.T) {
	s, key := newKeepAliveTestService(t)

	// An ungated method, so the handler runs without a backend.
	info := &grpc.StreamServerInfo{FullMethod: "/service.NodeService/Ungated", IsServerStream: true}
	var atArrival time.Time
	err := ConditionalStreamMiddleware(s)(nil, &fakeServerStream{ctx: withAPIKey(key.String())}, info, func(any, grpc.ServerStream) error {
		atArrival = s.LastRequest()
		time.Sleep(10 * time.Millisecond)
		// The panel went away mid-stream.
		return status.Error(codes.Canceled, "context canceled")
	})
	if status.Code(err) != codes.Canceled {
		t.Fatalf("err = %v, want Canceled", err)
	}
	if atArrival.IsZero() {
		t.Fatal("keep-alive was not refreshed when the stream opened")
	}
	if !s.LastRequest().After(atArrival) {
		t.Fatal("keep-alive was not refreshed when the stream ended")
	}
}
