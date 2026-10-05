package rpc

// GATE 3 found: StopCore(1) made the whole node unmanageable while cores 2 and 3
// kept serving traffic, because checkBackendStatus gated every unary RPC on the
// DEFAULT core (controller/rpc/middleware.go). The live three-core gate proves
// this against real processes but SKIPS without PG_LIVE_XRAY, so these are the
// deterministic tests that run everywhere.
//
// They drive the real interceptor over a real Controller, so a gate that stops
// routing on core_id fails here rather than only on a machine that happens to
// have all three binaries.

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pasarguard/node/backend"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
)

// gateFake is a started core that reports Stats for whatever it is asked. It is
// deliberately minimal: these tests are about WHICH core the gate consults, and
// nothing else the gate does can change that answer.
type gateFake struct {
	running atomic.Bool
}

func (f *gateFake) Started() bool { return f.running.Load() }
func (f *gateFake) Version() string {
	return "gate-fake"
}
func (f *gateFake) Logs() <-chan string { return make(chan string) }
func (f *gateFake) Restart() error     { return nil }
func (f *gateFake) Shutdown()           { f.running.Store(false) }

func (f *gateFake) SyncUser(context.Context, *common.User) error                  { return nil }
func (f *gateFake) SyncUsers(context.Context, []*common.User) error               { return nil }
func (f *gateFake) UpdateUsers(context.Context, []*common.User) error             { return nil }
func (f *gateFake) UpdateUsersAndRestart(context.Context, []*common.User) error   { return nil }
func (f *gateFake) GetOutboundsLatency(context.Context, *common.LatencyRequest) (*common.LatencyResponse, error) {
	return &common.LatencyResponse{}, nil
}

func (f *gateFake) GetSysStats(context.Context) (*common.BackendStatsResponse, error) {
	return &common.BackendStatsResponse{}, nil
}

func (f *gateFake) GetStats(context.Context, *common.StatRequest) (*common.StatResponse, error) {
	return &common.StatResponse{}, nil
}

func (f *gateFake) GetUserOnlineStats(context.Context, string) (*common.OnlineStatResponse, error) {
	return &common.OnlineStatResponse{}, nil
}

func (f *gateFake) GetUserOnlineIpListStats(context.Context, string) (*common.StatsOnlineIpListResponse, error) {
	return &common.StatsOnlineIpListResponse{}, nil
}

// gateFakeType is a type no real core claims, so registering it here cannot
// disturb the xray/sing-box tests that share this package.
const gateFakeType = common.BackendType(99)

func init() {
	backend.Register(gateFakeType, func(
		_ context.Context, _ *common.Backend, _ backend.Ports, _ *config.Config,
	) (backend.Backend, error) {
		f := &gateFake{}
		f.running.Store(true)
		return f, nil
	})
}

// gateService is a Service over a real Controller, so Backend()/BackendFor()/
// StartedCores() behave exactly as they do in production.
func gateService(t *testing.T) *Service {
	t.Helper()
	return New(config.NewTestConfig(t.TempDir(), uuid.New()))
}

// startGateCores brings up the named cores through the registered seam, exactly
// as the controller does for a real Start.
func startGateCores(t *testing.T, s *Service, ids ...uint64) {
	t.Helper()
	for _, id := range ids {
		s.LockControl(id)
		err := s.StartOrAttach(context.Background(), &common.Backend{
			Type: gateFakeType, CoreId: id, KeepAlive: 0,
		})
		s.UnlockControl(id)
		if err != nil {
			t.Fatalf("start core %d: %v", id, err)
		}
	}
	t.Cleanup(s.Disconnect)
}

// gateCode runs a request through the real unary gate and reports the code.
func gateCode(t *testing.T, s *Service, req any) codes.Code {
	t.Helper()
	interceptor := CheckBackendMiddleware(s)
	handler := func(context.Context, any) (any, error) { return &common.Empty{}, nil }
	info := &grpc.UnaryServerInfo{FullMethod: "/service.NodeService/GetStats"}
	_, err := interceptor(context.Background(), req, info, handler)
	return status.Code(err)
}

// TestPerCoreGateFollowsTheRequestedCore is GATE 3 at the RPC layer: with core 1
// stopped and cores 2 and 3 alive, a request naming core 2 must be allowed and a
// request naming core 1 must not.
func TestPerCoreGateFollowsTheRequestedCore(t *testing.T) {
	s := gateService(t)
	startGateCores(t, s, 1, 2, 3)

	for _, id := range []uint64{1, 2, 3} {
		if got := gateCode(t, s, &common.StatRequest{CoreId: id}); got != codes.OK {
			t.Fatalf("core %d running but its own stats call was refused: %v", id, got)
		}
	}

	s.DisconnectCore(1)

	for _, id := range []uint64{2, 3} {
		if got := gateCode(t, s, &common.StatRequest{CoreId: id, Type: common.StatType_UsersStat}); got != codes.OK {
			t.Errorf("GATE 3 DEFECT: core %d is still serving but its RPC was refused: %v. "+
				"The gate must route on the request's core_id, not on the default core.", id, got)
		}
	}

	// And the stopped core is genuinely refused, so the gate is not simply open.
	if got := gateCode(t, s, &common.StatRequest{CoreId: 1}); got == codes.OK {
		t.Error("a request for the stopped core 1 was allowed; the gate has stopped checking at all")
	}
}

// TestCoreIDZeroStillMeansTheDefaultCore is CONTRACT §1.2, and the reason this
// fix is a routing change rather than a behaviour change: a request naming no
// core must behave byte-for-byte as it did on a single-core node, including
// being refused when the default core is down.
func TestCoreIDZeroStillMeansTheDefaultCore(t *testing.T) {
	s := gateService(t)
	startGateCores(t, s, 1, 2)

	for _, req := range []any{&common.StatRequest{}, &common.Empty{}} {
		if got := gateCode(t, s, req); got != codes.OK {
			t.Errorf("core_id 0 with the default core running was refused: %v", got)
		}
	}

	s.DisconnectCore(1)

	if got := gateCode(t, s, &common.Empty{}); got == codes.OK {
		t.Error("core_id 0 was allowed with the default core stopped; core_id 0 must behave " +
			"exactly as it did before (CONTRACT §1.2). The per-core requests above still pass, " +
			"so this is the default-core rule holding, not the gate being disabled.")
	}
}

// TestAggregateStatsNeedsAnyRunningCore: GetStats with core_id 0 is the
// documented sum across every running core (CONTRACT §3.2), not the default
// core's reading. So it must survive core 1 being stopped — that is what lets the
// panel keep billing a multi-core node whose default core is down.
func TestAggregateStatsNeedsAnyRunningCore(t *testing.T) {
	s := gateService(t)
	startGateCores(t, s, 1, 2, 3)
	s.DisconnectCore(1)

	req := &common.StatRequest{CoreId: 0, Type: common.StatType_UsersStat}
	interceptor := CheckStatsBackendMiddleware(s)
	handler := func(context.Context, any) (any, error) { return &common.Empty{}, nil }
	info := &grpc.UnaryServerInfo{FullMethod: "/service.NodeService/GetStats"}

	if _, err := interceptor(context.Background(), req, info, handler); err != nil {
		t.Errorf("GATE 3 DEFECT: the core_id 0 aggregate was refused while cores 2 and 3 "+
			"were running: %v. CONTRACT §3.2 makes it the sum across every running core, so it "+
			"needs A core running, not the default core.", err)
	}

	// With every core down it is still refused, so the aggregate rule did not
	// turn the gate off.
	s.Disconnect()
	if _, err := interceptor(context.Background(), req, info, handler); err == nil {
		t.Error("the aggregate stats call was allowed with no core running at all")
	}
}

// TestStopCoreIsNotRefusedByItsOwnGate: StopCore asks to stop a core, so
// requiring that core to be running would refuse an already-idempotent call.
func TestStopCoreIsNotRefusedByItsOwnGate(t *testing.T) {
	s := gateService(t)
	startGateCores(t, s, 1, 2)

	if got := gateCode(t, s, &common.StopCore{CoreId: 1}); got != codes.OK {
		t.Errorf("StopCore(1) was refused while core 1 was running: %v", got)
	}

	s.DisconnectCore(1)
	if got := gateCode(t, s, &common.StopCore{CoreId: 1}); got != codes.OK {
		t.Errorf("StopCore(1) on an already-stopped core was refused: %v", got)
	}
}

// TestNamedCoreThatWasNeverStartedIsRefused: routing on core_id must not turn a
// typo or a stale panel into an empty answer.
func TestNamedCoreThatWasNeverStartedIsRefused(t *testing.T) {
	s := gateService(t)
	startGateCores(t, s, 1)

	if got := gateCode(t, s, &common.StatRequest{CoreId: 99}); got == codes.OK {
		t.Error("a request naming core 99, which does not exist, was allowed")
	}
}

// TestNoCoreRunningIsStillRefused: the gate must not have been disabled for the
// node-level case it was written for.
func TestNoCoreRunningIsStillRefused(t *testing.T) {
	s := gateService(t)

	for _, req := range []any{&common.Empty{}, &common.StatRequest{}, &common.StopCore{CoreId: 1}} {
		if got := gateCode(t, s, req); got == codes.OK {
			t.Errorf("request %T was allowed with no core running at all", req)
		}
	}
}