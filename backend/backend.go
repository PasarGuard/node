package backend

import (
	"context"

	"github.com/pasarguard/node/common"
)

type Backend interface {
	Started() bool
	Version() string
	Logs() <-chan string
	Restart() error
	Shutdown()
	SyncUser(context.Context, *common.User) error
	SyncUsers(context.Context, []*common.User) error
	UpdateUsers(context.Context, []*common.User) error
	UpdateUsersAndRestart(context.Context, []*common.User) error
	GetSysStats(context.Context) (*common.BackendStatsResponse, error)
	GetStats(context.Context, *common.StatRequest) (*common.StatResponse, error)
	GetOutboundsLatency(context.Context, *common.LatencyRequest) (*common.LatencyResponse, error)
	GetUserOnlineStats(context.Context, string) (*common.OnlineStatResponse, error)
	GetUserOnlineIpListStats(context.Context, string) (*common.StatsOnlineIpListResponse, error)
}

// RoutingBackend is implemented by backends that expose xray RoutingService.
// Only *xray.Xray implements it; controller handlers type-assert it and return
// codes.Unimplemented for backends that do not (e.g. WireGuard).
type RoutingBackend interface {
	ListRoutingRules(ctx context.Context) (*common.RoutingRulesResponse, error)
	GetBalancerInfo(ctx context.Context, tag string) (*common.BalancerInfoResponse, error)
	TestRoute(ctx context.Context, req *common.TestRouteRequest) (*common.RouteResult, error)
	AddRoutingRule(ctx context.Context, ruleJSON string, shouldAppend bool) error
	RemoveRoutingRule(ctx context.Context, ruleTag string) error
	OverrideBalancerTarget(ctx context.Context, balancerTag, target string) error
}

type ConfigKey struct{}

type UsersKey struct{}
