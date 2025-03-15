package backend

import (
	"context"

	"github.com/m03ed/gozargah-node/common"
)

type Backend interface {
	Started() bool
	GetVersion() string
	GetLogs() chan string
	Restart() error
	Shutdown()
	GenerateConfigFile() error
	SyncUser(context.Context, *common.User) error
	SyncUsers(context.Context, []*common.User) error
	GetSysStats(context.Context) (*common.BackendStatsResponse, error)
	GetUsersStats(context.Context, bool) (*common.StatResponse, error)
	GetUserStats(context.Context, string, bool) (*common.StatResponse, error)
	GetUserOnlineStats(context.Context, string) (*common.OnlineStatResponse, error)
	GetUserOnlineIpListStats(context.Context, string) (*common.StatsOnlineIpListResponse, error)
	GetOutboundsStats(context.Context, bool) (*common.StatResponse, error)
	GetOutboundStats(context.Context, string, bool) (*common.StatResponse, error)
	GetInboundsStats(context.Context, bool) (*common.StatResponse, error)
	GetInboundStats(context.Context, string, bool) (*common.StatResponse, error)
}
