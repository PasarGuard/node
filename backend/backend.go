package backend

import (
	"context"

	"github.com/pasarguard/node/common"
)

type Backend interface {
	Started() bool
	Version() string
	Logs() chan string
	Restart() error
	Shutdown()
	SyncUser(context.Context, *common.User) error
	SyncUsers(context.Context, []*common.User) error
	GetSysStats(context.Context) (*common.BackendStatsResponse, error)
	GetStats(context.Context, *common.StatRequest) (*common.StatResponse, error)
	GetUserOnlineStats(context.Context, string) (*common.OnlineStatResponse, error)
	GetUserOnlineIpListStats(context.Context, string) (*common.StatsOnlineIpListResponse, error)
}

type ConfigKey struct{}

type UsersKey struct{}
