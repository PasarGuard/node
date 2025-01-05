package backend

import (
	"context"

	"github.com/m03ed/marzban-node-go/common"
)

type Backend interface {
	Started() bool
	GetVersion() string
	GetLogs() chan string
	Restart() error
	Shutdown()
	GenerateConfigFile() error
	AddUser(context.Context, *common.User) error
	UpdateUser(context.Context, *common.User) error
	RemoveUser(context.Context, string)
	SyncUsers(context.Context, []*common.User) error
	GetSysStats(context.Context) (*common.BackendStatsResponse, error)
	GetUsersStats(context.Context, bool) (*common.StatResponse, error)
	GetStatOnline(context.Context, string) (*common.OnlineStatResponse, error)
	GetOutboundsStats(context.Context, bool) (*common.StatResponse, error)
	GetInboundsStats(context.Context, bool) (*common.StatResponse, error)
}
