package xray

import (
	"context"
	"errors"

	"github.com/pasarguard/node/common"
)

func (x *Xray) GetSysStats(ctx context.Context) (*common.BackendStatsResponse, error) {
	return x.handler.GetSysStats(ctx)
}

func (x *Xray) GetUserOnlineStats(ctx context.Context, email string) (*common.OnlineStatResponse, error) {
	return x.handler.GetUserOnlineStats(ctx, email)
}

func (x *Xray) GetUserOnlineIpListStats(ctx context.Context, email string) (*common.StatsOnlineIpListResponse, error) {
	return x.handler.GetUserOnlineIpListStats(ctx, email)
}

func (x *Xray) GetStats(ctx context.Context, request *common.StatRequest) (*common.StatResponse, error) {
	switch request.GetType() {

	case common.StatType_Outbounds:
		return x.handler.GetOutboundsStats(ctx, request.GetReset_())
	case common.StatType_Outbound:
		return x.handler.GetOutboundStats(ctx, request.GetName(), request.GetReset_())

	case common.StatType_Inbounds:
		return x.handler.GetInboundsStats(ctx, request.GetReset_())
	case common.StatType_Inbound:
		return x.handler.GetInboundStats(ctx, request.GetName(), request.GetReset_())

	case common.StatType_UsersStat:
		return x.handler.GetUsersStats(ctx, request.GetReset_())
	case common.StatType_UserStat:
		return x.handler.GetUserStats(ctx, request.GetName(), request.GetReset_())

	default:
		return nil, errors.New("not implemented stat type")
	}
}
