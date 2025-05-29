package rpc

import (
	"context"

	"github.com/m03ed/gozargah-node/common"
)

func (s *Service) GetStats(ctx context.Context, request *common.StatRequest) (*common.StatResponse, error) {
	return s.GetBackend().GetStats(ctx, request)
}

func (s *Service) GetUserOnlineStats(ctx context.Context, request *common.StatRequest) (*common.OnlineStatResponse, error) {
	return s.GetBackend().GetUserOnlineStats(ctx, request.GetName())
}

func (s *Service) GetUserOnlineIpListStats(ctx context.Context, request *common.StatRequest) (*common.StatsOnlineIpListResponse, error) {
	return s.GetBackend().GetUserOnlineIpListStats(ctx, request.GetName())
}

func (s *Service) GetBackendStats(ctx context.Context, _ *common.Empty) (*common.BackendStatsResponse, error) {
	return s.GetBackend().GetSysStats(ctx)
}

func (s *Service) GetSystemStats(_ context.Context, _ *common.Empty) (*common.SystemStatsResponse, error) {
	return s.SystemStats(), nil
}
