package rpc

import (
	"context"

	"github.com/m03ed/gozargah-node/common"
)

func (s *Service) GetStats(ctx context.Context, request *common.StatRequest) (*common.StatResponse, error) {
	stats, err := s.Backend().GetStats(ctx, request)
	if err != nil {
		err = common.InterceptNotFound(err)
		return nil, err
	}
	return stats, nil
}

func (s *Service) GetUserOnlineStats(ctx context.Context, request *common.StatRequest) (*common.OnlineStatResponse, error) {
	stats, err := s.Backend().GetUserOnlineStats(ctx, request.GetName())
	if err != nil {
		err = common.InterceptNotFound(err)
		return nil, err
	}
	return stats, nil
}

func (s *Service) GetUserOnlineIpListStats(ctx context.Context, request *common.StatRequest) (*common.StatsOnlineIpListResponse, error) {
	stats, err := s.Backend().GetUserOnlineIpListStats(ctx, request.GetName())
	if err != nil {
		err = common.InterceptNotFound(err)
		return nil, err
	}
	return stats, nil
}

func (s *Service) GetBackendStats(ctx context.Context, _ *common.Empty) (*common.BackendStatsResponse, error) {
	return s.Backend().GetSysStats(ctx)
}

func (s *Service) GetSystemStats(_ context.Context, _ *common.Empty) (*common.SystemStatsResponse, error) {
	return s.SystemStats(), nil
}
