package rpc

import (
	"context"
	"errors"

	"github.com/m03ed/gozargah-node/common"
)

func (s *Service) GetOutboundsStats(ctx context.Context, request *common.StatRequest) (*common.StatResponse, error) {
	return s.GetBackend().GetOutboundsStats(ctx, request.GetReset_())
}

func (s *Service) GetOutboundStats(ctx context.Context, request *common.StatRequest) (*common.StatResponse, error) {
	if request.GetName() == "" {
		return nil, errors.New("name is required")
	}
	return s.GetBackend().GetOutboundStats(ctx, request.GetName(), request.GetReset_())
}

func (s *Service) GetInboundsStats(ctx context.Context, request *common.StatRequest) (*common.StatResponse, error) {
	return s.GetBackend().GetInboundsStats(ctx, request.GetReset_())
}

func (s *Service) GetInboundStats(ctx context.Context, request *common.StatRequest) (*common.StatResponse, error) {
	if request.GetName() == "" {
		return nil, errors.New("name is required")
	}
	return s.GetBackend().GetInboundStats(ctx, request.GetName(), request.GetReset_())
}

func (s *Service) GetUsersStats(ctx context.Context, request *common.StatRequest) (*common.StatResponse, error) {
	return s.GetBackend().GetUsersStats(ctx, request.GetReset_())
}

func (s *Service) GetUserStats(ctx context.Context, request *common.StatRequest) (*common.StatResponse, error) {
	if request.GetName() == "" {
		return nil, errors.New("name is required")
	}
	return s.GetBackend().GetUserStats(ctx, request.GetName(), request.GetReset_())
}

func (s *Service) GetUserOnlineStats(ctx context.Context, request *common.StatRequest) (*common.OnlineStatResponse, error) {
	if request.GetName() == "" {
		return nil, errors.New("name is required")
	}
	return s.GetBackend().GetUserOnlineStats(ctx, request.GetName())
}

func (s *Service) GetUserOnlineIpListStats(ctx context.Context, request *common.StatRequest) (*common.StatsOnlineIpListResponse, error) {
	if request.GetName() == "" {
		return nil, errors.New("name is required")
	}
	return s.GetBackend().GetUserOnlineIpListStats(ctx, request.GetName())
}

func (s *Service) GetBackendStats(ctx context.Context, _ *common.Empty) (*common.BackendStatsResponse, error) {
	return s.GetBackend().GetSysStats(ctx)
}

func (s *Service) GetSystemStats(_ context.Context, _ *common.Empty) (*common.SystemStatsResponse, error) {
	return s.GetStats(), nil
}
