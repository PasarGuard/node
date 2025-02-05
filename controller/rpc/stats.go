package rpc

import (
	"context"

	"github.com/m03ed/marzban-node-go/common"
)

func (s *Service) GetOutboundsStats(ctx context.Context, _ *common.Empty) (*common.StatResponse, error) {
	return s.controller.GetBackend().GetOutboundsStats(ctx, true)
}

func (s *Service) GetOutboundStats(ctx context.Context, request *common.StatRequest) (*common.StatResponse, error) {
	return s.controller.GetBackend().GetOutboundStats(ctx, request.GetName(), true)
}

func (s *Service) GetInboundsStats(ctx context.Context, _ *common.Empty) (*common.StatResponse, error) {
	return s.controller.GetBackend().GetInboundsStats(ctx, true)
}

func (s *Service) GetInboundStats(ctx context.Context, request *common.StatRequest) (*common.StatResponse, error) {
	return s.controller.GetBackend().GetInboundStats(ctx, request.GetName(), true)
}

func (s *Service) GetUsersStats(ctx context.Context, _ *common.Empty) (*common.StatResponse, error) {
	return s.controller.GetBackend().GetUsersStats(ctx, true)
}

func (s *Service) GetUserStats(ctx context.Context, request *common.StatRequest) (*common.StatResponse, error) {
	return s.controller.GetBackend().GetUserStats(ctx, request.GetName(), true)
}

func (s *Service) GetUserOnlineStats(ctx context.Context, request *common.StatRequest) (*common.OnlineStatResponse, error) {
	return s.controller.GetBackend().GetStatOnline(ctx, request.GetName())
}

func (s *Service) GetBackendStats(ctx context.Context, _ *common.Empty) (*common.BackendStatsResponse, error) {
	return s.controller.GetBackend().GetSysStats(ctx)
}

func (s *Service) GetSystemStats(_ context.Context, _ *common.Empty) (*common.SystemStatsResponse, error) {
	return s.controller.GetStats(), nil
}
