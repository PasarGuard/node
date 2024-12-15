package rpc

import (
	"context"

	"github.com/m03ed/marzban-node-go/common"
)

func (s *Service) GetOutboundsStats(ctx context.Context, _ *common.Empty) (*common.StatResponse, error) {
	return s.controller.GetBackend().GetOutboundsStats(ctx, true)
}

func (s *Service) GetInboundsStats(ctx context.Context, _ *common.Empty) (*common.StatResponse, error) {
	return s.controller.GetBackend().GetInboundsStats(ctx, true)
}

func (s *Service) GetUsersStats(ctx context.Context, _ *common.Empty) (*common.StatResponse, error) {
	return s.controller.GetBackend().GetUsersStats(ctx, true)
}

func (s *Service) GetUserOnlineStat(ctx context.Context, request *common.OnlineStatRequest) (*common.OnlineStatResponse, error) {
	return s.controller.GetBackend().GetStatOnline(ctx, request.GetEmail())
}

func (s *Service) GetBackendStats(ctx context.Context, _ *common.Empty) (*common.BackendStatsResponse, error) {
	return s.controller.GetBackend().GetSysStats(ctx)
}

func (s *Service) GetNodeStats(_ context.Context, _ *common.Empty) (*common.SystemStatsResponse, error) {
	return s.controller.GetStats(), nil
}
