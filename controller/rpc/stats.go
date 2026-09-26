package rpc

import (
	"context"

	"github.com/pasarguard/node/backend"
	"github.com/pasarguard/node/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Service) backend() (backend.Backend, error) {
	backend := s.Backend()
	if backend == nil {
		return nil, status.Errorf(codes.Unavailable, "backend not initialized")
	}
	return backend, nil
}

func (s *Service) GetStats(ctx context.Context, request *common.StatRequest) (*common.StatResponse, error) {
	stats, err := s.Controller.GetStats(ctx, request)
	if err != nil {
		err = common.InterceptNotFound(err)
		return nil, err
	}
	return stats, nil
}

func (s *Service) CollectUsage(ctx context.Context, request *common.UsageRequest) (*common.UsageReceipt, error) {
	return s.Controller.CollectUsage(ctx, request)
}

func (s *Service) AcknowledgeUsage(ctx context.Context, request *common.UsageAck) (*common.Empty, error) {
	return s.Controller.AcknowledgeUsage(ctx, request)
}

func (s *Service) GetUserOnlineStats(ctx context.Context, request *common.StatRequest) (*common.OnlineStatResponse, error) {
	backend, err := s.backend()
	if err != nil {
		return nil, err
	}

	stats, err := backend.GetUserOnlineStats(ctx, request.GetName())
	if err != nil {
		err = common.InterceptNotFound(err)
		return nil, err
	}
	return stats, nil
}

func (s *Service) GetUserOnlineIpListStats(ctx context.Context, request *common.StatRequest) (*common.StatsOnlineIpListResponse, error) {
	backend, err := s.backend()
	if err != nil {
		return nil, err
	}

	stats, err := backend.GetUserOnlineIpListStats(ctx, request.GetName())
	if err != nil {
		err = common.InterceptNotFound(err)
		return nil, err
	}
	return stats, nil
}

func (s *Service) GetBackendStats(ctx context.Context, _ *common.Empty) (*common.BackendStatsResponse, error) {
	backend, err := s.backend()
	if err != nil {
		return nil, err
	}

	return backend.GetSysStats(ctx)
}

func (s *Service) GetOutboundsLatency(ctx context.Context, request *common.LatencyRequest) (*common.LatencyResponse, error) {
	return s.OutboundsLatency(ctx, request)
}

func (s *Service) GetSystemStats(ctx context.Context, _ *common.Empty) (*common.SystemStatsResponse, error) {
	return s.SystemStats(ctx), nil
}
