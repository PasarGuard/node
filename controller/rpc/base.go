package rpc

import (
	"context"

	"github.com/pasarguard/node/backend"
	"github.com/pasarguard/node/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// backend resolves the default core (core_id 0 / core 1). Every RPC that
// carried no core selector keeps calling it, so its behaviour is unchanged.
func (s *Service) backend() (backend.Backend, error) {
	b := s.Backend()
	if b == nil {
		return nil, status.Errorf(codes.Unavailable, "backend not initialized")
	}
	return b, nil
}

// backendFor resolves one core for a request that carries a core_id.
func (s *Service) backendFor(coreID uint64) (backend.Backend, error) {
	b, ok := s.BackendFor(coreID)
	if !ok {
		return nil, status.Errorf(codes.Unavailable, "core %d is not running", coreID)
	}
	return b, nil
}

// GetStats answers one core's request, or the sum across every core when
// core_id is 0 (CONTRACT §3.2).
func (s *Service) GetStats(ctx context.Context, request *common.StatRequest) (*common.StatResponse, error) {
	if request.GetCoreId() != 0 {
		b, err := s.backendFor(request.GetCoreId())
		if err != nil {
			return nil, err
		}
		return b.GetStats(ctx, request)
	}

	stats, err := s.Stats(ctx, request)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "%v", err)
	}
	return stats, nil
}

func (s *Service) GetUserOnlineStats(ctx context.Context, request *common.StatRequest) (*common.OnlineStatResponse, error) {
	backend, err := s.backendFor(request.GetCoreId())
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
	backend, err := s.backendFor(request.GetCoreId())
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
