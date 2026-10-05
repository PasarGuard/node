package rpc

import (
	"context"

	"github.com/pasarguard/node/common"
)

func (s *Service) Start(ctx context.Context, data *common.Backend) (*common.BaseInfoResponse, error) {
	s.LockControl(data.GetCoreId())
	defer s.UnlockControl(data.GetCoreId())

	if err := s.StartOrAttach(ctx, data); err != nil {
		return nil, err
	}

	return s.BaseInfoResponse(), nil
}

// Stop stops every core — unchanged behaviour for a single-core node.
func (s *Service) Stop(_ context.Context, _ *common.Empty) (*common.Empty, error) {
	s.LockControl(0)
	defer s.UnlockControl(0)

	s.Disconnect()
	return &common.Empty{}, nil
}

// StopCore stops one core and leaves the rest running.
func (s *Service) StopCore(_ context.Context, request *common.StopCore) (*common.Empty, error) {
	s.LockControl(request.GetCoreId())
	defer s.UnlockControl(request.GetCoreId())

	s.DisconnectCore(request.GetCoreId())
	return &common.Empty{}, nil
}

func (s *Service) GetBaseInfo(_ context.Context, _ *common.Empty) (*common.BaseInfoResponse, error) {
	return s.BaseInfoResponse(), nil
}
