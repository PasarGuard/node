package rpc

import (
	"context"

	"github.com/pasarguard/node/common"
)

func (s *Service) Start(ctx context.Context, data *common.Backend) (*common.BaseInfoResponse, error) {
	s.LockControl()
	defer s.UnlockControl()

	if err := s.StartOrAttach(ctx, data); err != nil {
		return nil, err
	}

	return s.BaseInfoResponse(), nil
}

func (s *Service) Stop(_ context.Context, _ *common.Empty) (*common.Empty, error) {
	s.LockControl()
	defer s.UnlockControl()

	s.Disconnect()
	return &common.Empty{}, nil
}

func (s *Service) GetBaseInfo(_ context.Context, _ *common.Empty) (*common.BaseInfoResponse, error) {
	return s.BaseInfoResponse(), nil
}
