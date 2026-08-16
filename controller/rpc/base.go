package rpc

import (
	"context"
	"log"

	"github.com/pasarguard/node/common"
)

func (s *Service) Start(ctx context.Context, data *common.Backend) (*common.BaseInfoResponse, error) {
	s.LockControl()
	defer s.UnlockControl()

	if s.Backend() != nil {
		log.Println("New connection, core control access was taken away from previous client.")
		s.Disconnect()
	}

	if err := s.StartBackend(ctx, data); err != nil {
		return nil, err
	}

	s.Connect(data.GetKeepAlive())

	return s.BaseInfoResponse(), nil
}

func (s *Service) Stop(_ context.Context, _ *common.Empty) (*common.Empty, error) {
	s.LockControl()
	defer s.UnlockControl()

	s.Disconnect()
	return nil, nil
}

func (s *Service) GetBaseInfo(_ context.Context, _ *common.Empty) (*common.BaseInfoResponse, error) {
	return s.BaseInfoResponse(), nil
}
