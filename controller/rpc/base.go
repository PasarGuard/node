package rpc

import (
	"context"
	"errors"
	"github.com/m03ed/gozargah-node/backend"
	"github.com/m03ed/gozargah-node/backend/xray"
	"github.com/m03ed/gozargah-node/common"
)

func (s *Service) Start(ctx context.Context, detail *common.Backend) (*common.BaseInfoResponse, error) {
	ctx, err := s.detectBackend(ctx, detail)
	if err != nil {
		return nil, err
	}

	if err = s.controller.StartBackend(ctx, detail.GetType()); err != nil {
		return nil, err
	}

	s.connect(detail.GetKeepAlive())

	return s.controller.BaseInfoResponse(true, ""), nil
}

func (s *Service) Stop(_ context.Context, _ *common.Empty) (*common.Empty, error) {
	s.disconnect()
	return nil, nil
}

func (s *Service) detectBackend(ctx context.Context, detail *common.Backend) (context.Context, error) {
	if detail.GetType() == common.BackendType_XRAY {
		config, err := xray.NewXRayConfig(detail.GetConfig())
		if err != nil {
			return nil, err
		}
		ctx = context.WithValue(ctx, backend.ConfigKey{}, config)
	} else {
		return nil, errors.New("unknown backend type")
	}

	ctx = context.WithValue(ctx, backend.UsersKey{}, detail.GetUsers())

	return ctx, nil
}

func (s *Service) GetBaseInfo(_ context.Context, _ *common.Empty) (*common.BaseInfoResponse, error) {
	return s.controller.BaseInfoResponse(false, ""), nil
}
