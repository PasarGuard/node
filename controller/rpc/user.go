package rpc

import (
	"context"
	"github.com/m03ed/marzban-node-go/common"
)

func (s *Service) AddUser(ctx context.Context, user *common.User) (*common.Empty, error) {
	return nil, s.controller.GetBackend().AddUser(ctx, user)
}

func (s *Service) UpdateUser(ctx context.Context, user *common.User) (*common.Empty, error) {
	return nil, s.controller.GetBackend().UpdateUser(ctx, user)
}

func (s *Service) RemoveUser(ctx context.Context, user *common.User) (*common.Empty, error) {
	s.controller.GetBackend().RemoveUser(ctx, user.Email)
	return nil, nil
}
