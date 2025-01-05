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

func (s *Service) SyncUsers(ctx context.Context, users *common.Users) (*common.Empty, error) {
	if err := s.controller.GetBackend().SyncUsers(ctx, users.GetUsers()); err != nil {
		return nil, err
	}

	return nil, nil
}
