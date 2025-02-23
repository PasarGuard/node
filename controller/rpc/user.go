package rpc

import (
	"context"
	"errors"
	"io"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/m03ed/gozargah-node/common"
)

func (s *Service) SyncUser(stream grpc.ClientStreamingServer[common.User, common.Empty]) error {
	for {
		user, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&common.Empty{})
		}
		if err != nil {
			return status.Errorf(codes.Internal, "failed to receive user: %v", err)
		}

		if user.GetEmail() == "" {
			return errors.New("email is required")
		}

		if err = s.controller.GetBackend().SyncUser(stream.Context(), user); err != nil {
			return status.Errorf(codes.Internal, "failed to update user: %v", err)
		}
	}
}

func (s *Service) SyncUsers(ctx context.Context, users *common.Users) (*common.Empty, error) {
	if err := s.controller.GetBackend().SyncUsers(ctx, users.GetUsers()); err != nil {
		return nil, err
	}

	return nil, nil
}
