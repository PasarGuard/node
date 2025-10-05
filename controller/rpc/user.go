package rpc

import (
	"context"
	"errors"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pasarguard/node/common"
)

func (s *Service) SyncUser(stream grpc.ClientStreamingServer[common.User, common.Empty]) error {
	for {
		user, err := stream.Recv()
		if err != nil {
			return stream.SendAndClose(&common.Empty{})
		}

		if user.GetEmail() == "" {
			return errors.New("email is required")
		}

		if err = s.Backend().SyncUser(stream.Context(), user); err != nil {
			log.Printf("Error syncing user: %v", err)
			return status.Errorf(codes.Internal, "failed to update user: %v", err)
		}
	}
}

func (s *Service) SyncUsers(ctx context.Context, users *common.Users) (*common.Empty, error) {
	if err := s.Backend().SyncUsers(ctx, users.GetUsers()); err != nil {
		return nil, err
	}

	return nil, nil
}
