package rpc

import (
	"context"
	"errors"
	"io"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/controller"
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

		log.Printf("Got user: %v", user.GetEmail())

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

func (s *Service) SyncUsersChunked(stream grpc.ClientStreamingServer[common.UsersChunk, common.Empty]) error {
	chunks := make(map[uint64][]*common.User)
	var (
		lastIndex uint64
		sawLast   bool
	)

	for {
		chunk, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return status.Errorf(codes.Internal, "failed to receive chunk: %v", err)
		}

		chunks[chunk.GetIndex()] = append(chunks[chunk.GetIndex()], chunk.GetUsers()...)

		if chunk.GetLast() {
			sawLast = true
			lastIndex = chunk.GetIndex()
			break
		}
	}

	users, err := controller.BuildUsersFromChunks(chunks, lastIndex, sawLast)
	if err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}

	if err := s.Backend().SyncUsers(stream.Context(), users); err != nil {
		return status.Errorf(codes.Internal, "failed to sync users: %v", err)
	}

	return stream.SendAndClose(&common.Empty{})
}
