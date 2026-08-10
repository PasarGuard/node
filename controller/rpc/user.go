package rpc

import (
	"context"
	"errors"
	"io"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/controller"
)

func addUserSyncStreamPayload(total int64, message proto.Message) (int64, error) {
	next := total + int64(proto.Size(message))
	if next > common.MaxProtoBodyBytes {
		return total, status.Error(codes.ResourceExhausted, "user sync stream payload too large")
	}
	return next, nil
}

func (s *Service) SyncUser(stream grpc.ClientStreamingServer[common.User, common.Empty]) error {
	users := make([]*common.User, 0)
	var epochBatch controller.UserSyncEpochBatch
	var streamBytes int64

	for {
		user, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return status.Errorf(codes.Internal, "failed to receive user: %v", err)
		}

		if user.GetEmail() == "" {
			return errors.New("email is required")
		}
		streamBytes, err = addUserSyncStreamPayload(streamBytes, user)
		if err != nil {
			return err
		}
		if err = epochBatch.Add(user.GetUserSyncEpoch()); err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}

		log.Printf("Got user: %v", user.GetEmail())
		users = append(users, user)
	}

	if len(users) == 0 {
		return stream.SendAndClose(&common.Empty{})
	}

	if err := s.ApplyUserSyncEpoch(epochBatch.Epoch(), func() error {
		back, err := s.backend()
		if err != nil {
			return err
		}
		for _, user := range users {
			if err = back.SyncUser(stream.Context(), user); err != nil {
				log.Printf("Error syncing user: %v", err)
				return status.Errorf(codes.Internal, "failed to update user: %v", err)
			}
		}
		return nil
	}); err != nil {
		return userSyncError(err)
	}

	return stream.SendAndClose(&common.Empty{})
}

func (s *Service) SyncUsers(ctx context.Context, users *common.Users) (*common.Empty, error) {
	if err := s.ApplyUserSyncEpoch(users.GetUserSyncEpoch(), func() error {
		back, err := s.backend()
		if err != nil {
			return err
		}
		return back.SyncUsers(ctx, users.GetUsers())
	}); err != nil {
		return nil, userSyncError(err)
	}

	return &common.Empty{}, nil
}

func (s *Service) SyncUsersChunked(stream grpc.ClientStreamingServer[common.UsersChunk, common.Empty]) error {
	chunks := make(map[uint64][]*common.User)
	var (
		lastIndex   uint64
		sawLast     bool
		epochBatch  controller.UserSyncEpochBatch
		streamBytes int64
	)

	for {
		chunk, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return status.Errorf(codes.Internal, "failed to receive chunk: %v", err)
		}
		streamBytes, err = addUserSyncStreamPayload(streamBytes, chunk)
		if err != nil {
			return err
		}
		if err = epochBatch.Add(chunk.GetUserSyncEpoch()); err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
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

	if err := s.ApplyUserSyncEpoch(epochBatch.Epoch(), func() error {
		back, err := s.backend()
		if err != nil {
			return err
		}
		if err = controller.ApplyChunkedUserUpdate(stream.Context(), back, users); err != nil {
			return status.Errorf(codes.Internal, "failed to update users: %v", err)
		}
		return nil
	}); err != nil {
		return userSyncError(err)
	}

	return stream.SendAndClose(&common.Empty{})
}
