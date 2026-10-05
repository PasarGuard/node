package rpc

import (
	"context"
	"errors"
	"io"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pasarguard/node/backend"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/controller"
)

// The user fan-out RPCs carry no core selector yet (User/Users/UsersChunk
// gained no core_id in batch 1.0), so a sync reaches every running core. With
// one core that is byte-for-byte today's behaviour. ponytail: add a targeted
// push when the proto carries the selector — see the change request in the batch
// report.

func (s *Service) SyncUser(stream grpc.ClientStreamingServer[common.User, common.Empty]) error {
	if _, err := s.backend(); err != nil {
		return err
	}

	for {
		user, err := stream.Recv()
		if err != nil {
			return stream.SendAndClose(&common.Empty{})
		}

		if user.GetEmail() == "" {
			return errors.New("email is required")
		}

		log.Printf("Got user: %v", user.GetEmail())

		if err = s.eachBackend(func(b backend.Backend) error {
			return b.SyncUser(stream.Context(), user)
		}); err != nil {
			log.Printf("Error syncing user: %v", err)
			return status.Errorf(codes.Internal, "failed to update user: %v", err)
		}
	}
}

func (s *Service) SyncUsers(ctx context.Context, users *common.Users) (*common.Empty, error) {
	if err := s.eachBackend(func(b backend.Backend) error {
		return b.SyncUsers(ctx, users.GetUsers())
	}); err != nil {
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

	if err := s.eachBackend(func(b backend.Backend) error {
		return controller.ApplyChunkedUserUpdate(stream.Context(), b, users)
	}); err != nil {
		return status.Errorf(codes.Internal, "failed to update users: %v", err)
	}

	return stream.SendAndClose(&common.Empty{})
}

// eachBackend runs fn against every running core, mapping the no-core case to
// the codes.Unavailable every other handler already returns.
func (s *Service) eachBackend(fn func(backend.Backend) error) error {
	err := s.EachBackend(func(_ uint64, b backend.Backend) error { return fn(b) })
	if err != nil {
		return status.Errorf(codes.Unavailable, "%v", err)
	}
	return nil
}
