package rpc

import (
	"context"
	"log"

	"github.com/pasarguard/node/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Service) Start(ctx context.Context, data *common.Backend) (*common.BaseInfoResponse, error) {
	s.LockControl()
	defer s.UnlockControl()

	clientIP := clientIPFromContext(ctx)
	if clientIP == "" {
		return nil, status.Errorf(codes.PermissionDenied, "unknown client ip")
	}

	if s.Backend() != nil && !s.IsCurrentClient(clientIP) {
		return nil, status.Errorf(codes.PermissionDenied, "node is controlled by another client")
	}

	if err := s.StartBackendControlled(ctx, data, clientIP); err != nil {
		if epochErr := userSyncError(err); status.Code(epochErr) == codes.FailedPrecondition {
			return nil, epochErr
		}
		if ctx.Err() != nil {
			return nil, status.FromContextError(ctx.Err()).Err()
		}
		log.Print("backend start failed")
		return nil, status.Error(codes.Internal, "failed to start backend")
	}

	return s.BaseInfoResponse(), nil
}

func (s *Service) Stop(_ context.Context, _ *common.Empty) (*common.Empty, error) {
	s.LockControl()
	defer s.UnlockControl()

	s.DisconnectControlled()
	return &common.Empty{}, nil
}

func (s *Service) GetBaseInfo(_ context.Context, _ *common.Empty) (*common.BaseInfoResponse, error) {
	return s.BaseInfoResponse(), nil
}
