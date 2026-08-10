package rpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
	"github.com/pasarguard/node/controller"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

type Service struct {
	common.UnimplementedNodeServiceServer
	controller.Controller
	bufferedUserSyncs chan struct{}
}

const maxConcurrentBufferedUserSyncs = 2

func New(cfg *config.Config) *Service {
	return &Service{
		Controller:        *controller.New(cfg),
		bufferedUserSyncs: make(chan struct{}, maxConcurrentBufferedUserSyncs),
	}
}

func (s *Service) acquireBufferedUserSync(ctx context.Context) (func(), error) {
	select {
	case s.bufferedUserSyncs <- struct{}{}:
		return func() { <-s.bufferedUserSyncs }, nil
	case <-ctx.Done():
		return nil, status.FromContextError(ctx.Err()).Err()
	default:
		return nil, status.Error(codes.ResourceExhausted, "too many buffered user sync streams")
	}
}

func StartGRPCListener(tlsConfig *tls.Config, addr string, cfg *config.Config) (func(ctx context.Context) error, controller.Service, error) {
	s := New(cfg)

	creds := credentials.NewTLS(tlsConfig)

	// Create the gRPC server with conditional middleware
	// Set max message size to 64MB to handle large configs and user data
	const maxMsgSize = 64 * 1024 * 1024 // 64MB
	grpcServer := grpc.NewServer(
		grpc.Creds(creds),
		grpc.MaxRecvMsgSize(maxMsgSize),
		grpc.MaxSendMsgSize(maxMsgSize),
		grpc.UnaryInterceptor(ConditionalMiddleware(s)),
		grpc.StreamInterceptor(ConditionalStreamMiddleware(s)),
	)

	// Register the service
	common.RegisterNodeServiceServer(grpcServer, s)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	go func() {
		log.Println("gRPC Server listening on", addr)
		log.Println("Press Ctrl+C to stop")
		if err = grpcServer.Serve(listener); err != nil {
			log.Printf("gRPC server error: %v", err)
		}
	}()

	// Create a shutdown function for gRPC server
	return func(ctx context.Context) error {
		// Graceful stop for gRPC server
		stopped := make(chan struct{})
		go func() {
			grpcServer.GracefulStop()
			close(stopped)
		}()

		// Wait for server to stop or context to timeout
		select {
		case <-stopped:
			return nil
		case <-ctx.Done():
			grpcServer.Stop() // Force stop if graceful stop times out
			return ctx.Err()
		}
	}, s, nil
}
