package rpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/pasarguard/node/backend/tunnel"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
	"github.com/pasarguard/node/controller"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Service struct {
	common.UnimplementedNodeServiceServer
	controller.Controller

	// tunnelMgr is the per-process tunnel manager (created lazily by
	// Tunnels()); tunnelOnce guards it. Declared here because Service is
	// defined here — the tunnel RPCs themselves live in tunnel.go.
	tunnelMgr  *tunnel.Manager
	tunnelOnce sync.Once
}

func New(cfg *config.Config) *Service {
	return &Service{
		Controller: *controller.New(cfg),
	}
}

func StartGRPCListener(tlsConfig *tls.Config, addr string, cfg *config.Config) (func(ctx context.Context) error, controller.Service, error) {
	s := New(cfg)

	// A tunnel comes back from config alone: every persisted tunnel is started
	// before the first RPC can be served, so ListTunnels right after boot
	// already reports it running (scope test 4). Failures are logged inside
	// Restore and never take the node down.
	if started, err := s.Tunnels().Restore(context.Background()); err != nil {
		log.Printf("[Warning] tunnel restore: %v", err)
	} else if started > 0 {
		log.Printf("restored %d tunnel(s) from config", started)
	}

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

	// Return a shutdown function for gRPC server
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
