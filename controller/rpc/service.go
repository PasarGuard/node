package rpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/m03ed/marzban-node-go/common"
	"github.com/m03ed/marzban-node-go/controller"
)

type Service struct {
	common.UnimplementedNodeServiceServer
	controller *controller.Controller
	mu         sync.Mutex
}

func NewService() *Service {
	s := &Service{controller: controller.NewController()}
	return s
}

func (s *Service) StopService() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.controller.StopJobs()
}

func (s *Service) connect() {
	s.controller.Connect()
}

func (s *Service) disconnect() {
	s.controller.Disconnect()
}

func StartGRPCListener(tlsConfig *tls.Config, addr string) (func(ctx context.Context) error, controller.Service, error) {
	s := NewService()

	creds := credentials.NewTLS(tlsConfig)

	// Create the gRPC server with conditional middleware
	grpcServer := grpc.NewServer(
		grpc.Creds(creds),
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
	}, controller.Service(s), nil
}
