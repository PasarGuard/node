package rpc

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/google/uuid"
	grpcmiddleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func validateApiKey(ctx context.Context, s *Service) error {
	// Extract metadata
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Errorf(codes.Unauthenticated, "missing metadata")
	}

	// Extract x-api-key header
	apiKeys, ok := md["x-api-key"]
	if !ok || len(apiKeys) == 0 {
		return status.Errorf(codes.Unauthenticated, "missing x-api-key header")
	}

	// Get the first key (there should typically be only one)
	apiKeyHeader := apiKeys[0]

	apiKey := s.ApiKey()
	key, err := uuid.Parse(apiKeyHeader)
	switch {
	case err != nil:
		return status.Errorf(codes.InvalidArgument, "invalid api key format: must be a valid UUID")
	case key != apiKey:
		return status.Errorf(codes.PermissionDenied, "api key mismatch")
	}

	return nil
}

func validateApiKeyMiddleware(s *Service) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		if err := validateApiKey(ctx, s); err != nil {
			return nil, err
		}

		return handler(ctx, req)
	}
}

func validateApiKeyStreamMiddleware(s *Service) grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		// Use common session validation logic
		if err := validateApiKey(ss.Context(), s); err != nil {
			log.Println("invalid api key stream:", err)
			return err
		}

		return handler(srv, ss)
	}
}

func checkBackendStatus(s *Service) error {
	back := s.Backend()
	if back == nil {
		return status.Errorf(codes.Unavailable, "backend not initialized")
	}
	if !back.Started() {
		return status.Errorf(codes.Unavailable, "core is not started yet")
	}
	return nil
}

func CheckBackendMiddleware(s *Service) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		if err := checkBackendStatus(s); err != nil {
			return nil, err
		}

		return handler(ctx, req)
	}
}

func CheckBackendStreamMiddleware(s *Service) grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		if err := checkBackendStatus(s); err != nil {
			return err
		}

		return handler(srv, ss)
	}
}

func logRequest(ctx context.Context, method string, err error) {
	// Extract client IP
	clientIP := "unknown"
	if p, ok := peer.FromContext(ctx); ok {
		clientIP = p.Addr.String()
	}

	logEntry := fmt.Sprintf("IP: %s, Method: %s,", clientIP, strings.TrimPrefix(method, "/service.NodeService/"))

	// Log based on the response status
	if err != nil {
		st, _ := status.FromError(err)
		log.Println(logEntry, "Code:", st.Code())
	} else {
		log.Println(logEntry, "Status: Success")
	}
}

func LoggingInterceptor(s *Service) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Handle the request
		resp, err := handler(ctx, req)

		// Log the request
		logRequest(ctx, info.FullMethod, err)

		// Track successful requests
		if err == nil {
			s.NewRequest()
		}

		return resp, err
	}
}

func LoggingStreamInterceptor(s *Service) grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		clientIP := "unknown"
		if p, ok := peer.FromContext(ss.Context()); ok {
			clientIP = p.Addr.String()
		}
		log.Printf("Trying To Open Stream Connection, IP: %s, Method: %s,", clientIP, strings.TrimPrefix(info.FullMethod, "/service.NodeService/"))

		// Handle the request
		err := handler(srv, ss)

		// Log the request
		logRequest(ss.Context(), info.FullMethod, err)

		// Track successful requests
		if err == nil {
			s.NewRequest()
		}

		return err
	}
}

var backendMethods = map[string]bool{
	"/service.NodeService/GetStats":                 true,
	"/service.NodeService/GetUserOnlineStats":       true,
	"/service.NodeService/GetUserOnlineIpListStats": true,
	"/service.NodeService/GetBackendStats":          true,
	"/service.NodeService/GetSystemStats":           true,
	"/service.NodeService/Stop":                     true,
	"/service.NodeService/SyncUser":                 true,
	"/service.NodeService/SyncUsers":                true,
	"/service.NodeService/SyncUsersChunked":         true,
	"/service.NodeService/GetLogs":                  true,
}

func ConditionalMiddleware(s *Service) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		var interceptors []grpc.UnaryServerInterceptor

		interceptors = append(interceptors, LoggingInterceptor(s))

		interceptors = append(interceptors, validateApiKeyMiddleware(s))

		if backendMethods[info.FullMethod] {
			interceptors = append(interceptors, CheckBackendMiddleware(s))
		}

		chained := grpcmiddleware.ChainUnaryServer(interceptors...)
		return chained(ctx, req, info, handler)
	}
}

func ConditionalStreamMiddleware(s *Service) grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		var interceptors []grpc.StreamServerInterceptor

		interceptors = append(interceptors, LoggingStreamInterceptor(s))

		interceptors = append(interceptors, validateApiKeyStreamMiddleware(s))

		if backendMethods[info.FullMethod] {
			interceptors = append(interceptors, CheckBackendStreamMiddleware(s))
		}

		chained := grpcmiddleware.ChainStreamServer(interceptors...)
		return chained(srv, ss, info, handler)
	}
}
