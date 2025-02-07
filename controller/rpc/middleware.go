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

func validateSessionID(ctx context.Context, s *Service) error {
	// Extract metadata
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Errorf(codes.Unauthenticated, "missing metadata")
	}

	// Check session ID
	sessionID := s.controller.GetSessionID()
	if sessionID == uuid.Nil {
		return status.Errorf(codes.Unauthenticated, "please connect first")
	}

	// Extract Authorization header
	authHeader, ok := md["Authorization"]
	if !ok || len(authHeader) == 0 {
		return status.Errorf(codes.Unauthenticated, "missing authorization header")
	}

	// Validate token format (Bearer <token>)
	tokenParts := strings.Split(authHeader[0], " ")
	if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
		return status.Errorf(codes.InvalidArgument, "invalid authorization header format")
	}

	// Parse token
	tokenString := tokenParts[1]
	token, err := uuid.Parse(tokenString)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "invalid session ID: %v", err)
	}

	// Check if session ID matches
	if token != sessionID {
		return status.Errorf(codes.PermissionDenied, "session ID mismatch")
	}

	return nil
}

func CheckSessionIDMiddleware(s *Service) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		if err := validateSessionID(ctx, s); err != nil {
			return nil, err
		}

		return handler(ctx, req)
	}
}

func CheckSessionIDStreamMiddleware(s *Service) grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		// Use common session validation logic
		if err := validateSessionID(ss.Context(), s); err != nil {
			log.Println("invalid session ID stream:", err)
			return err
		}

		return handler(srv, ss)
	}
}

func checkBackendStatus(s *Service) error {
	back := s.controller.GetBackend()
	if back == nil {
		return status.Errorf(codes.Internal, "backend not initialized")
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

func LoggingInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	// Handle the request
	resp, err := handler(ctx, req)

	// Log the request
	logRequest(ctx, info.FullMethod, err)

	return resp, err
}

func LoggingStreamInterceptor() grpc.StreamServerInterceptor {
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

		return err
	}
}

var backendMethods = map[string]bool{
	"/service.NodeService/GetOutboundsStats":  true,
	"/service.NodeService/GetOutboundStats":   true,
	"/service.NodeService/GetInboundsStats":   true,
	"/service.NodeService/GetInboundStats":    true,
	"/service.NodeService/GetUsersStats":      true,
	"/service.NodeService/GetUserStats":       true,
	"/service.NodeService/GetUserOnlineStats": true,
	"/service.NodeService/GetBackendStats":    true,
	"/service.NodeService/SyncUser":           true,
	"/service.NodeService/SyncUsers":          true,
}

var sessionIDMethods = map[string]bool{
	"/service.NodeService/Stop":               true,
	"/service.NodeService/GetBaseInfo":        true,
	"/service.NodeService/GetLogs":            true,
	"/service.NodeService/GetSystemStats":     true,
	"/service.NodeService/GetOutboundsStats":  true,
	"/service.NodeService/GetOutboundStats":   true,
	"/service.NodeService/GetInboundsStats":   true,
	"/service.NodeService/GetInboundStats":    true,
	"/service.NodeService/GetUsersStats":      true,
	"/service.NodeService/GetUserStats":       true,
	"/service.NodeService/GetUserOnlineStats": true,
	"/service.NodeService/GetBackendStats":    true,
	"/service.NodeService/SyncUser":           true,
	"/service.NodeService/SyncUsers":          true,
}

func ConditionalMiddleware(s *Service) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		var interceptors []grpc.UnaryServerInterceptor

		interceptors = append(interceptors, LoggingInterceptor)

		if sessionIDMethods[info.FullMethod] {
			interceptors = append(interceptors, CheckSessionIDMiddleware(s))
		}

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

		interceptors = append(interceptors, LoggingStreamInterceptor())

		if sessionIDMethods[info.FullMethod] {
			interceptors = append(interceptors, CheckSessionIDStreamMiddleware(s))
		}

		if backendMethods[info.FullMethod] {
			interceptors = append(interceptors, CheckBackendStreamMiddleware(s))
		}

		chained := grpcmiddleware.ChainStreamServer(interceptors...)
		return chained(srv, ss, info, handler)
	}
}
