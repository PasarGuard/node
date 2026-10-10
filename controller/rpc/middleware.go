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

	"github.com/pasarguard/node/common"
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
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if err := validateApiKey(ctx, s); err != nil {
			return nil, err
		}

		return handler(ctx, req)
	}
}

func validateApiKeyStreamMiddleware(s *Service) grpc.StreamServerInterceptor {
	return func(
		srv any,
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

// coreSelector is any request message that carries a core_id. Every generated
// proto message has the getter, so this is one assertion rather than a switch
// over the RPC set.
type coreSelector interface {
	GetCoreId() uint64
}

// checkBackendStatus gates an RPC on the core the REQUEST names, not on the
// default core.
//
// Gating on the default core was correct while a node had one core, and it is
// what core_id 0 must keep meaning for every RPC that is not a stats
// aggregate (CONTRACT §1.2): a request that names no core falls back to the
// default core and behaves exactly as it always did. But it is wrong the moment
// a node runs N — StopCore(1) then made every RPC on cores 2 and 3 answer
// `Unavailable: backend not initialized` while both cores kept serving traffic,
// which is a node the panel can neither manage nor bill.
//
// The routing is by core_id rather than by any per-method list, so a new RPC
// that carries a core selector is gated correctly without being registered here.
func checkBackendStatus(s *Service, req any) error {
	// StopCore asks to stop a core, so requiring that core to be running would
	// refuse an already-idempotent call. DisconnectCore is a no-op for a core
	// that is not running; the only real precondition is that some core exists.
	if _, isStop := req.(*common.StopCore); isStop {
		if s.Backend() == nil && len(s.StartedCores()) == 0 {
			return status.Errorf(codes.Unavailable, "backend not initialized")
		}
		return nil
	}

	if selector, ok := req.(coreSelector); ok && selector.GetCoreId() != 0 {
		back, ok := s.BackendFor(selector.GetCoreId())
		if !ok {
			return status.Errorf(codes.Unavailable, "core %d is not running", selector.GetCoreId())
		}
		if !back.Started() {
			return status.Errorf(codes.Unavailable, "core %d is not started yet", selector.GetCoreId())
		}
		return nil
	}

	// No core named (core_id 0, or a request type with no selector): the default
	// core, byte-for-byte as before.
	back := s.Backend()
	if back == nil {
		return status.Errorf(codes.Unavailable, "backend not initialized")
	}
	if !back.Started() {
		return status.Errorf(codes.Unavailable, "core is not started yet")
	}
	return nil
}

// checkAggregateStatus gates the core_id 0 STATS calls, whose contract is the
// sum across every running core (CONTRACT §3.2) rather than the default core's
// reading. They need one running core, not a particular one — so with core 1
// stopped and cores 2 and 3 serving, the aggregate still answers.
func checkAggregateStatus(s *Service) error {
	if len(s.StartedCores()) > 0 {
		return nil
	}
	return status.Errorf(codes.Unavailable, "backend not initialized")
}

// CheckStatsBackendMiddleware gates GetStats on the core it names, or on the
// aggregate rule when it names none. It replaces the plain backend gate for that
// one method; the other backendMethods keep the default-core gate.
func CheckStatsBackendMiddleware(s *Service) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if selector, ok := req.(coreSelector); !ok || selector.GetCoreId() == 0 {
			// core_id 0 on GetStats is the sum across every running core.
			if err := checkAggregateStatus(s); err != nil {
				return nil, err
			}
			return handler(ctx, req)
		}
		if err := checkBackendStatus(s, req); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

func CheckBackendMiddleware(s *Service) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if err := checkBackendStatus(s, req); err != nil {
			return nil, err
		}

		return handler(ctx, req)
	}
}

func CheckBackendStreamMiddleware(s *Service) grpc.StreamServerInterceptor {
	return func(
		srv any,
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		// Every stream in backendMethods is gated on Empty, which names no core,
		// so the default core is the whole of the decision here.
		if err := checkBackendStatus(s, nil); err != nil {
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
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
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
		srv any,
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
	"/service.NodeService/StopCore":                 true,
	"/service.NodeService/SyncUser":                 true,
	"/service.NodeService/SyncUsers":                true,
	"/service.NodeService/SyncUsersChunked":         true,
	"/service.NodeService/GetLogs":                  true,
	"/service.NodeService/ListRoutingRules":         true,
	"/service.NodeService/GetBalancerInfo":          true,
	"/service.NodeService/TestRoute":                true,
	"/service.NodeService/AddRoutingRule":           true,
	"/service.NodeService/RemoveRoutingRule":        true,
	"/service.NodeService/OverrideBalancerTarget":   true,
}

// aggregateMethods are the stats calls whose core_id 0 means "sum across every
// running core" (CONTRACT §3.2) rather than "the default core's reading". They
// are gated on a core running rather than on the DEFAULT core running. On a
// single-core node the two rules agree exactly, so this changes nothing for the
// case that existed before.
var aggregateMethods = map[string]bool{
	"/service.NodeService/GetStats": true,
}

func ConditionalMiddleware(s *Service) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		var interceptors []grpc.UnaryServerInterceptor

		interceptors = append(interceptors, LoggingInterceptor(s))

		interceptors = append(interceptors, validateApiKeyMiddleware(s))

		if backendMethods[info.FullMethod] {
			if aggregateMethods[info.FullMethod] {
				interceptors = append(interceptors, CheckStatsBackendMiddleware(s))
			} else {
				interceptors = append(interceptors, CheckBackendMiddleware(s))
			}
		}

		chained := grpcmiddleware.ChainUnaryServer(interceptors...)
		return chained(ctx, req, info, handler)
	}
}

func ConditionalStreamMiddleware(s *Service) grpc.StreamServerInterceptor {
	return func(
		srv any,
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
