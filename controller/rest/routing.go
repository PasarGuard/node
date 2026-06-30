package rest

import (
	"net/http"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pasarguard/node/backend"
	"github.com/pasarguard/node/common"
)

// asRoutingBackend adapts a backend to RoutingBackend, returning Unimplemented
// for backends (e.g. WireGuard) that do not support xray routing. Kept as a free
// function so the capability gate is unit-testable without a live server.
func asRoutingBackend(b backend.Backend) (backend.RoutingBackend, error) {
	rb, ok := b.(backend.RoutingBackend)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "routing is only supported by the xray backend")
	}
	return rb, nil
}

func (s *Service) routingBackend() (backend.RoutingBackend, error) {
	return asRoutingBackend(s.Backend())
}

// writeRoutingError maps a backend error to the matching HTTP status, mirroring
// the stats.go handlers (InterceptNotFound + gRPC-code-to-HTTP).
func writeRoutingError(w http.ResponseWriter, err error) {
	err = common.InterceptNotFound(err)
	st, _ := status.FromError(err)
	http.Error(w, err.Error(), common.GrpcCodeToHTTP(st.Code()))
}

func (s *Service) ListRoutingRules(w http.ResponseWriter, r *http.Request) {
	rb, err := s.routingBackend()
	if err != nil {
		writeRoutingError(w, err)
		return
	}

	resp, err := rb.ListRoutingRules(r.Context())
	if err != nil {
		writeRoutingError(w, err)
		return
	}

	common.SendProtoResponse(w, resp)
}

func (s *Service) GetBalancerInfo(w http.ResponseWriter, r *http.Request) {
	rb, err := s.routingBackend()
	if err != nil {
		writeRoutingError(w, err)
		return
	}

	var request common.BalancerInfoRequest
	if err := common.ReadProtoBody(r.Body, &request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	resp, err := rb.GetBalancerInfo(r.Context(), request.GetTag())
	if err != nil {
		writeRoutingError(w, err)
		return
	}

	common.SendProtoResponse(w, resp)
}

func (s *Service) TestRoute(w http.ResponseWriter, r *http.Request) {
	rb, err := s.routingBackend()
	if err != nil {
		writeRoutingError(w, err)
		return
	}

	var request common.TestRouteRequest
	if err := common.ReadProtoBody(r.Body, &request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	resp, err := rb.TestRoute(r.Context(), &request)
	if err != nil {
		writeRoutingError(w, err)
		return
	}

	common.SendProtoResponse(w, resp)
}

func (s *Service) AddRoutingRule(w http.ResponseWriter, r *http.Request) {
	rb, err := s.routingBackend()
	if err != nil {
		writeRoutingError(w, err)
		return
	}

	var request common.AddRoutingRuleRequest
	if err := common.ReadProtoBody(r.Body, &request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := rb.AddRoutingRule(r.Context(), request.GetRule(), !request.GetShouldReset()); err != nil {
		writeRoutingError(w, err)
		return
	}

	common.SendProtoResponse(w, &common.Empty{})
}

func (s *Service) RemoveRoutingRule(w http.ResponseWriter, r *http.Request) {
	rb, err := s.routingBackend()
	if err != nil {
		writeRoutingError(w, err)
		return
	}

	var request common.RemoveRoutingRuleRequest
	if err := common.ReadProtoBody(r.Body, &request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := rb.RemoveRoutingRule(r.Context(), request.GetRuleTag()); err != nil {
		writeRoutingError(w, err)
		return
	}

	common.SendProtoResponse(w, &common.Empty{})
}

func (s *Service) OverrideBalancerTarget(w http.ResponseWriter, r *http.Request) {
	rb, err := s.routingBackend()
	if err != nil {
		writeRoutingError(w, err)
		return
	}

	var request common.OverrideBalancerTargetRequest
	if err := common.ReadProtoBody(r.Body, &request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := rb.OverrideBalancerTarget(r.Context(), request.GetBalancerTag(), request.GetTarget()); err != nil {
		writeRoutingError(w, err)
		return
	}

	common.SendProtoResponse(w, &common.Empty{})
}
