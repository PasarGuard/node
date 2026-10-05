package rest

import (
	"errors"
	"fmt"
	"net/http"

	"google.golang.org/grpc/status"

	"github.com/pasarguard/node/backend"
	"github.com/pasarguard/node/common"
)

// backendFor resolves one core for a request that carries a core_id, falling
// back to the default core when it does not.
func (s *Service) backendFor(coreID uint64) (backend.Backend, error) {
	if b, ok := s.BackendFor(coreID); ok {
		return b, nil
	}
	return nil, errNoBackend
}

var errNoBackend = errors.New("backend not initialized")

// GetStats answers one core's request, or the sum across every core when
// core_id is 0 (CONTRACT §3.2).
func (s *Service) GetStats(w http.ResponseWriter, r *http.Request) {
	var request common.StatRequest
	if err := common.ReadProtoBody(r.Body, &request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if request.GetCoreId() != 0 {
		b, err := s.backendFor(request.GetCoreId())
		if err != nil {
			http.Error(w, fmt.Sprintf("core %d is not running", request.GetCoreId()), http.StatusServiceUnavailable)
			return
		}
		resp, err := b.GetStats(r.Context(), &request)
		s.writeStats(w, resp, err)
		return
	}

	resp, err := s.Stats(r.Context(), &request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	s.writeStats(w, resp, nil)
}

func (s *Service) writeStats(w http.ResponseWriter, stats *common.StatResponse, err error) {
	if err != nil {
		err = common.InterceptNotFound(err)
		st, _ := status.FromError(err)
		httpCode := common.GrpcCodeToHTTP(st.Code())
		http.Error(w, err.Error(), httpCode)
		return
	}

	common.SendProtoResponse(w, stats)
}

func (s *Service) GetUserOnlineStat(w http.ResponseWriter, r *http.Request) {
	var request common.StatRequest
	if err := common.ReadProtoBody(r.Body, &request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	b, err := s.backendFor(request.GetCoreId())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	stats, err := b.GetUserOnlineStats(r.Context(), request.GetName())
	if err != nil {
		err = common.InterceptNotFound(err)
		st, _ := status.FromError(err)
		httpCode := common.GrpcCodeToHTTP(st.Code())
		http.Error(w, err.Error(), httpCode)
		return
	}

	common.SendProtoResponse(w, stats)
}

func (s *Service) GetUserOnlineIpListStats(w http.ResponseWriter, r *http.Request) {
	var request common.StatRequest
	if err := common.ReadProtoBody(r.Body, &request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	b, err := s.backendFor(request.GetCoreId())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	stats, err := b.GetUserOnlineIpListStats(r.Context(), request.GetName())
	if err != nil {
		err = common.InterceptNotFound(err)
		st, _ := status.FromError(err)
		httpCode := common.GrpcCodeToHTTP(st.Code())
		http.Error(w, err.Error(), httpCode)
		return
	}

	common.SendProtoResponse(w, stats)
}

func (s *Service) GetBackendStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.Backend().GetSysStats(r.Context())
	if err != nil {
		st, _ := status.FromError(err)
		httpCode := common.GrpcCodeToHTTP(st.Code())
		http.Error(w, err.Error(), httpCode)
		return
	}

	common.SendProtoResponse(w, stats)
}

func (s *Service) GetOutboundsLatency(w http.ResponseWriter, r *http.Request) {
	var request common.LatencyRequest
	if err := common.ReadProtoBody(r.Body, &request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	latency, err := s.OutboundsLatency(r.Context(), &request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	common.SendProtoResponse(w, latency)
}

func (s *Service) GetSystemStats(w http.ResponseWriter, r *http.Request) {
	common.SendProtoResponse(w, s.SystemStats(r.Context()))
}
