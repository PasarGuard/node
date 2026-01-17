package rest

import (
	"encoding/json"
	"net/http"

	"google.golang.org/grpc/status"

	"github.com/pasarguard/node/common"
)

func (s *Service) GetStats(w http.ResponseWriter, r *http.Request) {
	var request common.StatRequest
	if err := common.ReadProtoBody(r.Body, &request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	stats, err := s.Backend().GetStats(r.Context(), &request)
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

	stats, err := s.Backend().GetUserOnlineStats(r.Context(), request.GetName())
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

	stats, err := s.Backend().GetUserOnlineIpListStats(r.Context(), request.GetName())
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	common.SendProtoResponse(w, stats)
}

func (s *Service) GetSystemStats(w http.ResponseWriter, _ *http.Request) {
	common.SendProtoResponse(w, s.SystemStats())
}

// GetLimitEnforcerMetrics returns limit enforcer metrics as JSON
func (s *Service) GetLimitEnforcerMetrics(w http.ResponseWriter, _ *http.Request) {
	enforcer := s.Controller.GetLimitEnforcer()
	if enforcer == nil {
		http.Error(w, "limit enforcer not enabled", http.StatusNotFound)
		return
	}

	metrics := enforcer.GetMetrics()

	w.Header().Set("Content-Type", "application/json")
	data, err := json.Marshal(metrics)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(data)
}
