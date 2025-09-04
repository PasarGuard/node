package rest

import (
	"google.golang.org/grpc/status"
	"net/http"

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
