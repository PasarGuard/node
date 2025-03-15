package rest

import (
	"net/http"

	"github.com/m03ed/gozargah-node/common"
)

func (s *Service) GetOutboundsStats(w http.ResponseWriter, r *http.Request) {
	var request common.StatRequest
	if err := common.ReadProtoBody(r.Body, &request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	stats, err := s.GetBackend().GetOutboundsStats(r.Context(), request.GetReset_())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	common.SendProtoResponse(w, stats)
}

func (s *Service) GetOutboundStats(w http.ResponseWriter, r *http.Request) {
	var request common.StatRequest
	if err := common.ReadProtoBody(r.Body, &request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if request.GetName() == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	stats, err := s.GetBackend().GetOutboundStats(r.Context(), request.GetName(), request.GetReset_())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	common.SendProtoResponse(w, stats)
}

func (s *Service) GetInboundsStats(w http.ResponseWriter, r *http.Request) {
	var request common.StatRequest
	if err := common.ReadProtoBody(r.Body, &request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	stats, err := s.GetBackend().GetInboundsStats(r.Context(), request.GetReset_())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	common.SendProtoResponse(w, stats)
}

func (s *Service) GetInboundStats(w http.ResponseWriter, r *http.Request) {
	var request common.StatRequest
	if err := common.ReadProtoBody(r.Body, &request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if request.GetName() == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	stats, err := s.GetBackend().GetInboundStats(r.Context(), request.GetName(), request.GetReset_())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	common.SendProtoResponse(w, stats)
}

func (s *Service) GetUsersStats(w http.ResponseWriter, r *http.Request) {
	var request common.StatRequest
	if err := common.ReadProtoBody(r.Body, &request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	stats, err := s.GetBackend().GetUsersStats(r.Context(), request.GetReset_())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	common.SendProtoResponse(w, stats)
}

func (s *Service) GetUserStats(w http.ResponseWriter, r *http.Request) {
	var request common.StatRequest
	if err := common.ReadProtoBody(r.Body, &request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if request.GetName() == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	stats, err := s.GetBackend().GetUserStats(r.Context(), request.GetName(), request.GetReset_())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
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

	if request.GetName() == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	stats, err := s.GetBackend().GetUserOnlineStats(r.Context(), request.GetName())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
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

	if request.GetName() == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	stats, err := s.GetBackend().GetUserOnlineIpListStats(r.Context(), request.GetName())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	common.SendProtoResponse(w, stats)
}

func (s *Service) GetBackendStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.GetBackend().GetSysStats(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	common.SendProtoResponse(w, stats)
}

func (s *Service) GetSystemStats(w http.ResponseWriter, _ *http.Request) {
	common.SendProtoResponse(w, s.GetStats())
}
