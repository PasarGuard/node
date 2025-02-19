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

	stats, err := s.controller.GetBackend().GetOutboundsStats(r.Context(), request.GetReset_())
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

	stats, err := s.controller.GetBackend().GetOutboundStats(r.Context(), request.GetName(), request.GetReset_())
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

	stats, err := s.controller.GetBackend().GetInboundsStats(r.Context(), request.GetReset_())
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

	stats, err := s.controller.GetBackend().GetInboundStats(r.Context(), request.GetName(), request.GetReset_())
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

	stats, err := s.controller.GetBackend().GetUsersStats(r.Context(), request.GetReset_())
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

	stats, err := s.controller.GetBackend().GetUserStats(r.Context(), request.GetName(), request.GetReset_())
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

	stats, err := s.controller.GetBackend().GetStatOnline(r.Context(), request.GetName())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	common.SendProtoResponse(w, stats)
}

func (s *Service) GetBackendStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.controller.GetBackend().GetSysStats(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	common.SendProtoResponse(w, stats)
}

func (s *Service) GetSystemStats(w http.ResponseWriter, _ *http.Request) {
	common.SendProtoResponse(w, s.controller.GetStats())
}
