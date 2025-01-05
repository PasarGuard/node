package rest

import (
	"encoding/json"
	"github.com/go-chi/chi/v5"
	"net/http"
)

func (s *Service) GetOutboundsStats(w http.ResponseWriter, r *http.Request) {
	response, err := s.controller.GetBackend().GetOutboundsStats(r.Context(), true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (s *Service) GetInboundsStats(w http.ResponseWriter, r *http.Request) {
	response, err := s.controller.GetBackend().GetInboundsStats(r.Context(), true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (s *Service) GetUsersStats(w http.ResponseWriter, r *http.Request) {
	response, err := s.controller.GetBackend().GetUsersStats(r.Context(), true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (s *Service) GetUserOnlineStat(w http.ResponseWriter, r *http.Request) {
	email := chi.URLParam(r, "email")
	if email == "" {
		http.Error(w, "missing email", http.StatusBadRequest)
		return
	}

	response, err := s.controller.GetBackend().GetStatOnline(r.Context(), email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (s *Service) GetBackendStats(w http.ResponseWriter, r *http.Request) {
	response, err := s.controller.GetBackend().GetSysStats(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (s *Service) GetSystemStats(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.controller.GetStats())
}
