package service

import (
	"context"
	"encoding/json"
	log "marzban-node/logger"
	"net/http"
	"time"
)

func (s *Service) GetOutboundsStats(w http.ResponseWriter, _ *http.Request) {
	if !s.GetCore().Started() {
		http.Error(w, "core is not started yet", http.StatusServiceUnavailable)
		return
	}

	api := s.GetXrayAPI()
	if api.StatsServiceClient == nil {
		http.Error(w, "stat service is not available", http.StatusServiceUnavailable)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	response, err := api.GetOutboundsStats(ctx, true)
	if err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Service) GetInboundsStats(w http.ResponseWriter, _ *http.Request) {
	if !s.core.Started() {
		http.Error(w, "core is not started yet", http.StatusServiceUnavailable)
		return
	}

	api := s.GetXrayAPI()
	if api.StatsServiceClient == nil {
		http.Error(w, "stat service is not available", http.StatusServiceUnavailable)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	response, err := api.GetInboundsStats(ctx, true)
	if err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Service) GetUsersStats(w http.ResponseWriter, _ *http.Request) {
	if !s.core.Started() {
		http.Error(w, "core is not started yet", http.StatusServiceUnavailable)
		return
	}

	api := s.GetXrayAPI()
	if api.StatsServiceClient == nil {
		http.Error(w, "stat service is not available", http.StatusServiceUnavailable)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	response, err := api.GetUsersStats(ctx, true)
	if err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Service) GetSystemStats(w http.ResponseWriter, _ *http.Request) {
	if !s.core.Started() {
		http.Error(w, "core is not started yet", http.StatusServiceUnavailable)
		return
	}

	api := s.GetXrayAPI()
	if api.StatsServiceClient == nil {
		http.Error(w, "stat service is not available", http.StatusServiceUnavailable)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()

	response, err := api.GetSysStats(ctx)
	if err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Service) GetNodeStats(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.stats)
}
