package rest

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"

	"github.com/m03ed/marzban-node-go/backend"
	"github.com/m03ed/marzban-node-go/backend/xray"
	"github.com/m03ed/marzban-node-go/common"
)

func (s *Service) Base(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.controller.BaseInfoResponse(false, ""))
}

func (s *Service) Ping(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{})
}

func (s *Service) Start(w http.ResponseWriter, r *http.Request) {
	ctx, backendType, err := s.detectBackend(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "unknown ip", http.StatusServiceUnavailable)
		return
	}

	if s.controller.GetBackend() != nil {
		log.Println("New connection from ", ip, " core control access was taken away from previous client.")
		s.disconnect()
	}

	s.connect(ip)

	log.Println(ip, " connected, Session ID = ", s.controller.GetSessionID())

	if err = s.controller.StartBackend(ctx, backendType); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.controller.BaseInfoResponse(true, ""))
}

func (s *Service) Stop(w http.ResponseWriter, _ *http.Request) {
	log.Println(s.GetIP(), " disconnected, Session ID = ", s.controller.GetSessionID())
	s.disconnect()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{})
}

func (s *Service) detectBackend(r *http.Request) (context.Context, common.BackendType, error) {
	var body common.Backend
	var ctx context.Context

	// Decode into a map
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return nil, 0, errors.New("invalid JSON")
	}

	if body.Type == common.BackendType_XRAY {
		config, err := xray.NewXRayConfig(body.Config)
		if err != nil {
			return nil, 0, errors.New("invalid Config")
		}
		ctx = context.WithValue(r.Context(), backend.ConfigKey{}, config)
	} else {
		return ctx, body.Type, errors.New("invalid backend type")
	}

	return ctx, body.Type, nil
}
