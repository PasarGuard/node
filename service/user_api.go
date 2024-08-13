package service

import (
	"context"
	"encoding/json"
	log "marzban-node/logger"
	"marzban-node/xray"
	"net/http"
	"slices"
	"time"
)

func (s *Service) AddUser(w http.ResponseWriter, r *http.Request) {
	api := s.GetXrayAPI()
	if api.HandlerServiceClient == nil {
		http.Error(w, "handler service is not available", http.StatusServiceUnavailable)
		return
	}

	var body userBody
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user := body.User
	if user == nil {
		http.Error(w, "no user received", http.StatusNotAcceptable)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()

	proxySetting := xray.SetupUserAccount(user)
	for _, inbound := range s.GetConfig().Inbounds {
		account, isActive := xray.IsActiveInbound(inbound, user, proxySetting)
		if isActive {
			err = api.AddInboundUser(ctx, inbound.Tag, account)
			if err != nil {
				errorMessage := "Failed to add user:"
				http.Error(w, errorMessage+err.Error(), http.StatusInternalServerError)
				log.Error(errorMessage, err)
				return
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{})
}

func (s *Service) UpdateUser(w http.ResponseWriter, r *http.Request) {
	api := s.GetXrayAPI()
	if api.HandlerServiceClient == nil {
		http.Error(w, "handler service is not available", http.StatusServiceUnavailable)
		return
	}

	var body userBody
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user := body.User
	if user == nil {
		http.Error(w, "no user received", http.StatusNotAcceptable)
		return
	}

	var activeInbounds []string

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()

	proxySetting := xray.SetupUserAccount(user)
	for _, inbound := range s.GetConfig().Inbounds {
		account, isActive := xray.IsActiveInbound(inbound, user, proxySetting)
		if isActive {
			err = api.AddInboundUser(ctx, inbound.Tag, account)
			activeInbounds = append(activeInbounds, inbound.Tag)
			if err != nil {
				errorMessage := "Failed to add user:"
				http.Error(w, errorMessage+err.Error(), http.StatusInternalServerError)
				log.Error(errorMessage, err)
				return
			}
		}
	}

	for _, inbound := range s.GetConfig().Inbounds {
		if !slices.Contains(activeInbounds, inbound.Tag) {
			_ = api.RemoveInboundUser(ctx, inbound.Tag, user.Email)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{})
}

func (s *Service) RemoveUser(w http.ResponseWriter, r *http.Request) {
	api := s.GetXrayAPI()
	if api.HandlerServiceClient == nil {
		http.Error(w, "handler service is not available", http.StatusServiceUnavailable)
		return
	}

	var body userBody
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user := body.User
	if user == nil {
		http.Error(w, "no user received", http.StatusNotAcceptable)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()

	for _, inbound := range s.GetConfig().Inbounds {
		_ = api.RemoveInboundUser(ctx, inbound.Tag, user.Email)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{})
}
