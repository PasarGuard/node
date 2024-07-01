package service

import (
	"context"
	"encoding/json"
	"fmt"
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

	var data UserData
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, "Failed to decode user: "+err.Error(), http.StatusBadRequest)
		return
	}

	user := data.User
	email := fmt.Sprintf("%s.%d", user.Username, user.ID)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	proxySetting := xray.SetupUserAccount(user, email)
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

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("user added successfully"))
}

func (s *Service) UpdateUser(w http.ResponseWriter, r *http.Request) {
	api := s.GetXrayAPI()
	if api.HandlerServiceClient == nil {
		http.Error(w, "handler service is not available", http.StatusServiceUnavailable)
		return
	}

	var data UserData
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, "Failed to decode user: "+err.Error(), http.StatusBadRequest)
		return
	}

	user := data.User
	email := fmt.Sprintf("%s.%d", user.Username, user.ID)

	var activeInbounds []string

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	proxySetting := xray.SetupUserAccount(user, email)

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
			_ = api.RemoveInboundUser(ctx, inbound.Tag, email)
		}
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("user added successfully"))
}

func (s *Service) RemoveUser(w http.ResponseWriter, r *http.Request) {
	api := s.GetXrayAPI()
	if api.HandlerServiceClient == nil {
		http.Error(w, "handler service is not available", http.StatusServiceUnavailable)
		return
	}

	var data UserData
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, "Failed to decode user: "+err.Error(), http.StatusBadRequest)
		return
	}

	user := data.User
	email := fmt.Sprintf("%s.%d", user.Username, user.ID)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	for _, inbound := range s.GetConfig().Inbounds {
		_ = api.RemoveInboundUser(ctx, inbound.Tag, email)
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("user removed"))
}
