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

func (s *Service) addUser(w http.ResponseWriter, r *http.Request) {
	var user xray.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Failed to decode user: "+err.Error(), http.StatusBadRequest)
		return
	}

	email := fmt.Sprintf("%s.%d", user.Username, user.ID)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	proxySetting := xray.SetupUserAccount(user, email)
	for _, inbound := range s.Config.Inbounds {
		account, isActive := xray.IsActiveInbound(inbound, user, proxySetting)
		if isActive {
			err = xray.AddUserToInbound(ctx, s.HandlerClient, inbound.Tag, account)
			if err != nil {
				errorMessage := "Failed to add user:"
				http.Error(w, errorMessage+err.Error(), http.StatusInternalServerError)
				log.ErrorLog(errorMessage, err)
			}
		}
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("user added successfully"))
}

func (s *Service) updateUser(w http.ResponseWriter, r *http.Request) {
	var user xray.User

	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Failed to decode user: "+err.Error(), http.StatusBadRequest)
		return
	}

	email := fmt.Sprintf("%s.%d", user.Username, user.ID)

	var activeInbounds []string

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	proxySetting := xray.SetupUserAccount(user, email)

	for _, inbound := range s.Config.Inbounds {
		account, isActive := xray.IsActiveInbound(inbound, user, proxySetting)
		if isActive {
			err = xray.AlertInboundUser(ctx, s.HandlerClient, inbound.Tag, account)
			activeInbounds = append(activeInbounds, inbound.Tag)
			if err != nil {
				errorMessage := "Failed to add user:"
				http.Error(w, errorMessage+err.Error(), http.StatusInternalServerError)
				log.ErrorLog(errorMessage, err)
			}
		}
	}

	for _, inbound := range s.Config.Inbounds {
		if !slices.Contains(activeInbounds, inbound.Tag) {
			_ = xray.RemoveUserFromInbound(ctx, s.HandlerClient, inbound.Tag, email)
		}
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("user added successfully"))
}

func (s *Service) removeUser(w http.ResponseWriter, r *http.Request) {
	var user xray.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Failed to decode user: "+err.Error(), http.StatusBadRequest)
		return
	}
	email := fmt.Sprintf("%s.%d", user.Username, user.ID)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	for _, inbound := range s.Config.Inbounds {
		_ = xray.RemoveUserFromInbound(ctx, s.HandlerClient, inbound.Tag, email)
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("user removed"))
}
