package rest

import (
	"encoding/json"
	"net/http"

	"github.com/m03ed/marzban-node-go/common"
)

func (s *Service) AddUser(w http.ResponseWriter, r *http.Request) {
	user := &common.User{}
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if user == nil {
		http.Error(w, "no user received", http.StatusBadRequest)
		return
	}

	if err := s.controller.GetBackend().AddUser(r.Context(), user); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{})
}

func (s *Service) UpdateUser(w http.ResponseWriter, r *http.Request) {
	user := &common.User{}
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if user == nil {
		http.Error(w, "no user received", http.StatusBadRequest)
		return
	}

	if err := s.controller.GetBackend().UpdateUser(r.Context(), user); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{})
}

func (s *Service) RemoveUser(w http.ResponseWriter, r *http.Request) {
	user := &common.User{}
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if user == nil {
		http.Error(w, "no user received", http.StatusBadRequest)
		return
	}

	s.controller.GetBackend().RemoveUser(r.Context(), user.Email)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{})
}
