package rest

import (
	"io"
	"log"
	"net/http"

	"google.golang.org/protobuf/proto"

	"github.com/pasarguard/node/common"
)

func (s *Service) SyncUser(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	user := &common.User{}
	if err = proto.Unmarshal(body, user); err != nil {
		http.Error(w, "Failed to decode user", http.StatusBadRequest)
		return
	}

	if user == nil {
		http.Error(w, "no user received", http.StatusBadRequest)
		return
	}

	if err = s.Backend().SyncUser(r.Context(), user); err != nil {
		log.Printf("Error syncing user: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response, _ := proto.Marshal(&common.Empty{})

	w.Header().Set("Content-Type", "application/x-protobuf")
	if _, err = w.Write(response); err != nil {
		http.Error(w, "Failed to write response", http.StatusInternalServerError)
		return
	}
}

func (s *Service) SyncUsers(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	users := &common.Users{}
	if err = proto.Unmarshal(body, users); err != nil {
		http.Error(w, "Failed to decode user", http.StatusBadRequest)
		return
	}

	if err = s.Backend().SyncUsers(r.Context(), users.GetUsers()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response, _ := proto.Marshal(&common.Empty{})

	w.Header().Set("Content-Type", "application/x-protobuf")
	if _, err = w.Write(response); err != nil {
		http.Error(w, "Failed to write response", http.StatusInternalServerError)
		return
	}
}
