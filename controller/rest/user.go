package rest

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"

	"google.golang.org/protobuf/proto"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/controller"
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

	if user.GetEmail() == "" {
		http.Error(w, "email is required", http.StatusBadRequest)
		return
	}

	log.Printf("Got user: %v", user.GetEmail())

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

	userList := users.GetUsers()
	log.Printf("SyncUsers: received %d users from panel", len(userList))
	if len(userList) == 0 {
		log.Printf("WARNING: SyncUsers received 0 users - panel may not be sending users correctly")
	}

	if err = s.Backend().SyncUsers(r.Context(), userList); err != nil {
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

func (s *Service) SyncUsersChunked(w http.ResponseWriter, r *http.Request) {
	reader := bufio.NewReader(r.Body)
	defer r.Body.Close()

	chunks := make(map[uint64][]*common.User)
	var (
		lastIndex uint64
		sawLast   bool
	)

	for {
		size, err := binary.ReadUvarint(reader)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to read chunk length: %v", err), http.StatusBadRequest)
			return
		}
		if size == 0 {
			continue
		}

		payload := make([]byte, size)
		if _, err = io.ReadFull(reader, payload); err != nil {
			http.Error(w, fmt.Sprintf("failed to read chunk payload: %v", err), http.StatusBadRequest)
			return
		}

		chunk := &common.UsersChunk{}
		if err = proto.Unmarshal(payload, chunk); err != nil {
			http.Error(w, fmt.Sprintf("failed to decode chunk: %v", err), http.StatusBadRequest)
			return
		}

		chunks[chunk.GetIndex()] = append(chunks[chunk.GetIndex()], chunk.GetUsers()...)

		if chunk.GetLast() {
			sawLast = true
			lastIndex = chunk.GetIndex()
			break
		}
	}

	users, err := controller.BuildUsersFromChunks(chunks, lastIndex, sawLast)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Large chunk: update in-memory then restart (no API calls).
	if len(users) > 500 {
		if err := s.Backend().UpdateUsersAndRestart(r.Context(), users); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		// Small chunk: update via API without restart.
		if err := s.Backend().UpdateUsers(r.Context(), users); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	common.SendProtoResponse(w, &common.Empty{})
}
