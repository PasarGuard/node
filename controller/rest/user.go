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

	if user == nil {
		http.Error(w, "no user received", http.StatusBadRequest)
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

	if err := s.Backend().SyncUsers(r.Context(), users); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	common.SendProtoResponse(w, &common.Empty{})
}
