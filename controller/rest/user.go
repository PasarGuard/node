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

const maxChunkBytes uint64 = 8 * 1024 * 1024

func readRequestBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, common.MaxProtoBodyBytes)
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err == nil {
		return body, true
	}
	var maxBytesError *http.MaxBytesError
	if errors.As(err, &maxBytesError) {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
	} else {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
	}
	return nil, false
}

func (s *Service) SyncUser(w http.ResponseWriter, r *http.Request) {
	body, ok := readRequestBody(w, r)
	if !ok {
		return
	}

	user := &common.User{}
	if err := proto.Unmarshal(body, user); err != nil {
		http.Error(w, "Failed to decode user", http.StatusBadRequest)
		return
	}

	if user.GetEmail() == "" {
		http.Error(w, "email is required", http.StatusBadRequest)
		return
	}

	log.Printf("Got user: %v", user.GetEmail())

	if err := s.ApplyUserSyncEpoch(user.GetUserSyncEpoch(), func() error {
		back := s.Backend()
		if back == nil {
			return errors.New("backend is not started")
		}
		return back.SyncUser(r.Context(), user)
	}); err != nil {
		log.Printf("Error syncing user: %v", err)
		writeUserSyncError(w, err, http.StatusInternalServerError)
		return
	}

	response, _ := proto.Marshal(&common.Empty{})

	w.Header().Set("Content-Type", "application/x-protobuf")
	if _, err := w.Write(response); err != nil {
		http.Error(w, "Failed to write response", http.StatusInternalServerError)
		return
	}
}

func (s *Service) SyncUsers(w http.ResponseWriter, r *http.Request) {
	body, ok := readRequestBody(w, r)
	if !ok {
		return
	}

	users := &common.Users{}
	if err := proto.Unmarshal(body, users); err != nil {
		http.Error(w, "Failed to decode user", http.StatusBadRequest)
		return
	}

	if err := s.ApplyUserSyncEpoch(users.GetUserSyncEpoch(), func() error {
		back := s.Backend()
		if back == nil {
			return errors.New("backend is not started")
		}
		return back.SyncUsers(r.Context(), users.GetUsers())
	}); err != nil {
		writeUserSyncError(w, err, http.StatusInternalServerError)
		return
	}

	response, _ := proto.Marshal(&common.Empty{})

	w.Header().Set("Content-Type", "application/x-protobuf")
	if _, err := w.Write(response); err != nil {
		http.Error(w, "Failed to write response", http.StatusInternalServerError)
		return
	}
}

func (s *Service) SyncUsersChunked(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, common.MaxProtoBodyBytes)
	reader := bufio.NewReader(r.Body)
	defer r.Body.Close()

	chunks := make(map[uint64][]*common.User)
	var (
		lastIndex  uint64
		sawLast    bool
		epochBatch controller.UserSyncEpochBatch
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
		if size > maxChunkBytes || size > uint64(common.MaxProtoBodyBytes) {
			http.Error(w, "chunk payload too large", http.StatusRequestEntityTooLarge)
			return
		}

		payload := make([]byte, int(size))
		if _, err = io.ReadFull(reader, payload); err != nil {
			http.Error(w, fmt.Sprintf("failed to read chunk payload: %v", err), http.StatusBadRequest)
			return
		}

		chunk := &common.UsersChunk{}
		if err = proto.Unmarshal(payload, chunk); err != nil {
			http.Error(w, fmt.Sprintf("failed to decode chunk: %v", err), http.StatusBadRequest)
			return
		}
		if err = epochBatch.Add(chunk.GetUserSyncEpoch()); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
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

	if err := s.ApplyUserSyncEpoch(epochBatch.Epoch(), func() error {
		back := s.Backend()
		if back == nil {
			return errors.New("backend is not started")
		}
		return controller.ApplyChunkedUserUpdate(r.Context(), back, users)
	}); err != nil {
		writeUserSyncError(w, err, http.StatusInternalServerError)
		return
	}

	common.SendProtoResponse(w, &common.Empty{})
}
