package rest

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"

	"google.golang.org/protobuf/proto"

	"github.com/pasarguard/node/common"
)

const (
	requestChunkSize = 64 * 1024 // 64KB streaming chunks
)

func readRequestBody(body io.ReadCloser) ([]byte, error) {
	defer body.Close()

	var buf bytes.Buffer
	tmp := make([]byte, requestChunkSize)
	for {
		n, err := body.Read(tmp)
		if n > 0 {
			if _, werr := buf.Write(tmp[:n]); werr != nil {
				return nil, werr
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
	}

	if buf.Len() == 0 {
		return nil, io.ErrUnexpectedEOF
	}

	return buf.Bytes(), nil
}

func decodeUsersPayload(data []byte) ([]*common.User, error) {
	if len(data) == 0 {
		return nil, io.ErrUnexpectedEOF
	}

	// First try a Users envelope for batch updates.
	users := &common.Users{}
	if err := proto.Unmarshal(data, users); err == nil && len(users.GetUsers()) > 0 {
		return users.GetUsers(), nil
	}

	// Fallback to single user payload.
	user := &common.User{}
	if err := proto.Unmarshal(data, user); err == nil && user.GetEmail() != "" {
		return []*common.User{user}, nil
	}

	return nil, fmt.Errorf("failed to decode user payload")
}

func (s *Service) SyncUser(w http.ResponseWriter, r *http.Request) {
	body, err := readRequestBody(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read request body: %v", err), http.StatusBadRequest)
		return
	}

	users, err := decodeUsersPayload(body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to decode user payload: %v", err), http.StatusBadRequest)
		return
	}

	for _, user := range users {
		log.Printf("Got user: %v", user.GetEmail())

		if err = s.Backend().SyncUser(r.Context(), user); err != nil {
			log.Printf("Error syncing user: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	common.SendProtoResponse(w, &common.Empty{})
}

func (s *Service) SyncUsers(w http.ResponseWriter, r *http.Request) {
	users := &common.Users{}
	if err := common.ReadProtoBody(r.Body, users); err != nil {
		http.Error(w, fmt.Sprintf("Failed to decode user payload: %v", err), http.StatusBadRequest)
		return
	}

	if err := s.Backend().SyncUsers(r.Context(), users.GetUsers()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	common.SendProtoResponse(w, &common.Empty{})
}
