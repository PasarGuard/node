package rest

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"

	"google.golang.org/protobuf/proto"

	"github.com/m03ed/marzban-node-go/backend"
	"github.com/m03ed/marzban-node-go/backend/xray"
	"github.com/m03ed/marzban-node-go/common"
)

func (s *Service) Base(w http.ResponseWriter, _ *http.Request) {
	response, _ := proto.Marshal(s.controller.BaseInfoResponse(false, ""))

	w.Header().Set("Content-Type", "application/x-protobuf")
	if _, err := w.Write(response); err != nil {
		http.Error(w, "Failed to write response", http.StatusInternalServerError)
		return
	}
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

	response, _ := proto.Marshal(s.controller.BaseInfoResponse(true, ""))

	w.Header().Set("Content-Type", "application/x-protobuf")
	if _, err = w.Write(response); err != nil {
		http.Error(w, "Failed to write response", http.StatusInternalServerError)
		return
	}
}

func (s *Service) Stop(w http.ResponseWriter, _ *http.Request) {
	log.Println(s.GetIP(), " disconnected, Session ID = ", s.controller.GetSessionID())
	s.disconnect()

	response, _ := proto.Marshal(&common.Empty{})

	w.Header().Set("Content-Type", "application/x-protobuf")
	if _, err := w.Write(response); err != nil {
		http.Error(w, "Failed to write response", http.StatusInternalServerError)
		return
	}
}

func (s *Service) detectBackend(r *http.Request) (context.Context, common.BackendType, error) {
	var data common.Backend
	var ctx context.Context

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, 0, err
	}
	defer r.Body.Close()

	// Decode into a map
	if err = proto.Unmarshal(body, &data); err != nil {
		return nil, 0, err
	}

	if data.Type == common.BackendType_XRAY {
		config, err := xray.NewXRayConfig(data.Config)
		if err != nil {
			return nil, 0, err
		}
		ctx = context.WithValue(r.Context(), backend.ConfigKey{}, config)
	} else {
		return ctx, data.Type, errors.New("invalid backend type")
	}

	ctx = context.WithValue(ctx, backend.UsersKey{}, data.GetUsers())

	return ctx, data.Type, nil
}
