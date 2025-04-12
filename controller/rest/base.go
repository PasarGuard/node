package rest

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"

	"github.com/m03ed/gozargah-node/backend"
	"github.com/m03ed/gozargah-node/backend/xray"
	"github.com/m03ed/gozargah-node/common"
)

func (s *Service) Base(w http.ResponseWriter, _ *http.Request) {
	common.SendProtoResponse(w, s.BaseInfoResponse())
}

func (s *Service) Start(w http.ResponseWriter, r *http.Request) {
	ctx, backendType, keepAlive, err := s.detectBackend(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "unknown ip", http.StatusServiceUnavailable)
		return
	}

	if s.GetBackend() != nil {
		log.Println("New connection from ", ip, " core control access was taken away from previous client.")
		s.Disconnect()
	}

	s.Connect(ip, keepAlive)

	if err = s.StartBackend(ctx, backendType); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	common.SendProtoResponse(w, s.BaseInfoResponse())
}

func (s *Service) Stop(w http.ResponseWriter, _ *http.Request) {
	s.Disconnect()

	common.SendProtoResponse(w, &common.Empty{})
}

func (s *Service) detectBackend(r *http.Request) (context.Context, common.BackendType, uint64, error) {
	var data common.Backend
	var ctx context.Context

	if err := common.ReadProtoBody(r.Body, &data); err != nil {
		return nil, 0, 0, err
	}

	if data.Type == common.BackendType_XRAY {
		config, err := xray.NewXRayConfig(data.Config)
		if err != nil {
			return nil, 0, 0, err
		}
		ctx = context.WithValue(r.Context(), backend.ConfigKey{}, config)
	} else {
		return ctx, data.GetType(), data.GetKeepAlive(), errors.New("invalid backend type")
	}

	ctx = context.WithValue(ctx, backend.UsersKey{}, data.GetUsers())

	return ctx, data.GetType(), data.GetKeepAlive(), nil
}
