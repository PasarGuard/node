package rest

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"

	"github.com/pasarguard/node/backend"
	"github.com/pasarguard/node/backend/xray"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/controller"
)

func (s *Service) Base(w http.ResponseWriter, _ *http.Request) {
	common.SendProtoResponse(w, s.BaseInfoResponse())
}

func (s *Service) Start(w http.ResponseWriter, r *http.Request) {
	ctx, backendType, keepAlive, limitParams, err := s.detectBackend(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "unknown ip", http.StatusServiceUnavailable)
		return
	}

	if s.Backend() != nil {
		log.Println("New connection from ", ip, " core control access was taken away from previous client.")
		s.Disconnect()
	}

	s.Connect(ip, keepAlive)

	if err = s.StartBackend(ctx, backendType); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// Start limit enforcer if panel provided configuration
	s.StartLimitEnforcer(limitParams)

	common.SendProtoResponse(w, s.BaseInfoResponse())
}

func (s *Service) Stop(w http.ResponseWriter, _ *http.Request) {
	s.Disconnect()

	common.SendProtoResponse(w, &common.Empty{})
}

func (s *Service) detectBackend(r *http.Request) (context.Context, common.BackendType, uint64, controller.LimitEnforcerParams, error) {
	var data common.Backend
	var ctx context.Context

	if err := common.ReadProtoBody(r.Body, &data); err != nil {
		return nil, 0, 0, controller.LimitEnforcerParams{}, err
	}

	if data.Type == common.BackendType_XRAY {
		config, err := xray.NewXRayConfig(data.GetConfig(), data.GetExcludeInbounds())
		if err != nil {
			return nil, 0, 0, controller.LimitEnforcerParams{}, err
		}
		ctx = context.WithValue(r.Context(), backend.ConfigKey{}, config)
	} else {
		return ctx, data.GetType(), data.GetKeepAlive(), controller.LimitEnforcerParams{}, errors.New("invalid backend type")
	}

	ctx = context.WithValue(ctx, backend.UsersKey{}, data.GetUsers())

	limitParams := controller.LimitEnforcerParams{
		NodeID:               data.GetNodeId(),
		PanelAPIURL:          data.GetPanelApiUrl(),
		LimitCheckInterval:   data.GetLimitCheckInterval(),
		LimitRefreshInterval: data.GetLimitRefreshInterval(),
	}

	return ctx, data.GetType(), data.GetKeepAlive(), limitParams, nil
}
