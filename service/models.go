package service

import (
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"marzban-node/xray"
	"marzban-node/xray_api"
)

type session struct {
	SessionId string `json:"session_id"`
}

type Service struct {
	Router        chi.Router
	Connected     bool
	ClientIP      string
	SessionID     uuid.UUID
	Core          *xray.Core
	CoreVersion   string
	Config        xray.Config
	ApiPort       int
	HandlerClient *xray_api.XrayClient
}

type startBody struct {
	session
	Config xray.Config
}
