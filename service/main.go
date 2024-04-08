package service

import (
	"encoding/json"
	"github.com/go-chi/chi/v5"
	log "marzban-node/logger"
	"marzban-node/middleware"
	"marzban-node/xray"
	"net/http"

	"github.com/google/uuid"
)

type Service struct {
	Router      chi.Router
	Connected   bool
	ClientIP    string
	SessionID   uuid.UUID
	Core        *xray.Core
	CoreVersion string
	Config      xray.Config
}

func NewService() *Service {
	core, err := xray.NewXRayCore()
	if err != nil {
		log.ErrorLog("Failed to create new core: ", err)
	}

	s := &Service{
		Router: chi.NewRouter(),
		Core:   core,
	}
	s.CoreVersion = s.Core.Version

	s.Router.Use(middleware.LogRequest)

	s.Router.Post("/", s.Base)
	s.Router.Post("/ping", s.Ping)
	s.Router.Post("/connect", s.Connect)
	s.Router.Post("/disconnect", s.Disconnect)
	s.Router.Post("/start", s.Start)
	s.Router.Post("/stop", s.Stop)
	s.Router.Post("/restart", s.Restart)

	s.Router.HandleFunc("/logs", s.Logs)

	return s
}

func (s *Service) Base(w http.ResponseWriter, _ *http.Request) {
	json.NewEncoder(w).Encode(s.response())
}

func (s *Service) response(extra ...interface{}) map[string]interface{} {
	res := map[string]interface{}{
		"connected":    s.Connected,
		"started":      s.Core.Started(),
		"core_version": s.CoreVersion,
	}
	for i := 0; i < len(extra); i += 2 {
		res[extra[i].(string)] = extra[i+1]
	}
	return res
}
