package service

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"marzban-node/config"
	log "marzban-node/logger"
	"marzban-node/tools"
	"marzban-node/xray_api"
)

const NodeVersion = "go-0.0.1"

func (s *Service) Base(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.response())
}

func (s *Service) Connect(w http.ResponseWriter, r *http.Request) {
	s.SessionID = uuid.New()

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return
	}

	s.ClientIP = ip

	if s.Connected {
		log.InfoLog("New connection from ", s.ClientIP, " Core control access was taken away from previous client.")
		if s.Core.Started() {
			s.Core.Stop()
		}
	}

	s.Connected = true

	log.InfoLog(s.ClientIP, " connected, Session ID = ", s.SessionID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.response("session_id", s.SessionID))
}

func (s *Service) Disconnect(w http.ResponseWriter, _ *http.Request) {
	if s.Connected {
		log.InfoLog(s.ClientIP, " disconnected, Session ID = ", s.SessionID)
	}

	s.SessionID = uuid.Nil
	s.ClientIP = ""
	s.Connected = false

	if s.Core.Started() {
		s.Core.Stop()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.response())
}

func (s *Service) Ping(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{})
}

func (s *Service) Start(w http.ResponseWriter, r *http.Request) {
	var body startBody
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		http.Error(w, "Failed to decode config: "+err.Error(), http.StatusBadRequest)
		return
	}

	body.Config.ApplyAPI(s.ApiPort)

	err = s.Core.Start(body.Config)
	if err != nil {
		log.ErrorLog("Failed to start core: ", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	logs := s.Core.GetLogs()

	startTime := time.Now()
	endTime := startTime.Add(3 * time.Second)
	for time.Now().Before(endTime) {
		for _, newLog := range logs {
			if strings.Contains(newLog, "Xray "+s.CoreVersion+" started") {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	if !s.Core.Started() {
		http.Error(w, "Failed to start core.", http.StatusServiceUnavailable)
		return
	}

	err = s.makeHandler()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.response())
}

func (s *Service) Stop(w http.ResponseWriter, _ *http.Request) {
	s.Core.Stop()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.response())
}

func (s *Service) Restart(w http.ResponseWriter, r *http.Request) {
	var body startBody
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		http.Error(w, "Failed to decode config: "+err.Error(), http.StatusBadRequest)
		return
	}

	body.Config.ApplyAPI(s.ApiPort)

	s.Core.Restart(body.Config)

	err = s.makeHandler()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.response())
}

func (s *Service) response(extra ...interface{}) map[string]interface{} {
	res := map[string]interface{}{
		"connected":    s.Connected,
		"started":      s.Core.Started(),
		"core_version": s.CoreVersion,
		"node_version": NodeVersion,
	}
	for i := 0; i < len(extra); i += 2 {
		res[extra[i].(string)] = extra[i+1]
	}
	return res
}

func (s *Service) makeHandler() error {
	sslCert, err := tools.ReadFileAsString(config.SslClientCertFile)
	if err != nil {
		return err
	}

	s.HandlerClient, err = xray_api.NewXrayClient("127.0.0.1", s.ApiPort, sslCert, "Gozargah")
	if err != nil {
		return err
	} else {
		return nil
	}
}
