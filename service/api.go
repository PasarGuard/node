package service

import (
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	log "marzban-node/logger"
	"marzban-node/xray"
	"net"
	"net/http"
	"strings"
	"time"
)

func (s *Service) Connect(w http.ResponseWriter, r *http.Request) {
	s.SessionID = uuid.New()

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return
	}

	s.ClientIP = ip

	if s.Connected {
		logMessage := fmt.Sprintf("New connection from %s, Core control access was taken away from previous client.", s.ClientIP)
		log.InfoLog(logMessage)
		if s.Core.Started() {
			s.Core.Stop()
		}
	}

	s.Connected = true

	logMessage := fmt.Sprintf("%s connected, Session ID = \"%s\".", s.ClientIP, s.SessionID)
	log.InfoLog(logMessage)

	json.NewEncoder(w).Encode(s.response("session_id", s.SessionID))
}

func (s *Service) Ping(w http.ResponseWriter, r *http.Request) {
	var body map[string]interface{}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	sessionID, err := uuid.Parse(body["session_id"].(string))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if sessionID != s.SessionID {
		http.Error(w, "Session ID mismatch.", http.StatusForbidden)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{})
}

func (s *Service) Disconnect(w http.ResponseWriter, _ *http.Request) {
	if s.Connected {
		logMessage := fmt.Sprintf("%s disconnected, Session ID = \"%s\".", s.ClientIP, s.SessionID)
		log.InfoLog(logMessage)
	}

	s.SessionID = uuid.Nil
	s.ClientIP = ""
	s.Connected = false

	if s.Core.Started() {
		s.Core.Stop()
	}

	json.NewEncoder(w).Encode(s.response())
}

func (s *Service) Start(w http.ResponseWriter, r *http.Request) {
	var body map[string]interface{}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	sessionID, err := uuid.Parse(body["session_id"].(string))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if sessionID != s.SessionID {
		http.Error(w, "Session ID mismatch.", http.StatusForbidden)
		return
	}

	config, err := xray.NewXRayConfig(body["config"].(string), s.ClientIP)
	if err != nil {
		http.Error(w, "Failed to decode config: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}

	err = s.Core.Start(*config)
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

	json.NewEncoder(w).Encode(s.response())
}

func (s *Service) Stop(w http.ResponseWriter, r *http.Request) {
	var body map[string]interface{}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	sessionID, err := uuid.Parse(body["session_id"].(string))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if sessionID != s.SessionID {
		http.Error(w, "Session ID mismatch.", http.StatusForbidden)
		return
	}

	s.Core.Stop()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(s.response())
}

func (s *Service) Restart(w http.ResponseWriter, r *http.Request) {
	var body map[string]interface{}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	sessionID, err := uuid.Parse(body["session_id"].(string))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if sessionID != s.SessionID {
		http.Error(w, "Session ID mismatch.", http.StatusForbidden)
		return
	}

	config, err := xray.NewXRayConfig(body["config"].(string), s.ClientIP)
	if err != nil {
		http.Error(w, "Failed to decode config: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}

	s.Core.Restart(*config)

	json.NewEncoder(w).Encode(s.response())
}
