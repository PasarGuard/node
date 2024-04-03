package service

import (
	"encoding/json"
	"github.com/google/uuid"
	"log"
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
		log.Printf("New connection from %s, Core control access was taken away from previous client.", s.ClientIP)
		if s.Core.Started() {
			s.Core.Stop()
		}
	}

	s.Connected = true
	log.Printf("%s connected, Session ID = \"%s\".", s.ClientIP, s.SessionID)

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

func (s *Service) Disconnect(w http.ResponseWriter, r *http.Request) {
	if s.Connected {
		log.Printf("%s disconnected, Session ID = \"%s\".", s.ClientIP, s.SessionID)
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

	logs := s.Core.GetLogs()
	// TODO: close function
	// defer logs.Close()

	err = s.Core.Start(*config)
	if err != nil {
		log.Printf("Failed to start core: %s", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

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
