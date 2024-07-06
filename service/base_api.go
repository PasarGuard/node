package service

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	log "marzban-node/logger"
)

const NodeVersion = "go-0.0.1"

func (s *Service) Base(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.response())
}

func (s *Service) Connect(w http.ResponseWriter, r *http.Request) {
	sessionID := uuid.New()
	s.SetSessionID(sessionID)

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return
	}

	s.SetIP(ip)

	if s.IsConnected() {
		log.Info("New connection from ", ip, " core control access was taken away from previous client.")
		s.core.Stop()
	}

	s.SetConnected(true)

	log.Info(ip, " connected, Session ID = ", sessionID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.response("session_id", sessionID))
}

func (s *Service) Disconnect(w http.ResponseWriter, _ *http.Request) {
	if s.IsConnected() {
		log.Info(s.clientIP, " disconnected, Session ID = ", s.GetSessionID())
	}

	s.SetSessionID(uuid.Nil)
	s.SetIP("")
	s.SetConnected(false)

	core := s.GetCore()

	if core.Started() {
		core.Stop()
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
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	newConfig := body.Config
	if newConfig == nil {
		http.Error(w, "no config received", http.StatusNotAcceptable)
		return
	}

	err = newConfig.ApplyAPI(s.GetAPIPort())
	if err != nil {
		log.Error("Failed to apply API: ", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	err = s.GetCore().Start(newConfig)
	if err != nil {
		log.Error("Failed to start core: ", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	err = s.checkXrayStatus()
	if err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.SetConfig(newConfig)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.response())
}

func (s *Service) Stop(w http.ResponseWriter, _ *http.Request) {
	s.GetCore().Stop()

	s.SetConfig(nil)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.response())
}

func (s *Service) Restart(w http.ResponseWriter, r *http.Request) {
	var body startBody
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	newConfig := body.Config
	if newConfig == nil {
		http.Error(w, "no config received", http.StatusNotAcceptable)
		return
	}

	err = s.GetCore().Restart(newConfig)
	if err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	err = s.checkXrayStatus()
	if err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.SetConfig(newConfig)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.response())
}

func (s *Service) checkXrayStatus() error {
	core := s.GetCore()

	logChan := core.GetLogs()
	version := core.GetVersion()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

Loop:
	for {
		select {
		case lastLog := <-logChan:
			if strings.Contains(lastLog, "Xray "+version+" started") {
				break Loop
			} else {
				regex := regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[([^]]+)\] (.+)$`)
				matches := regex.FindStringSubmatch(lastLog)
				if len(matches) > 3 && matches[2] == "Error" {
					return errors.New("Failed to start xray: " + matches[3])
				}
			}
		case <-ctx.Done():
			return errors.New("Failed to start xray: context done.")
		}
	}
	return nil
}

func (s *Service) response(extra ...interface{}) map[string]interface{} {
	core := s.GetCore()
	res := map[string]interface{}{
		"connected":    s.IsConnected(),
		"started":      core.Started(),
		"core_version": core.GetVersion(),
		"node_version": NodeVersion,
	}
	for i := 0; i < len(extra); i += 2 {
		res[extra[i].(string)] = extra[i+1]
	}
	return res
}
