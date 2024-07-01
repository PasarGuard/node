package service

import (
	"encoding/json"
	"fmt"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	log "marzban-node/logger"
	"net"
	"net/http"
)

func (s *Service) checkSessionID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// check ip
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if ip != s.ClientIP {
			http.Error(w, "IP address is not valid", http.StatusForbidden)
			return
		}

		// check session id
		var body session
		err = json.NewDecoder(r.Body).Decode(&body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		sessionID, err := uuid.Parse(body.SessionId)
		if err != nil {
			http.Error(w, "please send valid uuid", http.StatusBadRequest)
			return
		}

		if sessionID != s.SessionID {
			http.Error(w, "Session ID mismatch.", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func LogRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)

		logMessage := fmt.Sprintf("%s, %s, %s, %d \n", r.RemoteAddr, r.Method, r.URL.Path, ww.Status())
		log.ApiLog(logMessage)
	})
}
