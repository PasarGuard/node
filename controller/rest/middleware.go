package rest

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
)

func (s *Service) checkSessionIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// check ip
		clientIP := s.GetIP()
		clientID := s.controller.GetSessionID()
		if clientIP == "" || clientID == uuid.Nil {
			http.Error(w, "please connect first", http.StatusTooEarly)
			return
		}

		// check ip
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		switch {
		case err != nil:
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		case ip != s.GetIP():
			http.Error(w, "IP address is not valid", http.StatusForbidden)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "please connect first", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 {
			http.Error(w, "invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		tokenString := parts[1]
		sessionID, err := uuid.Parse(tokenString)
		switch {
		case err != nil:
			http.Error(w, "please send valid uuid", http.StatusUnprocessableEntity)
			return
		case sessionID != clientID:
			http.Error(w, "session id mismatch.", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Service) checkBackendMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		back := s.controller.GetBackend()
		if back == nil {
			http.Error(w, "backend not initialized", http.StatusInternalServerError)
			return
		}
		if !back.Started() {
			http.Error(w, "core is not started yet", http.StatusServiceUnavailable)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func LogRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		log.Println(fmt.Sprintf("[API] New requesrt from %s, %s, %s", r.RemoteAddr, r.Method, r.URL.Path))

		next.ServeHTTP(ww, r)

		log.Println(fmt.Sprintf("[API] %s, %s, %s, %d", r.RemoteAddr, r.Method, r.URL.Path, ww.Status()))
	})
}
