package rest

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
)

func (s *Service) validateApiKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "missing authorization header", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 {
			http.Error(w, "invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		// check API key
		apiKey := s.GetApiKey()

		tokenString := parts[1]
		sessionID, err := uuid.Parse(tokenString)
		switch {
		case err != nil:
			http.Error(w, "please send valid uuid", http.StatusUnprocessableEntity)
			return
		case sessionID != apiKey:
			http.Error(w, "api key mismatch.", http.StatusForbidden)
			return
		}

		s.NewRequest()
		next.ServeHTTP(w, r)
	})
}

func (s *Service) checkBackendMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		back := s.GetBackend()
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
