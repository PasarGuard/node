package rest

import (
	"fmt"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"log"
	"net/http"
)

func (s *Service) validateApiKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKeyHeader := r.Header.Get("x-api-key")
		if apiKeyHeader == "" {
			http.Error(w, "missing x-api-key header", http.StatusUnauthorized)
			return
		}

		// check API key
		apiKey := s.ApiKey()

		key, err := uuid.Parse(apiKeyHeader)
		switch {
		case err != nil:
			http.Error(w, "invalid api key format: must be a valid UUID", http.StatusUnprocessableEntity)
			return
		case key != apiKey:
			http.Error(w, "api key mismatch", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Service) checkBackendMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		back := s.Backend()
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

		log.Println(fmt.Sprintf("[API] New request from %s, %s, %s", r.RemoteAddr, r.Method, r.URL.Path))

		next.ServeHTTP(ww, r)

		log.Println(fmt.Sprintf("[API] %s, %s, %s, %d", r.RemoteAddr, r.Method, r.URL.Path, ww.Status()))
	})
}

func (s *Service) trackSuccessfulRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		next.ServeHTTP(ww, r)

		// Only track successful requests (status codes 200-299)
		if status := ww.Status(); status >= 200 && status < 300 {
			s.NewRequest()
		}
	})
}
