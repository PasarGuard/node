package rest

import (
	"log"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
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

		log.Printf("[API] New request from %s, %s, %s\n", r.RemoteAddr, r.Method, r.URL.Path)

		next.ServeHTTP(ww, r)

		log.Printf("[API] %s, %s, %s, %d\n", r.RemoteAddr, r.Method, r.URL.Path, ww.Status())
	})
}

// trackRequest refreshes keep-alive for every authenticated request when it
// arrives and again when it ends, whatever the status: a request that fails,
// times out on the panel side or is still running still proves the panel is
// alive. It must run after validateApiKey.
func (s *Service) trackRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.NewRequest()
		defer s.NewRequest()

		next.ServeHTTP(w, r)
	})
}
