package rest

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/pasarguard/node/controller"
)

func New() *Service {
	s := &Service{
		Controller: *controller.New(),
	}
	s.setRouter()
	return s
}

func (s *Service) setRouter() {
	router := chi.NewRouter()

	// Api Handlers
	router.Use(LogRequest)
	router.Use(s.validateApiKey)
	router.Use(middleware.Recoverer)

	router.Post("/start", s.Start)
	router.Get("/info", s.Base)

	router.Group(func(private chi.Router) {
		private.Use(s.checkBackendMiddleware)

		router.Put("/stop", s.Stop)
		router.Get("/logs", s.GetLogs)
		// stats api
		private.Route("/stats", func(statsGroup chi.Router) {
			statsGroup.Get("/", s.GetStats)
			statsGroup.Get("/user/online", s.GetUserOnlineStat)
			statsGroup.Get("/user/online_ip", s.GetUserOnlineIpListStats)
			statsGroup.Get("/backend", s.GetBackendStats)
			router.Get("/system", s.GetSystemStats)
		})
		private.Put("/user/sync", s.SyncUser)
		private.Put("/users/sync", s.SyncUsers)
	})

	s.Router = router
}

type Service struct {
	controller.Controller
	Router chi.Router
}

func StartHttpListener(tlsConfig *tls.Config, addr string) (func(ctx context.Context) error, controller.Service, error) {
	s := New()

	httpServer := &http.Server{
		Addr:      addr,
		TLSConfig: tlsConfig,
		Handler:   s.Router,
	}

	go func() {
		log.Println("HTTP Server listening on", addr)
		log.Println("Press Ctrl+C to stop")
		if err := httpServer.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	// Return a shutdown function for HTTP server
	return httpServer.Shutdown, s, nil
}
