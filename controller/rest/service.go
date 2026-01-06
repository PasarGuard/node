package rest

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/pasarguard/node/config"
	"github.com/pasarguard/node/controller"
)

func New(cfg *config.Config) *Service {
	s := &Service{
		Controller: *controller.New(cfg),
	}
	s.setRouter()
	return s
}

func (s *Service) setRouter() {
	router := chi.NewRouter()

	// Api Handlers
	router.Use(LogRequest)
	router.Use(s.validateApiKey)
	router.Use(s.trackSuccessfulRequest)
	router.Use(middleware.Recoverer)

	router.Post("/start", s.Start)
	router.Get("/info", s.Base)

	router.Group(func(private chi.Router) {
		private.Use(s.checkBackendMiddleware)

		private.Put("/stop", s.Stop)
		private.Get("/logs", s.GetLogs)
		// stats api
		private.Route("/stats", func(statsGroup chi.Router) {
			statsGroup.Get("/", s.GetStats)
			statsGroup.Get("/user/online", s.GetUserOnlineStat)
			statsGroup.Get("/user/online_ip", s.GetUserOnlineIpListStats)
			statsGroup.Get("/backend", s.GetBackendStats)
			statsGroup.Get("/system", s.GetSystemStats)
		})
		private.Put("/user/sync", s.SyncUser)
		private.Put("/users/sync", s.SyncUsers)
		private.Put("/users/sync/chunked", s.SyncUsersChunked)
	})

	s.Router = router
}

type Service struct {
	controller.Controller
	Router chi.Router
}

func StartHttpListener(tlsConfig *tls.Config, addr string, cfg *config.Config) (func(ctx context.Context) error, controller.Service, error) {
	s := New(cfg)

	httpServer := &http.Server{
		Addr:      addr,
		TLSConfig: tlsConfig,
		Handler:   s.Router,
	}

	// Test if we can listen on the port before starting the goroutine
	listener, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return nil, nil, err
	}

	go func() {
		log.Println("HTTP Server listening on", addr)
		log.Println("Press Ctrl+C to stop")
		if err := httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	// Return a shutdown function for HTTP server
	return httpServer.Shutdown, s, nil
}
