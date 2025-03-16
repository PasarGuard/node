package rest

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/go-chi/chi/v5"
	"github.com/m03ed/gozargah-node/controller"
	"log"
	"net/http"
)

func NewService() *Service {
	s := &Service{}
	s.Init()
	s.setRouter()
	return s
}

func (s *Service) setRouter() {
	router := chi.NewRouter()

	// Api Handlers
	router.Use(LogRequest)

	router.Post("/start", s.Start)

	router.Group(func(protected chi.Router) {
		// check session and need to return data as context
		protected.Use(s.checkSessionIDMiddleware)

		protected.Get("/info", s.Base)
		protected.Put("/stop", s.Stop)
		protected.Get("/logs", s.GetLogs)

		protected.Get("/stats/system", s.GetSystemStats)

		protected.Group(func(private chi.Router) {
			private.Use(s.checkBackendMiddleware)

			// stats api
			private.Route("/stats", func(statsGroup chi.Router) {
				statsGroup.Get("/inbounds", s.GetInboundsStats)
				statsGroup.Get("/inbound", s.GetInboundStats)
				statsGroup.Get("/outbounds", s.GetOutboundsStats)
				statsGroup.Get("/outbound", s.GetOutboundStats)
				statsGroup.Get("/users", s.GetUsersStats)
				statsGroup.Get("/user", s.GetUserStats)
				statsGroup.Get("/user/online", s.GetUserOnlineStat)
				statsGroup.Get("/user/online_ip", s.GetUserOnlineIpListStats)
				statsGroup.Get("/backend", s.GetBackendStats)
			})
			private.Put("/user/sync", s.SyncUser)
			private.Put("/users/sync", s.SyncUsers)
		})
	})

	s.Router = router
}

type Service struct {
	controller.Controller
	Router chi.Router
}

func StartHttpListener(tlsConfig *tls.Config, addr string) (func(ctx context.Context) error, controller.Service, error) {
	s := NewService()

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
