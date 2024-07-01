package service

import (
	"github.com/go-chi/chi/v5"
)

func NewService() (*Service, error) {

	s := new(Service)
	err := s.Init()
	if err != nil {
		return nil, err
	}

	s.startJobs()

	router := s.GetRouter()

	// Api Handlers
	router.Use(LogRequest)

	router.Post("/", s.Base)
	router.Post("/connect", s.Connect)
	router.HandleFunc("/logs", s.Logs)

	router.Group(func(protected chi.Router) {
		// middleware
		protected.Use(s.CheckSessionID)

		router.Post("/ping", s.Ping)
		router.Post("/start", s.Start)
		router.Post("/stop", s.Stop)
		router.Post("/restart", s.Restart)
		router.Post("/disconnect", s.Disconnect)
	})

	// users api
	router.Group(func(userGroup chi.Router) {
		userGroup.Use(s.CheckSessionID)
		userGroup.Mount("/user", userGroup)

		router.Post("/add", s.AddUser)
		router.Post("/update", s.UpdateUser)
		router.Post("/remove", s.RemoveUser)
	})

	// stats api
	router.Group(func(statsGroup chi.Router) {
		statsGroup.Use(s.CheckSessionID)
		statsGroup.Mount("/stats", statsGroup)

		router.Post("/users", s.GetUsersStats)
		router.Post("/inbounds", s.GetInboundsStats)
		router.Post("/outbounds", s.GetOutboundsStats)
		router.Post("/system", s.GetSystemStats)
		router.Post("/nodes", s.GetNodeStats)
	})

	return s, nil
}
