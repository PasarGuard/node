package rest

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"google.golang.org/protobuf/proto"
)

func (s *Service) GetOutboundsStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.controller.GetBackend().GetOutboundsStats(r.Context(), true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	response, _ := proto.Marshal(stats)

	w.Header().Set("Content-Type", "application/x-protobuf")
	if _, err = w.Write(response); err != nil {
		http.Error(w, "Failed to write response", http.StatusInternalServerError)
		return
	}
}

func (s *Service) GetOutboundStats(w http.ResponseWriter, r *http.Request) {
	tag := chi.URLParam(r, "tag")
	if tag == "" {
		http.Error(w, "missing tag", http.StatusBadRequest)
		return
	}

	stats, err := s.controller.GetBackend().GetOutboundStats(r.Context(), tag, true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	response, _ := proto.Marshal(stats)

	w.Header().Set("Content-Type", "application/x-protobuf")
	if _, err = w.Write(response); err != nil {
		http.Error(w, "Failed to write response", http.StatusInternalServerError)
		return
	}
}

func (s *Service) GetInboundsStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.controller.GetBackend().GetInboundsStats(r.Context(), true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	response, _ := proto.Marshal(stats)

	w.Header().Set("Content-Type", "application/x-protobuf")
	if _, err = w.Write(response); err != nil {
		http.Error(w, "Failed to write response", http.StatusInternalServerError)
		return
	}
}

func (s *Service) GetInboundStats(w http.ResponseWriter, r *http.Request) {
	tag := chi.URLParam(r, "tag")
	if tag == "" {
		http.Error(w, "missing tag", http.StatusBadRequest)
		return
	}

	stats, err := s.controller.GetBackend().GetInboundStats(r.Context(), tag, true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	response, _ := proto.Marshal(stats)

	w.Header().Set("Content-Type", "application/x-protobuf")
	if _, err = w.Write(response); err != nil {
		http.Error(w, "Failed to write response", http.StatusInternalServerError)
		return
	}
}

func (s *Service) GetUsersStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.controller.GetBackend().GetUsersStats(r.Context(), true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	response, _ := proto.Marshal(stats)

	w.Header().Set("Content-Type", "application/x-protobuf")
	if _, err = w.Write(response); err != nil {
		http.Error(w, "Failed to write response", http.StatusInternalServerError)
		return
	}
}

func (s *Service) GetUserStats(w http.ResponseWriter, r *http.Request) {
	email := chi.URLParam(r, "email")
	if email == "" {
		http.Error(w, "missing email", http.StatusBadRequest)
		return
	}

	stats, err := s.controller.GetBackend().GetUserStats(r.Context(), email, true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	response, _ := proto.Marshal(stats)

	w.Header().Set("Content-Type", "application/x-protobuf")
	if _, err = w.Write(response); err != nil {
		http.Error(w, "Failed to write response", http.StatusInternalServerError)
		return
	}
}

func (s *Service) GetUserOnlineStat(w http.ResponseWriter, r *http.Request) {
	email := chi.URLParam(r, "email")
	if email == "" {
		http.Error(w, "missing email", http.StatusBadRequest)
		return
	}

	stats, err := s.controller.GetBackend().GetStatOnline(r.Context(), email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	response, _ := proto.Marshal(stats)

	w.Header().Set("Content-Type", "application/x-protobuf")
	if _, err = w.Write(response); err != nil {
		http.Error(w, "Failed to write response", http.StatusInternalServerError)
		return
	}
}

func (s *Service) GetBackendStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.controller.GetBackend().GetSysStats(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	response, _ := proto.Marshal(stats)

	w.Header().Set("Content-Type", "application/x-protobuf")
	if _, err = w.Write(response); err != nil {
		http.Error(w, "Failed to write response", http.StatusInternalServerError)
		return
	}
}

func (s *Service) GetSystemStats(w http.ResponseWriter, _ *http.Request) {
	data, _ := proto.Marshal(s.controller.GetStats())

	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(data); err != nil {
		http.Error(w, "Failed to write response", http.StatusInternalServerError)
		return
	}
}
