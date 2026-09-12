package rest

import (
	"errors"
	"net/http"

	"github.com/pasarguard/node/common"
)

func (s *Service) Base(w http.ResponseWriter, _ *http.Request) {
	common.SendProtoResponse(w, s.BaseInfoResponse())
}

func (s *Service) Start(w http.ResponseWriter, r *http.Request) {
	if err := disableWriteDeadline(w); err != nil && !errors.Is(err, http.ErrNotSupported) {
		http.Error(w, "failed to configure lifecycle response deadline", http.StatusInternalServerError)
		return
	}
	stopCancelDeadline := stopWritesOnContext(r.Context(), w)
	defer stopCancelDeadline()

	s.LockControl()
	defer s.UnlockControl()

	data := &common.Backend{}

	if err := common.ReadProtoBody(r.Body, data); err != nil {
		if errors.Is(err, common.ErrProtoBodyTooLarge) {
			http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ip, ok := requestClientIP(r)
	if !ok {
		http.Error(w, "unknown ip", http.StatusServiceUnavailable)
		return
	}

	if s.Backend() != nil && !s.IsCurrentClient(ip) {
		http.Error(w, "node is controlled by another client", http.StatusForbidden)
		return
	}

	if err := s.StartBackendControlled(r.Context(), data, ip); err != nil {
		writeUserSyncError(w, err, http.StatusServiceUnavailable)
		return
	}
	common.SendProtoResponse(w, s.BaseInfoResponse())
}

func (s *Service) Stop(w http.ResponseWriter, r *http.Request) {
	if err := disableWriteDeadline(w); err != nil && !errors.Is(err, http.ErrNotSupported) {
		http.Error(w, "failed to configure lifecycle response deadline", http.StatusInternalServerError)
		return
	}
	stopCancelDeadline := stopWritesOnContext(r.Context(), w)
	defer stopCancelDeadline()

	s.LockControl()
	defer s.UnlockControl()

	s.DisconnectControlled()

	common.SendProtoResponse(w, &common.Empty{})
}
