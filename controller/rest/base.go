package rest

import (
	"net/http"

	"github.com/pasarguard/node/common"
)

func (s *Service) Base(w http.ResponseWriter, _ *http.Request) {
	common.SendProtoResponse(w, s.BaseInfoResponse())
}

func (s *Service) Start(w http.ResponseWriter, r *http.Request) {
	data := &common.Backend{}

	if err := common.ReadProtoBody(r.Body, data); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.LockControl(data.GetCoreId())
	defer s.UnlockControl(data.GetCoreId())

	if err := s.StartOrAttach(r.Context(), data); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	common.SendProtoResponse(w, s.BaseInfoResponse())
}

func (s *Service) Stop(w http.ResponseWriter, _ *http.Request) {
	s.LockControl(0)
	defer s.UnlockControl(0)

	s.Disconnect()

	common.SendProtoResponse(w, &common.Empty{})
}
