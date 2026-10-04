package rest

import (
	"net/http"

	"github.com/pasarguard/node/common"
	"google.golang.org/grpc/status"
)

func (s *Service) CollectUsage(w http.ResponseWriter, r *http.Request) {
	var request common.UsageRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	if err := common.ReadProtoBody(r.Body, &request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	receipt, err := s.Controller.CollectUsage(r.Context(), &request)
	if err != nil {
		http.Error(w, err.Error(), common.GrpcCodeToHTTP(status.Code(err)))
		return
	}
	common.SendProtoResponse(w, receipt)
}

func (s *Service) AcknowledgeUsage(w http.ResponseWriter, r *http.Request) {
	var request common.UsageAck
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	if err := common.ReadProtoBody(r.Body, &request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	response, err := s.Controller.AcknowledgeUsage(r.Context(), &request)
	if err != nil {
		http.Error(w, err.Error(), common.GrpcCodeToHTTP(status.Code(err)))
		return
	}
	common.SendProtoResponse(w, response)
}
