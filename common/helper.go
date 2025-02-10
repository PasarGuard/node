package common

import (
	"io"
	"net/http"

	"google.golang.org/protobuf/proto"
)

func ReadProtoBody(body io.ReadCloser, message proto.Message) error {
	data, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	defer body.Close()

	// Decode into a map
	if err = proto.Unmarshal(data, message); err != nil {
		return err
	}
	return nil
}

func SendProtoResponse(w http.ResponseWriter, data proto.Message) {
	response, _ := proto.Marshal(data)

	w.Header().Set("Content-Type", "application/x-protobuf")
	if _, err := w.Write(response); err != nil {
		http.Error(w, "Failed to write response", http.StatusInternalServerError)
		return
	}
}
