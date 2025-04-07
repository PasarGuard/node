package common

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"strings"

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

func EnsureBase64Password(password string, method string) string {
	// First check if it's already a valid base64 string
	decodedBytes, err := base64.StdEncoding.DecodeString(password)
	if err == nil {
		// It's already base64, now check if length is appropriate
		if (strings.Contains(method, "aes-128-gcm") && len(decodedBytes) == 16) ||
			((strings.Contains(method, "aes-256-gcm") || strings.Contains(method, "chacha20-poly1305")) && len(decodedBytes) == 32) {
			// Already correct length
			return password
		}
	}

	// Hash the password to get a consistent byte array
	hasher := sha256.New()
	hasher.Write([]byte(password))
	hashBytes := hasher.Sum(nil)

	// Resize based on method
	var keyBytes []byte
	if strings.Contains(method, "aes-128-gcm") {
		keyBytes = hashBytes[:16] // First 16 bytes for AES-128
	} else {
		keyBytes = hashBytes[:32] // First 32 bytes for AES-256 or ChaCha20
	}

	return base64.StdEncoding.EncodeToString(keyBytes)
}
