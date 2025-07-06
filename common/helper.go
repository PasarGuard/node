package common

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

// GrpcCodeToHTTP maps gRPC codes to HTTP status codes.
func GrpcCodeToHTTP(code codes.Code) int {
	switch code {
	case codes.OK:
		return http.StatusOK
	case codes.Canceled:
		return 499 // client closed request
	case codes.InvalidArgument:
		return http.StatusBadRequest
	case codes.Unauthenticated:
		return http.StatusUnauthorized
	case codes.PermissionDenied:
		return http.StatusForbidden
	case codes.NotFound:
		return http.StatusNotFound
	case codes.AlreadyExists:
		return http.StatusConflict
	case codes.ResourceExhausted:
		return http.StatusTooManyRequests
	case codes.FailedPrecondition:
		return http.StatusPreconditionFailed
	case codes.Aborted:
		return http.StatusConflict
	case codes.OutOfRange:
		return http.StatusBadRequest
	case codes.Unimplemented:
		return http.StatusNotImplemented
	case codes.Internal:
		return http.StatusInternalServerError
	case codes.Unavailable:
		return http.StatusServiceUnavailable
	case codes.DeadlineExceeded:
		return http.StatusGatewayTimeout
	default:
		return http.StatusInternalServerError
	}
}

// InterceptNotFound checks for errors ending with "not found."
// and wraps them as gRPC NotFound.
func InterceptNotFound(err error) error {
	if err != nil && strings.HasSuffix(err.Error(), "not found.") {
		return status.Error(codes.NotFound, err.Error())
	}
	return err
}
