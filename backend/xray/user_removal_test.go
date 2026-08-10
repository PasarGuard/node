package xray

import (
	"errors"
	"testing"

	"github.com/pasarguard/node/backend/xray/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestIsBenignUserRemovalError(t *testing.T) {
	absentInbound := &Inbound{clients: make(map[string]api.Account)}
	for _, err := range []error{
		nil,
		status.Error(codes.NotFound, "user not found"),
		status.Error(codes.Unknown, "proxy/trojan: User user@example.com not found."),
		status.Error(codes.Unknown, "app/proxyman/command: proxy is not a UserManager"),
		status.Error(codes.Unknown, "opaque handler response"),
	} {
		if !isBenignUserRemovalError(err, absentInbound, "user@example.com") {
			t.Fatalf("expected benign removal error: %v", err)
		}
	}

	presentInbound := &Inbound{clients: map[string]api.Account{
		"user@example.com": trojanAccount("user@example.com", "secret"),
	}}
	for _, err := range []error{
		status.Error(codes.Unknown, "user not found"),
		status.Error(codes.Unavailable, "connection refused"),
		status.Error(codes.DeadlineExceeded, "deadline exceeded"),
		errors.New("user not found"),
		errors.New("local handler failure"),
	} {
		if isBenignUserRemovalError(err, presentInbound, "user@example.com") {
			t.Fatalf("unexpectedly accepted runtime failure: %v", err)
		}
	}
}
