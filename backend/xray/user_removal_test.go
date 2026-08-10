package xray

import (
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestIsBenignUserRemovalError(t *testing.T) {
	for _, err := range []error{
		nil,
		status.Error(codes.NotFound, "user not found"),
		status.Error(codes.Unknown, "proxy/trojan: User user@example.com not found."),
		status.Error(codes.Unknown, "app/proxyman/command: proxy is not a UserManager"),
	} {
		if !isBenignUserRemovalError(err) {
			t.Fatalf("expected benign removal error: %v", err)
		}
	}

	for _, err := range []error{
		status.Error(codes.Unavailable, "connection refused"),
		status.Error(codes.DeadlineExceeded, "deadline exceeded"),
		errors.New("local handler failure"),
	} {
		if isBenignUserRemovalError(err) {
			t.Fatalf("unexpectedly accepted runtime failure: %v", err)
		}
	}
}
