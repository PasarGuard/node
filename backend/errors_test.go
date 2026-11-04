package backend

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestRetryLaterKeepsTheErrorAndItsText(t *testing.T) {
	cause := fmt.Errorf("the users are still being applied: %w", context.DeadlineExceeded)
	err := RetryLater(cause)

	if !IsRetryLater(err) || !IsRetryLater(fmt.Errorf("failed to update users: %w", err)) {
		t.Error("a RetryLater error, plain or wrapped, is not reported as retry-later")
	}
	if err.Error() != cause.Error() {
		t.Errorf("RetryLater changed the text: %q, want %q", err, cause)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Error("RetryLater hides the error it marks")
	}
	if IsRetryLater(cause) || IsRetryLater(nil) {
		t.Error("an unmarked error or nil is reported as retry-later")
	}
	if RetryLater(nil) != nil {
		t.Error("RetryLater(nil) is not nil")
	}
}
