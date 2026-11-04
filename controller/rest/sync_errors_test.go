package rest

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/pasarguard/node/backend"
)

// Bridge 0.9.4 reads a 500 answer to /users/sync/chunked as its users being
// refused and splits the batch to find them; a 503 is a failure to retry as a
// whole. A backend that is busy or restarting marks its error retry-later
// (only MTProto does), and the node must answer that as 503 with the same
// body. Xray and WireGuard errors keep their 500.
func TestSyncErrorStatus(t *testing.T) {
	plain := errors.New("failed to add user 1 to inbound vless-in: boom") // xray or WireGuard
	busy := backend.RetryLater(fmt.Errorf("the users are still being applied: %w", context.DeadlineExceeded))

	for name, tc := range map[string]struct {
		err  error
		want int
	}{
		"xray or wireguard error": {plain, http.StatusInternalServerError},
		"retry-later":             {busy, http.StatusServiceUnavailable},
		"wrapped retry-later":     {fmt.Errorf("apply: %w", busy), http.StatusServiceUnavailable},
	} {
		if got := syncErrorStatus(tc.err); got != tc.want {
			t.Errorf("%s: status = %d, want %d", name, got, tc.want)
		}
	}
}
