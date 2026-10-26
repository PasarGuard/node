package rpc

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pasarguard/node/backend"
)

// Bridge 0.9.4 reads an INTERNAL answer to SyncUsersChunked as its users
// being refused and splits the batch to find them; any other code is a
// failure to retry as a whole. A backend that is busy or restarting marks its
// error retry-later (only MTProto does), and the node must answer that as
// Unavailable with the same text. Xray and WireGuard errors keep their codes.
func TestSyncErrorCodes(t *testing.T) {
	plain := errors.New("failed to add user 1 to inbound vless-in: boom") // xray or WireGuard
	busy := backend.RetryLater(fmt.Errorf("the users are still being applied: %w", context.DeadlineExceeded))

	for name, tc := range map[string]struct {
		err  error
		want codes.Code
	}{
		"xray or wireguard error": {plain, codes.Internal},
		"retry-later":             {busy, codes.Unavailable},
		"wrapped retry-later":     {fmt.Errorf("apply: %w", busy), codes.Unavailable},
	} {
		if got := syncErrorCode(tc.err); got != tc.want {
			t.Errorf("%s: SyncUser and SyncUsersChunked code = %s, want %s", name, got, tc.want)
		}
	}

	// SyncUsers answers the backend's error as it is, so gRPC sends it as
	// Unknown; only a retry-later error becomes Unavailable, same text.
	if got := syncUsersError(plain); got != plain {
		t.Errorf("SyncUsers changed an xray or WireGuard error: %v", got)
	}
	got := status.Convert(syncUsersError(busy))
	if got.Code() != codes.Unavailable || got.Message() != busy.Error() {
		t.Errorf("SyncUsers answered a retry-later error as %s %q, want Unavailable %q", got.Code(), got.Message(), busy.Error())
	}
}
