package rpc

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pasarguard/node/backend"
)

// syncErrorCode is the code of a failed user sync. A backend that is busy or
// restarting marks its error retry-later (backend.RetryLaterError): that is
// Unavailable, so a client retries the batch as a whole. Anything else is
// Internal, which bridge 0.9.4 reads as its users being refused and narrows
// down by splitting the batch.
func syncErrorCode(err error) codes.Code {
	if backend.IsRetryLater(err) {
		return codes.Unavailable
	}
	return codes.Internal
}

// syncUsersError is what SyncUsers answers for err: the error as it is
// (gRPC Unknown), or Unavailable with the same text when it is retry-later.
func syncUsersError(err error) error {
	if backend.IsRetryLater(err) {
		return status.Error(codes.Unavailable, err.Error())
	}
	return err
}
