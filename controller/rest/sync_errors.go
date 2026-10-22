package rest

import (
	"net/http"

	"github.com/pasarguard/node/backend"
)

// syncErrorStatus is the HTTP status of a failed user sync. A backend that is
// busy or restarting marks its error retry-later (backend.RetryLaterError):
// that is 503, so a client retries the batch as a whole. Anything else is
// 500, which bridge 0.9.4 reads as its users being refused and narrows down
// by splitting the batch.
func syncErrorStatus(err error) int {
	if backend.IsRetryLater(err) {
		return http.StatusServiceUnavailable
	}
	return http.StatusInternalServerError
}
