package backend

import "errors"

// RetryLaterError marks a user sync error that comes from the backend's
// state, not from the users sent: the backend is busy with an earlier
// change, its core is restarting, or it was shut down. The node answers it as
// unavailable (gRPC Unavailable, HTTP 503) with the same text, so a client
// retries the batch later instead of splitting it to find a user to blame.
type RetryLaterError struct {
	Err error
}

func (e *RetryLaterError) Error() string { return e.Err.Error() }

func (e *RetryLaterError) Unwrap() error { return e.Err }

// RetryLater marks err as a RetryLaterError; nil stays nil.
func RetryLater(err error) error {
	if err == nil {
		return nil
	}
	return &RetryLaterError{Err: err}
}

// IsRetryLater reports whether err, or an error it wraps, is a
// RetryLaterError.
func IsRetryLater(err error) bool {
	var retryLater *RetryLaterError
	return errors.As(err, &retryLater)
}
