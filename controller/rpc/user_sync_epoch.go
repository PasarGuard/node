package rpc

import (
	"errors"

	"github.com/pasarguard/node/controller"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func userSyncError(err error) error {
	var epochErr *controller.UserSyncEpochError
	if errors.As(err, &epochErr) {
		return status.Error(codes.FailedPrecondition, epochErr.Error())
	}
	return err
}
