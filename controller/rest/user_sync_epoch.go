package rest

import (
	"errors"
	"net/http"

	"github.com/pasarguard/node/controller"
)

func writeUserSyncError(w http.ResponseWriter, err error, fallbackStatus int) {
	var epochErr *controller.UserSyncEpochError
	if errors.As(err, &epochErr) {
		http.Error(w, epochErr.Error(), http.StatusPreconditionFailed)
		return
	}
	http.Error(w, err.Error(), fallbackStatus)
}
