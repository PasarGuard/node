package rest

import (
	"bytes"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
	"github.com/pasarguard/node/controller"
	"google.golang.org/protobuf/proto"
)

func TestRESTChunkedSyncRejectsMixedEpochs(t *testing.T) {
	service := &Service{Controller: *controller.New(config.NewTestConfig(t.TempDir(), uuid.New()))}
	var body bytes.Buffer
	for _, chunk := range []*common.UsersChunk{
		{Index: 0, UserSyncEpoch: 40, Users: []*common.User{{Email: "first@example.com"}}},
		{Index: 1, Last: true, UserSyncEpoch: 41, Users: []*common.User{{Email: "second@example.com"}}},
	} {
		payload, err := proto.Marshal(chunk)
		if err != nil {
			t.Fatal(err)
		}
		var length [binary.MaxVarintLen64]byte
		n := binary.PutUvarint(length[:], uint64(len(payload)))
		body.Write(length[:n])
		body.Write(payload)
	}

	req := httptest.NewRequest(http.MethodPut, "/users/sync/chunked", &body)
	recorder := httptest.NewRecorder()
	service.SyncUsersChunked(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for mixed epochs, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestRESTUserSyncEpochErrorUsesPreconditionFailed(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeUserSyncError(recorder, &controller.UserSyncEpochError{Received: 2, Current: 3}, http.StatusInternalServerError)
	if recorder.Code != http.StatusPreconditionFailed {
		t.Fatalf("expected 412, got %d", recorder.Code)
	}
}

func TestRESTStaleUserSyncRejectsBeforeBackendAccess(t *testing.T) {
	service := &Service{Controller: *controller.New(config.NewTestConfig(t.TempDir(), uuid.New()))}
	if err := service.ApplyUserSyncEpoch(70, func() error { return nil }); err != nil {
		t.Fatalf("failed to establish current epoch: %v", err)
	}
	payload, err := proto.Marshal(&common.User{Email: "stale@example.com", UserSyncEpoch: 69})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPut, "/user/sync", bytes.NewReader(payload))
	recorder := httptest.NewRecorder()
	service.SyncUser(recorder, req)
	if recorder.Code != http.StatusPreconditionFailed {
		t.Fatalf("expected stale request to fail with 412 before nil backend access, got %d: %s", recorder.Code, recorder.Body.String())
	}
}
