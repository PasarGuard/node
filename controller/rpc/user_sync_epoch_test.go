package rpc

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
	"github.com/pasarguard/node/controller"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestGRPCUserSyncEpochErrorUsesFailedPrecondition(t *testing.T) {
	err := userSyncError(&controller.UserSyncEpochError{Received: 2, Current: 3})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %v", status.Code(err))
	}
}

func TestGRPCStaleUserSyncRejectsBeforeBackendAccess(t *testing.T) {
	service := New(config.NewTestConfig(t.TempDir(), uuid.New()))
	if err := service.ApplyUserSyncEpoch(70, func() error { return nil }); err != nil {
		t.Fatalf("failed to establish current epoch: %v", err)
	}
	_, err := service.SyncUsers(context.Background(), &common.Users{UserSyncEpoch: 69})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected stale request to fail before nil backend access, got %v", err)
	}
}

func TestGRPCUserSyncStreamHasAggregatePayloadLimit(t *testing.T) {
	user := &common.User{Email: "bounded@example.com"}
	_, err := addUserSyncStreamPayload(common.MaxProtoBodyBytes-1, user)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("expected aggregate stream limit, got %v", err)
	}
}

func TestGRPCChunkedUserSyncStreamHasAggregatePayloadLimit(t *testing.T) {
	chunk := &common.UsersChunk{Users: []*common.User{{Email: "bounded@example.com"}}}
	_, err := addUserSyncStreamPayload(common.MaxProtoBodyBytes-1, chunk)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("expected aggregate chunk stream limit, got %v", err)
	}
}
