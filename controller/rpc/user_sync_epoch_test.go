package rpc

import (
	"context"
	"errors"
	"strings"
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

func TestGRPCUserSyncErrorUsesTypedStatusWithoutPII(t *testing.T) {
	err := userSyncError(errors.New("failed for private@example.com"))
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal, got %v", status.Code(err))
	}
	if strings.Contains(err.Error(), "private@example.com") {
		t.Fatalf("gRPC error leaked user identity: %v", err)
	}
}

func TestBufferedUserSyncConcurrencyIsBounded(t *testing.T) {
	service := New(config.NewTestConfig(t.TempDir(), uuid.New()))
	releases := make([]func(), 0, maxConcurrentBufferedUserSyncs)
	for range maxConcurrentBufferedUserSyncs {
		release, err := service.acquireBufferedUserSync(context.Background())
		if err != nil {
			t.Fatalf("failed to acquire permitted slot: %v", err)
		}
		releases = append(releases, release)
	}
	if _, err := service.acquireBufferedUserSync(context.Background()); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("excess stream status = %v, want ResourceExhausted", status.Code(err))
	}
	releases[0]()
	release, err := service.acquireBufferedUserSync(context.Background())
	if err != nil {
		t.Fatalf("released slot was not reusable: %v", err)
	}
	release()
	for _, release := range releases[1:] {
		release()
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
