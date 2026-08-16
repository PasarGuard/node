package controller

import (
	"context"
	"strings"
	"testing"

	"github.com/pasarguard/node/backend"
	"github.com/pasarguard/node/common"
)

func TestBuildUsersFromChunksOrdersByIndex(t *testing.T) {
	chunks := map[uint64][]*common.User{
		1: {
			{Email: "second"},
		},
		0: {
			{Email: "first"},
		},
	}

	users, err := BuildUsersFromChunks(chunks, 1, true)
	if err != nil {
		t.Fatalf("expected users to build successfully, got error: %v", err)
	}

	if len(users) != 2 || users[0].GetEmail() != "first" || users[1].GetEmail() != "second" {
		t.Fatalf("users not ordered by index: %#v", users)
	}
}

func TestBuildUsersFromChunksMissingLast(t *testing.T) {
	_, err := BuildUsersFromChunks(map[uint64][]*common.User{}, 0, false)
	if err == nil || !strings.Contains(err.Error(), "missing final chunk indicator") {
		t.Fatalf("expected missing final chunk indicator error, got: %v", err)
	}
}

func TestBuildUsersFromChunksMissingChunk(t *testing.T) {
	chunks := map[uint64][]*common.User{
		1: {
			{Email: "only"},
		},
	}

	_, err := BuildUsersFromChunks(chunks, 1, true)
	if err == nil || !strings.Contains(err.Error(), "missing chunk index 0") {
		t.Fatalf("expected missing chunk index error, got: %v", err)
	}
}

type chunkUpdateBackend struct {
	backend.Backend
	updateCalls  int
	restartCalls int
	updatedUsers int
}

func (b *chunkUpdateBackend) UpdateUsers(_ context.Context, users []*common.User) error {
	b.updateCalls++
	b.updatedUsers = len(users)
	return nil
}

func (b *chunkUpdateBackend) UpdateUsersAndRestart(_ context.Context, _ []*common.User) error {
	b.restartCalls++
	return nil
}

func TestApplyChunkedUserUpdateDoesNotRestartForLargeBatches(t *testing.T) {
	users := make([]*common.User, 150)
	for i := range users {
		users[i] = &common.User{Email: "user"}
	}

	fakeBackend := &chunkUpdateBackend{}
	if err := ApplyChunkedUserUpdate(context.Background(), fakeBackend, users); err != nil {
		t.Fatalf("ApplyChunkedUserUpdate failed: %v", err)
	}

	if fakeBackend.updateCalls != 1 {
		t.Fatalf("expected one UpdateUsers call, got %d", fakeBackend.updateCalls)
	}
	if fakeBackend.restartCalls != 0 {
		t.Fatalf("expected no UpdateUsersAndRestart calls, got %d", fakeBackend.restartCalls)
	}
	if fakeBackend.updatedUsers != len(users) {
		t.Fatalf("expected %d updated users, got %d", len(users), fakeBackend.updatedUsers)
	}
}
