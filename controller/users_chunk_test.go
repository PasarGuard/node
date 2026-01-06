package controller

import (
	"strings"
	"testing"

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
