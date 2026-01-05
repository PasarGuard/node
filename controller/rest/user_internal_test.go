package rest

import (
	"bytes"
	"io"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/pasarguard/node/common"
)

func TestReadRequestBodyChunked(t *testing.T) {
	payload := bytes.Repeat([]byte("abc123"), 50000) // ~300KB
	reader := io.NopCloser(bytes.NewReader(payload))

	data, err := readRequestBody(reader)
	if err != nil {
		t.Fatalf("readRequestBody failed: %v", err)
	}

	if len(data) != len(payload) {
		t.Fatalf("payload length mismatch: got %d, want %d", len(data), len(payload))
	}

	if !bytes.Equal(data[:32], payload[:32]) || !bytes.Equal(data[len(data)-32:], payload[len(payload)-32:]) {
		t.Fatalf("payload contents mismatch")
	}
}

func TestDecodeUsersPayloadSingleUser(t *testing.T) {
	user := &common.User{Email: "single@example.com"}
	data, err := proto.Marshal(user)
	if err != nil {
		t.Fatalf("failed to marshal user: %v", err)
	}

	users, err := decodeUsersPayload(data)
	if err != nil {
		t.Fatalf("decodeUsersPayload returned error: %v", err)
	}

	if len(users) != 1 || users[0].GetEmail() != user.GetEmail() {
		t.Fatalf("decoded users mismatch: %+v", users)
	}
}

func TestDecodeUsersPayloadUsersEnvelope(t *testing.T) {
	usersMsg := &common.Users{
		Users: []*common.User{
			{Email: "a@example.com"},
			{Email: "b@example.com"},
		},
	}
	data, err := proto.Marshal(usersMsg)
	if err != nil {
		t.Fatalf("failed to marshal users: %v", err)
	}

	users, err := decodeUsersPayload(data)
	if err != nil {
		t.Fatalf("decodeUsersPayload returned error: %v", err)
	}

	if len(users) != len(usersMsg.GetUsers()) {
		t.Fatalf("expected %d users, got %d", len(usersMsg.GetUsers()), len(users))
	}
}
