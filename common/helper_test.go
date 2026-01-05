package common

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestReadProtoBodyChunked(t *testing.T) {
	largeConfig := strings.Repeat("config", 30000) // ~180KB to force multiple reads
	expected := &Backend{
		Type:   BackendType_XRAY,
		Config: largeConfig,
		Users: []*User{
			{Email: "a@example.com"},
		},
		KeepAlive: 5,
	}

	data, err := proto.Marshal(expected)
	if err != nil {
		t.Fatalf("failed to marshal backend: %v", err)
	}

	reader := io.NopCloser(bytes.NewReader(data))

	var decoded Backend
	if err = ReadProtoBody(reader, &decoded); err != nil {
		t.Fatalf("ReadProtoBody returned error: %v", err)
	}

	if decoded.GetConfig() != expected.GetConfig() {
		t.Fatalf("config mismatch: got %d chars, want %d chars", len(decoded.GetConfig()), len(expected.GetConfig()))
	}

	if decoded.GetKeepAlive() != expected.GetKeepAlive() {
		t.Fatalf("keepalive mismatch: got %d, want %d", decoded.GetKeepAlive(), expected.GetKeepAlive())
	}

	if got := decoded.GetUsers(); len(got) != len(expected.GetUsers()) || got[0].GetEmail() != expected.GetUsers()[0].GetEmail() {
		t.Fatalf("users mismatch: got %+v, want %+v", got, expected.GetUsers())
	}
}
