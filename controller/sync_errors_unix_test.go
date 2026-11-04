//go:build !windows

package controller_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/controller"
	"github.com/pasarguard/node/controller/rest"
	"github.com/pasarguard/node/controller/rpc"
)

// A busy MTProto node must answer a sync as unavailable (gRPC Unavailable,
// HTTP 503), not as INTERNAL or 500, which bridge 0.9.4 reads as its users
// being refused and splits the batch to find them. Here every sync changes
// the users, and the fake telemt never confirms a reload, so the apply is
// still waiting for telemt when the caller's deadline passes, like a full
// apply on a large node. The text the panel matches stays in the answer.
const stillApplying = "the users are still being applied"

// syncCallTimeout is the caller's deadline for each sync below.
const syncCallTimeout = time.Second

func changedUsers() []*common.User {
	return []*common.User{{
		Email:    "2",
		Inbounds: []string{"mtproto"},
		Proxies:  &common.Proxy{Mtproto: &common.Mtproto{Secret: "ffeeddccbbaa00112233445566778899"}},
	}}
}

type startable interface {
	LockControl()
	UnlockControl()
	StartOrAttach(context.Context, *common.Backend) error
}

func startMTProto(t *testing.T, s startable) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	s.LockControl()
	defer s.UnlockControl()
	if err := s.StartOrAttach(ctx, controller.MTProtoStartRequest()); err != nil {
		t.Fatalf("Start: %v", err)
	}
}

func newMTProtoRPCService(t *testing.T) *rpc.Service {
	t.Helper()
	cfg, _ := controller.FakeTelemtConfig(t, "0s")
	s := rpc.New(cfg)
	t.Cleanup(s.Disconnect)
	startMTProto(t, s)
	return s
}

func newMTProtoRESTService(t *testing.T) *rest.Service {
	t.Helper()
	cfg, _ := controller.FakeTelemtConfig(t, "0s")
	s := rest.New(cfg)
	t.Cleanup(s.Disconnect)
	startMTProto(t, s)
	return s
}

// chunkStream is the server side of a SyncUsersChunked call.
type chunkStream struct {
	grpc.ServerStream
	ctx    context.Context
	chunks []*common.UsersChunk
}

func (s *chunkStream) Context() context.Context { return s.ctx }

func (s *chunkStream) Recv() (*common.UsersChunk, error) {
	if len(s.chunks) == 0 {
		return nil, io.EOF
	}
	chunk := s.chunks[0]
	s.chunks = s.chunks[1:]
	return chunk, nil
}

func (s *chunkStream) SendAndClose(*common.Empty) error { return nil }

func assertUnavailable(t *testing.T, err error) {
	t.Helper()
	got := status.Convert(err)
	if got.Code() != codes.Unavailable || !strings.Contains(got.Message(), stillApplying) {
		t.Errorf("busy MTProto sync answered %s %q, want Unavailable with %q", got.Code(), got.Message(), stillApplying)
	}
}

func assert503(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), stillApplying) {
		t.Errorf("busy MTProto sync answered %d %q, want 503 with %q", recorder.Code, recorder.Body.String(), stillApplying)
	}
}

func TestBusyMTProtoSyncIsUnavailable(t *testing.T) {
	t.Run("grpc SyncUsers", func(t *testing.T) {
		s := newMTProtoRPCService(t)
		ctx, cancel := context.WithTimeout(context.Background(), syncCallTimeout)
		defer cancel()
		_, err := s.SyncUsers(ctx, &common.Users{Users: changedUsers()})
		assertUnavailable(t, err)
	})

	t.Run("grpc SyncUsersChunked", func(t *testing.T) {
		s := newMTProtoRPCService(t)
		ctx, cancel := context.WithTimeout(context.Background(), syncCallTimeout)
		defer cancel()
		err := s.SyncUsersChunked(&chunkStream{
			ctx:    ctx,
			chunks: []*common.UsersChunk{{Users: changedUsers(), Index: 0, Last: true}},
		})
		assertUnavailable(t, err)
	})

	t.Run("rest SyncUsers", func(t *testing.T) {
		s := newMTProtoRESTService(t)
		body, err := proto.Marshal(&common.Users{Users: changedUsers()})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), syncCallTimeout)
		defer cancel()
		recorder := httptest.NewRecorder()
		s.SyncUsers(recorder, httptest.NewRequest(http.MethodPut, "/users/sync", bytes.NewReader(body)).WithContext(ctx))
		assert503(t, recorder)
	})

	t.Run("rest SyncUsersChunked", func(t *testing.T) {
		s := newMTProtoRESTService(t)
		payload, err := proto.Marshal(&common.UsersChunk{Users: changedUsers(), Index: 0, Last: true})
		if err != nil {
			t.Fatal(err)
		}
		body := append(binary.AppendUvarint(nil, uint64(len(payload))), payload...)
		ctx, cancel := context.WithTimeout(context.Background(), syncCallTimeout)
		defer cancel()
		recorder := httptest.NewRecorder()
		s.SyncUsersChunked(recorder, httptest.NewRequest(http.MethodPut, "/users/sync/chunked", bytes.NewReader(body)).WithContext(ctx))
		assert503(t, recorder)
	})
}
