package xray

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman/command"
	"google.golang.org/grpc"

	"github.com/pasarguard/node/backend/xray/api"
	"github.com/pasarguard/node/common"
)

const recordingInbounds = `{"inbounds":[
	{"tag":"vless","protocol":"vless","settings":{"clients":[],"decryption":"none"}},
	{"tag":"vmess","protocol":"vmess","settings":{"clients":[]}},
	{"tag":"trojan","protocol":"trojan","settings":{"clients":[]}},
	{"tag":"ss","protocol":"shadowsocks","settings":{"clients":[],"method":"aes-128-gcm","network":"tcp,udp"}},
	{"tag":"ss2022","protocol":"shadowsocks","settings":{"clients":[],"method":"2022-blake3-aes-128-gcm","password":"MDEyMzQ1Njc4OWFiY2RlZg==","network":"tcp,udp"}},
	{"tag":"hysteria","protocol":"hysteria","settings":{"clients":[]}}
]}`

var recordingTags = []string{"vless", "vmess", "trojan", "ss", "ss2022", "hysteria"}

type recordingInboundService struct {
	command.UnimplementedHandlerServiceServer
	mu         sync.Mutex
	operations []string
	failAdds   int
}

func (s *recordingInboundService) AlterInbound(_ context.Context, request *command.AlterInboundRequest) (*command.AlterInboundResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	operation := request.GetOperation().GetType()
	switch {
	case strings.HasSuffix(operation, ".AddUserOperation"):
		operation = "add"
	case strings.HasSuffix(operation, ".RemoveUserOperation"):
		operation = "remove"
	}
	s.operations = append(s.operations, request.GetTag()+":"+operation)

	if operation == "add" && s.failAdds > 0 {
		s.failAdds--
		return nil, errors.New("add rejected")
	}
	return &command.AlterInboundResponse{}, nil
}

func (s *recordingInboundService) take() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	operations := s.operations
	s.operations = nil
	slices.Sort(operations)
	return operations
}

func (s *recordingInboundService) rejectNextAdd() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failAdds++
}

func newRecordingXray(t *testing.T) (*Xray, *recordingInboundService) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	service := &recordingInboundService{}
	server := grpc.NewServer()
	command.RegisterHandlerServiceServer(server, service)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	handler, err := api.NewXrayAPI(listener.Addr().(*net.TCPAddr).Port)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(handler.Close)

	cfg, err := NewConfig(recordingInbounds, nil)
	if err != nil {
		t.Fatal(err)
	}

	return &Xray{config: cfg, handler: handler}, service
}

func recordingUser(email string, inbounds ...string) *common.User {
	return &common.User{
		Email:    email,
		Inbounds: inbounds,
		Proxies: &common.Proxy{
			Vmess:       &common.Vmess{Id: "6f1c6c5e-3f59-4a0e-9d8a-2b4f1c9d7e10"},
			Vless:       &common.Vless{Id: "0b6f2a4e-6a54-4a51-9a3a-6f1e2b1f7c11", Flow: "xtls-rprx-vision"},
			Trojan:      &common.Trojan{Password: "example-trojan-key"},
			Shadowsocks: &common.Shadowsocks{Password: "example-shadowsocks-key", Method: "aes-128-gcm"},
			Hysteria:    &common.Hysteria{Auth: "hysteria secret"},
		},
	}
}

func operations(pairs ...string) []string {
	slices.Sort(pairs)
	return pairs
}

func replaced(tags ...string) []string {
	var pairs []string
	for _, tag := range tags {
		pairs = append(pairs, tag+":remove", tag+":add")
	}
	return pairs
}

func removed(tags ...string) []string {
	var pairs []string
	for _, tag := range tags {
		pairs = append(pairs, tag+":remove")
	}
	return pairs
}

func assertOperations(t *testing.T, got []string, want []string) {
	t.Helper()

	if !slices.Equal(got, want) {
		t.Fatalf("operations sent to xray:\n got  %v\n want %v", got, want)
	}
}

func syncContext(t *testing.T) context.Context {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestSyncUserLeavesAnUnchangedUserAlone(t *testing.T) {
	x, service := newRecordingXray(t)
	ctx := syncContext(t)
	user := recordingUser("1.alice", recordingTags...)

	if err := x.SyncUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	assertOperations(t, service.take(), operations(replaced(recordingTags...)...))

	if err := x.SyncUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	assertOperations(t, service.take(), nil)
}

func TestSyncUserLeavesAUserLoadedAtStartupAlone(t *testing.T) {
	x, service := newRecordingXray(t)
	ctx := syncContext(t)
	user := recordingUser("1.alice", recordingTags...)

	x.config.syncUsers([]*common.User{user})

	if err := x.SyncUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	assertOperations(t, service.take(), nil)
}

func TestSyncUserReplacesOnlyTheAccountThatChanged(t *testing.T) {
	x, service := newRecordingXray(t)
	ctx := syncContext(t)
	user := recordingUser("1.alice", recordingTags...)

	if err := x.SyncUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	service.take()

	user.Proxies.Trojan.Password = "rotated trojan secret"
	if err := x.SyncUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	assertOperations(t, service.take(), operations(replaced("trojan")...))
}

func TestSyncUserRemovesAUserFromTheInboundsTheyLeave(t *testing.T) {
	x, service := newRecordingXray(t)
	ctx := syncContext(t)

	if err := x.SyncUser(ctx, recordingUser("1.alice", recordingTags...)); err != nil {
		t.Fatal(err)
	}
	service.take()

	if err := x.SyncUser(ctx, recordingUser("1.alice", "vless", "trojan")); err != nil {
		t.Fatal(err)
	}
	assertOperations(t, service.take(), operations(removed("vmess", "ss", "ss2022", "hysteria")...))

	if err := x.SyncUser(ctx, recordingUser("1.alice")); err != nil {
		t.Fatal(err)
	}
	assertOperations(t, service.take(), operations(removed(recordingTags...)...))
}

func TestSyncUserRetriesAnAddThatFailed(t *testing.T) {
	x, service := newRecordingXray(t)
	ctx := syncContext(t)
	user := recordingUser("1.alice", "vless")

	service.rejectNextAdd()
	if err := x.SyncUser(ctx, user); err == nil {
		t.Fatal("a rejected add was not reported")
	}
	service.take()

	if err := x.SyncUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	assertOperations(t, service.take(), operations(append(replaced("vless"), removed("vmess", "trojan", "ss", "ss2022", "hysteria")...)...))

	if err := x.SyncUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	assertOperations(t, service.take(), operations(removed("vmess", "trojan", "ss", "ss2022", "hysteria")...))
}

func TestUpdateUsersLeavesUnchangedUsersAlone(t *testing.T) {
	x, service := newRecordingXray(t)
	ctx := syncContext(t)
	alice := recordingUser("1.alice", "vless", "trojan")
	bob := recordingUser("2.bob", "vless", "trojan")

	if err := x.UpdateUsers(ctx, []*common.User{alice, bob}); err != nil {
		t.Fatal(err)
	}
	service.take()

	bob.Proxies.Vless.Id = "9c3e8f5a-1b2d-4c6e-8f0a-3d5b7c9e1f21"
	carol := recordingUser("3.carol")
	if err := x.UpdateUsers(ctx, []*common.User{alice, bob, carol}); err != nil {
		t.Fatal(err)
	}

	assertOperations(t, service.take(), operations(
		"vless:remove", "vless:remove", "vless:add",
		"trojan:remove",
		"vmess:remove", "vmess:remove", "vmess:remove",
		"ss:remove", "ss:remove", "ss:remove",
		"ss2022:remove", "ss2022:remove", "ss2022:remove",
		"hysteria:remove", "hysteria:remove", "hysteria:remove",
	))
}

func TestUpdateUsersRetriesAnAddThatFailed(t *testing.T) {
	x, service := newRecordingXray(t)
	ctx := syncContext(t)
	users := []*common.User{recordingUser("1.alice", "trojan")}

	service.rejectNextAdd()
	if err := x.UpdateUsers(ctx, users); err == nil {
		t.Fatal("a rejected add was not reported")
	}
	service.take()

	if err := x.UpdateUsers(ctx, users); err != nil {
		t.Fatal(err)
	}
	assertOperations(t, service.take(), operations(append(replaced("trojan"), removed("vless", "vmess", "ss", "ss2022", "hysteria")...)...))

	if err := x.UpdateUsers(ctx, users); err != nil {
		t.Fatal(err)
	}
	assertOperations(t, service.take(), operations(removed("vless", "vmess", "ss", "ss2022", "hysteria")...))
}
