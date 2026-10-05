package xray

import (
	"encoding/base64"
	"slices"
	"strings"
	"testing"

	"github.com/pasarguard/node/backend/xray/api"
	"github.com/pasarguard/node/common"
)

const wireguardInbounds = `{"inbounds":[
	{"tag":"wg","protocol":"wireguard","settings":{"secretKey":"","peers":[]}}
]}`

func wireguardKey(fill byte) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string([]byte{fill}), 32)))
}

func wireguardUser(email, publicKey, preSharedKey string, peerIPs ...string) *common.User {
	if len(peerIPs) == 0 {
		peerIPs = []string{"10.0.0.2/32"}
	}
	return &common.User{
		Email:    email,
		Inbounds: []string{"wg"},
		Proxies: &common.Proxy{Wireguard: &common.Wireguard{
			PublicKey:    publicKey,
			PreSharedKey: preSharedKey,
			PeerIps:      peerIPs,
		}},
	}
}

func newWireguardXray(t *testing.T) (*Xray, *recordingInboundService) {
	t.Helper()

	x, service := newRecordingXray(t)
	cfg, err := NewConfig(wireguardInbounds, nil)
	if err != nil {
		t.Fatal(err)
	}
	x.config = cfg
	return x, service
}

func (s *recordingInboundService) takeOrdered() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	operations := s.operations
	s.operations = nil
	return operations
}

func assertOrdered(t *testing.T, got []string, want ...string) {
	t.Helper()

	if !slices.Equal(got, want) {
		t.Fatalf("operations sent to xray:\n got  %v\n want %v", got, want)
	}
}

func TestWireguardPeerReplaced(t *testing.T) {
	account := func(publicKey, preSharedKey string) *api.WireguardAccount {
		return &api.WireguardAccount{PublicKey: publicKey, PreSharedKey: preSharedKey, AllowedIPs: []string{"10.0.0.2/32"}}
	}

	for _, tc := range []struct {
		name    string
		current *api.WireguardAccount
		next    *api.WireguardAccount
		want    bool
	}{
		{"same key and psk", account("aa", "11"), account("aa", "11"), false},
		{"same key without psk", account("aa", ""), account("aa", ""), false},
		{"public key rotated", account("aa", ""), account("bb", ""), true},
		{"public key rotated with psk", account("aa", "11"), account("bb", "11"), true},
		{"psk removed", account("aa", "11"), account("aa", ""), true},
		{"psk changed", account("aa", "11"), account("aa", "22"), false},
		{"psk added", account("aa", ""), account("aa", "11"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := wireguardPeerReplaced(tc.current, tc.next); got != tc.want {
				t.Fatalf("wireguardPeerReplaced() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSyncUserWireguardPeerLifecycle(t *testing.T) {
	keyA, keyB, pskA, pskB := wireguardKey(0x11), wireguardKey(0x22), wireguardKey(0x33), wireguardKey(0x44)

	for _, tc := range []struct {
		name string
		from *common.User
		to   *common.User
		want []string
	}{
		{"unchanged peer", wireguardUser("1.alice", keyA, pskA), wireguardUser("1.alice", keyA, pskA), nil},
		{"public key rotated", wireguardUser("1.alice", keyA, ""), wireguardUser("1.alice", keyB, ""), []string{"wg:remove", "wg:add"}},
		{"public key rotated with psk", wireguardUser("1.alice", keyA, pskA), wireguardUser("1.alice", keyB, pskA), []string{"wg:remove", "wg:add"}},
		{"psk removed", wireguardUser("1.alice", keyA, pskA), wireguardUser("1.alice", keyA, ""), []string{"wg:remove", "wg:add"}},
		{"psk changed", wireguardUser("1.alice", keyA, pskA), wireguardUser("1.alice", keyA, pskB), []string{"wg:add"}},
		{"psk added", wireguardUser("1.alice", keyA, ""), wireguardUser("1.alice", keyA, pskA), []string{"wg:add"}},
		{"allowed ips changed", wireguardUser("1.alice", keyA, pskA, "10.0.0.2/32"), wireguardUser("1.alice", keyA, pskA, "10.0.0.3/32"), []string{"wg:add"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x, service := newWireguardXray(t)
			ctx := syncContext(t)

			if err := x.SyncUser(ctx, tc.from); err != nil {
				t.Fatal(err)
			}
			assertOrdered(t, service.takeOrdered(), "wg:add")

			if err := x.SyncUser(ctx, tc.to); err != nil {
				t.Fatal(err)
			}
			assertOrdered(t, service.takeOrdered(), tc.want...)
		})
	}
}

func TestSyncUserRemovesAWireguardPeerThatLeavesTheInbound(t *testing.T) {
	x, service := newWireguardXray(t)
	ctx := syncContext(t)
	user := wireguardUser("1.alice", wireguardKey(0x11), "")

	if err := x.SyncUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	service.takeOrdered()

	user.Inbounds = nil
	if err := x.SyncUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	assertOrdered(t, service.takeOrdered(), "wg:remove")
}

func TestUpdateUsersWireguardPeerLifecycle(t *testing.T) {
	keyA, keyB, pskA, pskB := wireguardKey(0x11), wireguardKey(0x22), wireguardKey(0x33), wireguardKey(0x44)

	for _, tc := range []struct {
		name string
		from *common.User
		to   *common.User
		want []string
	}{
		{"unchanged peer", wireguardUser("1.alice", keyA, pskA), wireguardUser("1.alice", keyA, pskA), nil},
		{"public key rotated", wireguardUser("1.alice", keyA, ""), wireguardUser("1.alice", keyB, ""), []string{"wg:remove", "wg:add"}},
		{"psk removed", wireguardUser("1.alice", keyA, pskA), wireguardUser("1.alice", keyA, ""), []string{"wg:remove", "wg:add"}},
		{"psk changed", wireguardUser("1.alice", keyA, pskA), wireguardUser("1.alice", keyA, pskB), []string{"wg:add"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x, service := newWireguardXray(t)
			ctx := syncContext(t)

			if err := x.UpdateUsers(ctx, []*common.User{tc.from}); err != nil {
				t.Fatal(err)
			}
			assertOrdered(t, service.takeOrdered(), "wg:add")

			if err := x.UpdateUsers(ctx, []*common.User{tc.to}); err != nil {
				t.Fatal(err)
			}
			assertOrdered(t, service.takeOrdered(), tc.want...)
		})
	}
}

func TestSyncUserTracksTheRotatedWireguardKey(t *testing.T) {
	x, service := newWireguardXray(t)
	ctx := syncContext(t)
	keyA, keyB := wireguardKey(0x11), wireguardKey(0x22)

	for _, key := range []string{keyA, keyB, keyB} {
		if err := x.SyncUser(ctx, wireguardUser("1.alice", key, "")); err != nil {
			t.Fatal(err)
		}
	}
	assertOrdered(t, service.takeOrdered(), "wg:add", "wg:remove", "wg:add")
}
