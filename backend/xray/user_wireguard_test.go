package xray

import (
	"encoding/base64"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

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

func TestSyncUserRetriesWireguardRemovalBeforeReplacement(t *testing.T) {
	x, service := newWireguardXray(t)
	ctx := syncContext(t)
	oldUser := wireguardUser("1.alice", wireguardKey(0x11), "")
	newUser := wireguardUser("1.alice", wireguardKey(0x22), "")

	if err := x.SyncUser(ctx, oldUser); err != nil {
		t.Fatal(err)
	}
	service.takeOrdered()
	service.rejectNextRemove()
	if err := x.SyncUser(ctx, newUser); err == nil {
		t.Fatal("expected removal failure")
	}
	assertOrdered(t, service.takeOrdered(), "wg:remove")
	if got := x.config.InboundConfigs[0].clients[oldUser.Email].(*api.WireguardAccount).PublicKey; got != strings.Repeat("11", 32) {
		t.Fatalf("cached key after failed removal = %s", got)
	}

	if err := x.SyncUser(ctx, newUser); err != nil {
		t.Fatal(err)
	}
	assertOrdered(t, service.takeOrdered(), "wg:remove", "wg:add")
}

func TestUpdateUsersRetriesWireguardRemovalBeforeReplacement(t *testing.T) {
	x, service := newWireguardXray(t)
	ctx := syncContext(t)
	oldUser := wireguardUser("1.alice", wireguardKey(0x11), "")
	newUser := wireguardUser("1.alice", wireguardKey(0x22), "")

	if err := x.UpdateUsers(ctx, []*common.User{oldUser}); err != nil {
		t.Fatal(err)
	}
	service.takeOrdered()
	service.rejectNextRemove()
	if err := x.UpdateUsers(ctx, []*common.User{newUser}); err == nil {
		t.Fatal("expected removal failure")
	}
	assertOrdered(t, service.takeOrdered(), "wg:remove")
	if got := x.config.InboundConfigs[0].clients[oldUser.Email].(*api.WireguardAccount).PublicKey; got != strings.Repeat("11", 32) {
		t.Fatalf("cached key after failed removal = %s", got)
	}

	if err := x.UpdateUsers(ctx, []*common.User{newUser}); err != nil {
		t.Fatal(err)
	}
	assertOrdered(t, service.takeOrdered(), "wg:remove", "wg:add")
}

func TestSyncUserRejectsInvalidWireguardSettingsWithoutRemovingPeer(t *testing.T) {
	for _, tc := range []struct {
		name    string
		invalid *common.User
	}{
		{"invalid key", wireguardUser("1.alice", "invalid-key", "")},
		{"malformed peer IP", wireguardUser("1.alice", wireguardKey(0x11), "", "not-a-cidr")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x, service := newWireguardXray(t)
			ctx := syncContext(t)
			user := wireguardUser("1.alice", wireguardKey(0x11), "")
			if err := x.SyncUser(ctx, user); err != nil {
				t.Fatal(err)
			}
			service.takeOrdered()

			if err := x.SyncUser(ctx, tc.invalid); err == nil {
				t.Fatal("expected invalid WireGuard account error")
			}
			assertOrdered(t, service.takeOrdered())
			if got := x.config.InboundConfigs[0].clients[user.Email].(*api.WireguardAccount).PublicKey; got != strings.Repeat("11", 32) {
				t.Fatalf("cached key after invalid update = %s", got)
			}
		})
	}
}

func TestSyncUserRemovesWireguardPeerWithValidIPOutsideInbound(t *testing.T) {
	x, service := newWireguardXray(t)
	x.config.InboundConfigs[0].Settings["address"] = []any{"10.0.0.1/24"}
	ctx := syncContext(t)
	user := wireguardUser("1.alice", wireguardKey(0x11), "", "10.0.0.2/32")
	if err := x.SyncUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	service.takeOrdered()

	outside := wireguardUser(user.Email, wireguardKey(0x11), "", "10.1.0.2/32")
	if err := x.SyncUser(ctx, outside); err != nil {
		t.Fatal(err)
	}
	assertOrdered(t, service.takeOrdered(), "wg:remove")
	if _, ok := x.config.InboundConfigs[0].clients[user.Email]; ok {
		t.Fatal("peer remained cached after leaving the inbound subnet")
	}
}

const mixedWireguardInbounds = `{"inbounds":[
	{"tag":"vless","protocol":"vless","settings":{"clients":[],"decryption":"none"}},
	{"tag":"wg","protocol":"wireguard","settings":{"secretKey":"","peers":[]}}
]}`

func newMixedWireguardXray(t *testing.T) (*Xray, *recordingInboundService) {
	t.Helper()

	x, service := newRecordingXray(t)
	cfg, err := NewConfig(mixedWireguardInbounds, nil)
	if err != nil {
		t.Fatal(err)
	}
	x.config = cfg
	return x, service
}

func mixedUser(email string, wireguard *common.Wireguard, inbounds ...string) *common.User {
	return &common.User{
		Email:    email,
		Inbounds: inbounds,
		Proxies: &common.Proxy{
			Vless:     &common.Vless{Id: "0b6f2a4e-6a54-4a51-9a3a-6f1e2b1f7c11"},
			Wireguard: wireguard,
		},
	}
}

func cachedClient(x *Xray, tag, email string) (api.Account, bool) {
	for _, inbound := range x.config.InboundConfigs {
		if inbound.Tag == tag {
			account, ok := inbound.clients[email]
			return account, ok
		}
	}
	return nil, false
}

func TestSetupUserAccountTreatsKeylessWireguardAsAbsent(t *testing.T) {
	// Panels send this message (field 5, length 0) for every user without
	// WireGuard keys, so it decodes to a non-nil but empty Wireguard.
	emptyFromWire := &common.Proxy{}
	if err := proto.Unmarshal([]byte{0x2a, 0x00}, emptyFromWire); err != nil {
		t.Fatal(err)
	}
	if emptyFromWire.GetWireguard() == nil {
		t.Fatal("expected a non-nil empty WireGuard message")
	}

	for _, tc := range []struct {
		name      string
		wireguard *common.Wireguard
	}{
		{"empty message from the wire", emptyFromWire.GetWireguard()},
		{"peer IPs without a key", &common.Wireguard{PeerIps: []string{"10.0.0.2/32"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings, err := setupUserAccount(mixedUser("1.alice", tc.wireguard, "vless", "wg"))
			if err != nil {
				t.Fatalf("setupUserAccount() error = %v", err)
			}
			if settings.Vless == nil {
				t.Fatal("expected the VLESS account to be set up")
			}
			if settings.Wireguard != nil {
				t.Fatalf("expected no WireGuard account, got %#v", settings.Wireguard)
			}
		})
	}
}

func TestSyncUserAppliesAUserWithAnEmptyWireguardMessage(t *testing.T) {
	x, service := newMixedWireguardXray(t)
	ctx := syncContext(t)

	if err := x.SyncUser(ctx, mixedUser("1.alice", &common.Wireguard{}, "vless", "wg")); err != nil {
		t.Fatal(err)
	}
	assertOperations(t, service.take(), operations("vless:remove", "vless:add", "wg:remove"))
	if _, ok := cachedClient(x, "vless", "1.alice"); !ok {
		t.Fatal("VLESS account was not stored")
	}
	if _, ok := cachedClient(x, "wg", "1.alice"); ok {
		t.Fatal("a WireGuard peer was stored without keys")
	}
}

func TestSyncUserRemovesAUserWithAnEmptyWireguardMessage(t *testing.T) {
	x, service := newMixedWireguardXray(t)
	ctx := syncContext(t)
	valid := &common.Wireguard{PublicKey: wireguardKey(0x11), PeerIps: []string{"10.0.0.2/32"}}

	if err := x.SyncUser(ctx, mixedUser("1.alice", valid, "vless", "wg")); err != nil {
		t.Fatal(err)
	}
	service.take()

	// A disabled or deleted user arrives with no inbounds and, from panels
	// that dropped its keys, an empty WireGuard message.
	if err := x.SyncUser(ctx, mixedUser("1.alice", &common.Wireguard{})); err != nil {
		t.Fatal(err)
	}
	assertOperations(t, service.take(), operations("vless:remove", "wg:remove"))
	for _, tag := range []string{"vless", "wg"} {
		if _, ok := cachedClient(x, tag, "1.alice"); ok {
			t.Fatalf("user remained cached on %s after removal", tag)
		}
	}
}

func TestSyncUserKeepsTheWireguardPeerOfAUserWithValidKeys(t *testing.T) {
	x, service := newMixedWireguardXray(t)
	ctx := syncContext(t)
	valid := &common.Wireguard{PublicKey: wireguardKey(0x11), PeerIps: []string{"10.0.0.2/32"}}

	if err := x.SyncUser(ctx, mixedUser("1.alice", valid, "vless", "wg")); err != nil {
		t.Fatal(err)
	}
	assertOperations(t, service.take(), operations("vless:remove", "vless:add", "wg:add"))
	account, ok := cachedClient(x, "wg", "1.alice")
	if !ok || account.(*api.WireguardAccount).PublicKey != strings.Repeat("11", 32) {
		t.Fatalf("WireGuard peer = %#v, stored = %t", account, ok)
	}
}

func TestSyncUserAppliesOtherInboundsWhenWireguardSettingsAreInvalid(t *testing.T) {
	x, service := newMixedWireguardXray(t)
	ctx := syncContext(t)
	valid := &common.Wireguard{PublicKey: wireguardKey(0x11), PeerIps: []string{"10.0.0.2/32"}}

	if err := x.SyncUser(ctx, mixedUser("1.alice", valid, "wg")); err != nil {
		t.Fatal(err)
	}
	service.take()

	invalid := &common.Wireguard{PublicKey: "invalid-key", PeerIps: []string{"10.0.0.2/32"}}
	if err := x.SyncUser(ctx, mixedUser("1.alice", invalid, "vless", "wg")); err == nil {
		t.Fatal("expected invalid WireGuard account error")
	}
	assertOperations(t, service.take(), operations("vless:remove", "vless:add"))
	account, ok := cachedClient(x, "wg", "1.alice")
	if !ok || account.(*api.WireguardAccount).PublicKey != strings.Repeat("11", 32) {
		t.Fatalf("live WireGuard peer changed after an invalid update: %#v, stored = %t", account, ok)
	}

	// Leaving every inbound removes the user, even with invalid WireGuard settings.
	if err := x.SyncUser(ctx, mixedUser("1.alice", invalid)); err != nil {
		t.Fatal(err)
	}
	assertOperations(t, service.take(), operations("vless:remove", "wg:remove"))
}
