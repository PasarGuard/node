package xray

import (
	"encoding/base64"
	"slices"
	"strings"
	"testing"

	"github.com/pasarguard/node/backend/xray/api"
	"github.com/pasarguard/node/common"
)

func testWireguardUser(peerIPs []string) *common.User {
	return &common.User{
		Email:    "peer@example.test",
		Inbounds: []string{"wg-v4", "wg-v6"},
		Proxies: &common.Proxy{Wireguard: &common.Wireguard{
			PublicKey: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("P", 32))),
			PeerIps:   peerIPs,
		}},
	}
}

func TestWireguardPeerIPsAreFilteredPerInbound(t *testing.T) {
	user := testWireguardUser([]string{
		"10.10.0.2/32", "10.20.0.2/32", "fd10::2/128", "10.10.0.0/16",
	})
	v4 := &Inbound{Tag: "wg-v4", Protocol: Wireguard, Settings: map[string]any{"address": []any{"10.10.0.1/24"}}}
	v6 := &Inbound{Tag: "wg-v6", Protocol: Wireguard, Settings: map[string]any{"address": []any{"fd10::1/64"}}}
	config := &Config{InboundConfigs: []*Inbound{v4, v6}}

	config.syncUsers([]*common.User{user})
	if got := v4.clients[user.Email].(*api.WireguardAccount).AllowedIPs; !slices.Equal(got, []string{"10.10.0.2/32"}) {
		t.Fatalf("startup IPv4 allowedIPs = %v", got)
	}
	if got := v6.clients[user.Email].(*api.WireguardAccount).AllowedIPs; !slices.Equal(got, []string{"fd10::2/128"}) {
		t.Fatalf("startup IPv6 allowedIPs = %v", got)
	}

	_, updates := config.buildInboundUpdates([]*common.User{user})
	for _, tc := range []struct {
		tag  string
		want string
	}{
		{"wg-v4", "10.10.0.2/32"},
		{"wg-v6", "fd10::2/128"},
	} {
		if len(updates[tc.tag].accounts) != 1 {
			t.Fatalf("%s incremental accounts = %d", tc.tag, len(updates[tc.tag].accounts))
		}
		got := updates[tc.tag].accounts[0].(*api.WireguardAccount).AllowedIPs
		if !slices.Equal(got, []string{tc.want}) {
			t.Fatalf("%s incremental allowedIPs = %v", tc.tag, got)
		}
	}

	settings, err := setupUserAccount(user)
	if err != nil {
		t.Fatal(err)
	}
	for _, inbound := range config.InboundConfigs {
		account, active := isActiveInbound(inbound, user.Inbounds, settings)
		if !active || !slices.Equal(account.(*api.WireguardAccount).AllowedIPs, inbound.clients[user.Email].(*api.WireguardAccount).AllowedIPs) {
			t.Fatalf("single user account for %s = %#v, active = %t", inbound.Tag, account, active)
		}
	}
}

func TestWireguardInboundOmitsPeersWithoutMatchingIPs(t *testing.T) {
	inbound := &Inbound{Tag: "wg-v4", Protocol: Wireguard, Settings: map[string]any{"address": []any{"10.10.0.1/24"}}}
	user := testWireguardUser([]string{"10.20.0.2/32"})
	inbound.syncUsers([]*common.User{user})
	if len(inbound.clients) != 0 {
		t.Fatalf("startup clients = %v", inbound.clients)
	}

	settings, err := setupUserAccount(user)
	if err != nil {
		t.Fatal(err)
	}
	if account, active := isActiveInbound(inbound, user.Inbounds, settings); active || account != nil {
		t.Fatalf("single user account = %#v, active = %t", account, active)
	}
	_, updates := (&Config{InboundConfigs: []*Inbound{inbound}}).buildInboundUpdates([]*common.User{user})
	if len(updates[inbound.Tag].accounts) != 0 {
		t.Fatalf("incremental accounts = %v", updates[inbound.Tag].accounts)
	}
}

func TestWireguardInboundRejectsInvalidPeerIP(t *testing.T) {
	inbound := &Inbound{Tag: "wg-v4", Protocol: Wireguard, Settings: map[string]any{"address": []string{"10.10.0.1/24"}}}
	account := &api.WireguardAccount{AllowedIPs: []string{"10.10.0.2/32", "invalid"}}
	if filtered, ok := inbound.wireguardAccountForInbound(account); ok || filtered != nil {
		t.Fatalf("filtered account = %#v, accepted = %t", filtered, ok)
	}
}

func TestWireguardInboundWithoutAddressKeepsPeerIPs(t *testing.T) {
	inbound := &Inbound{Protocol: Wireguard}
	account := &api.WireguardAccount{AllowedIPs: []string{"10.10.0.2/32", "fd10::2/128"}}
	filtered, ok := inbound.wireguardAccountForInbound(account)
	if !ok || !slices.Equal(filtered.AllowedIPs, account.AllowedIPs) {
		t.Fatalf("filtered account = %#v, accepted = %t", filtered, ok)
	}
}
