package api

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/pasarguard/node/common"
	"github.com/xtls/xray-core/proxy/wireguard"
	"google.golang.org/protobuf/proto"
)

func TestWireguardKeyToHex(t *testing.T) {
	raw := strings.Repeat("\x11", 32)
	want := strings.Repeat("11", 32)
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))

	for _, tc := range []struct {
		name string
		key  string
		want string
	}{
		{"base64", encoded, want},
		{"hex", want, want},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := WireguardKeyToHex(tc.key)
			if err != nil || got != tc.want {
				t.Fatalf("WireguardKeyToHex() = %q, %v; want %q, nil", got, err, tc.want)
			}
		})
	}
}

func TestWireguardKeyToHexRejectsInvalidKeys(t *testing.T) {
	for _, key := range []string{"", "not-a-key", base64.StdEncoding.EncodeToString([]byte("short")), strings.Repeat("z", 64)} {
		if got, err := WireguardKeyToHex(key); err == nil || got != "" {
			t.Fatalf("WireguardKeyToHex(%q) = %q, %v; want empty result and error", key, got, err)
		}
	}
}

func TestNewWireguardAccountNormalizesPSKAndMessage(t *testing.T) {
	publicKey := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("P", 32)))
	psk := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("S", 32)))
	account, err := NewWireguardAccount(&common.User{
		Email: "user@example.test",
		Proxies: &common.Proxy{Wireguard: &common.Wireguard{
			PublicKey: publicKey, PreSharedKey: psk, PeerIps: []string{"10.0.0.2/32"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if account.GetEmail() != "user@example.test" || account.PreSharedKey != strings.Repeat("53", 32) {
		t.Fatalf("account = %#v", account)
	}
	message, err := account.Message()
	if err != nil {
		t.Fatal(err)
	}
	peer := new(wireguard.PeerConfig)
	if err := proto.Unmarshal(message.Value, peer); err != nil {
		t.Fatal(err)
	}
	if peer.PreSharedKey != account.PreSharedKey {
		t.Fatalf("peer message = %#v, want PSK %q", peer, account.PreSharedKey)
	}
}
