package xray

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/pasarguard/node/backend/xray/api"
	"github.com/pasarguard/node/common"
)

const masqueConfig = `{"log":{},"inbounds":[{
	"tag":"masque","protocol":"masque","port":443,
	"settings":{"users":[{"email":"static","pass":"old"}],"address":["10.0.0.0/24","fd00::/64"],"mtu":1400},
	"streamSettings":{"network":"masque","security":"tls","masqueSettings":{"path":"/.well-known/masque/ip/*/*/"}}
}]}`

func masqueUser(email, pass string) *common.User {
	return &common.User{Email: email, Inbounds: []string{"masque"}, Proxies: &common.Proxy{Masque: &common.Masque{Pass: pass}}}
}

func assertMasqueClients(t *testing.T, cfg *Config, want map[string]string) {
	t.Helper()
	data, err := cfg.ToBytes()
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Inbounds []struct {
			Settings struct {
				Clients []api.MasqueAccount `json:"clients"`
				Address []string            `json:"address"`
				MTU     int                 `json:"mtu"`
			} `json:"settings"`
			StreamSettings map[string]any `json:"streamSettings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	inbound := decoded.Inbounds[0]
	if inbound.Settings.Clients == nil {
		t.Fatal("clients must be non-null to override Xray's users alias, including when empty")
	}
	got := make(map[string]string)
	for _, client := range inbound.Settings.Clients {
		got[client.Email] = client.Pass
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("clients = %v, want %v", got, want)
	}
	if !reflect.DeepEqual(inbound.Settings.Address, []string{"10.0.0.0/24", "fd00::/64"}) || inbound.Settings.MTU != 1400 {
		t.Fatal("MASQUE address pool or MTU changed")
	}
	if !reflect.DeepEqual(inbound.StreamSettings, cfg.InboundConfigs[0].StreamSettings) {
		t.Fatal("MASQUE transport settings changed")
	}
}

func TestMasqueConfigSyncAndClone(t *testing.T) {
	cfg, err := NewConfig(masqueConfig, nil)
	if err != nil {
		t.Fatal(err)
	}
	unassigned := masqueUser("unassigned", "secret")
	unassigned.Inbounds = nil
	missingProxy := &common.User{Email: "missing", Inbounds: []string{"masque"}}
	cfg.syncUsers([]*common.User{masqueUser("alice", "p:q"), unassigned, missingProxy})
	assertMasqueClients(t, cfg, map[string]string{"alice": "p:q"})

	cloned, err := cfg.Clone()
	if err != nil {
		t.Fatal(err)
	}
	cloned.InboundConfigs[0].clients["alice"].(*api.MasqueAccount).Pass = "changed"
	assertMasqueClients(t, cfg, map[string]string{"alice": "p:q"})
	cloned.updateUsers([]*common.User{masqueUser("bob", "new")})
	assertMasqueClients(t, cloned, map[string]string{"alice": "changed", "bob": "new"})
	cloned.syncUsers(nil)
	assertMasqueClients(t, cloned, map[string]string{})
}

func TestMasqueLiveUserManagement(t *testing.T) {
	for _, batch := range []bool{false, true} {
		name := "SyncUser"
		if batch {
			name = "UpdateUsers"
		}
		t.Run(name, func(t *testing.T) {
			x, service := newRecordingXray(t)
			var err error
			x.config, err = NewConfig(masqueConfig, nil)
			if err != nil {
				t.Fatal(err)
			}
			ctx := syncContext(t)
			syncUser := func(ctx context.Context, user *common.User) error {
				if batch {
					return x.UpdateUsers(ctx, []*common.User{user})
				}
				return x.SyncUser(ctx, user)
			}
			user := masqueUser("alice", "secret")
			if err := syncUser(ctx, user); err != nil {
				t.Fatal(err)
			}
			assertOperations(t, service.take(), operations(replaced("masque")...))
			assertMasqueClients(t, x.config, map[string]string{"alice": "secret"})
			if err := syncUser(ctx, user); err != nil {
				t.Fatal(err)
			}
			assertOperations(t, service.take(), nil)

			user.Proxies.Masque.Pass = "rotated"
			service.rejectNextAdd()
			if err := syncUser(ctx, user); err == nil {
				t.Fatal("expected failed add")
			}
			service.take()
			assertMasqueClients(t, x.config, map[string]string{})
			if err := syncUser(ctx, user); err != nil {
				t.Fatal(err)
			}
			assertOperations(t, service.take(), operations(replaced("masque")...))
			assertMasqueClients(t, x.config, map[string]string{"alice": "rotated"})

			user.Proxies.Masque = nil
			if err := syncUser(ctx, user); err != nil {
				t.Fatal(err)
			}
			assertOperations(t, service.take(), operations(removed("masque")...))
			assertMasqueClients(t, x.config, map[string]string{})
		})
	}
}

func TestMasqueExcludedInbound(t *testing.T) {
	cfg, err := NewConfig(masqueConfig, []string{"masque"})
	if err != nil {
		t.Fatal(err)
	}
	before, err := cfg.ToBytes()
	if err != nil {
		t.Fatal(err)
	}
	cfg.syncUsers([]*common.User{masqueUser("alice", "secret")})
	cfg.updateUsers([]*common.User{masqueUser("bob", "secret")})
	after, err := cfg.ToBytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("excluded inbound was modified")
	}
}
