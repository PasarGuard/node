package xray

import (
	"encoding/json"
	"reflect"
	"sync"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"

	"github.com/pasarguard/node/common"
)

const toBytesConfig = `{
	"log":{"access":"/var/log/xray/access.log","error":"/var/log/xray/error.log","loglevel":"warning"},
	"inbounds":[
		{"tag":"static","protocol":"vless","settings":{"decryption":"none","clients":[{"id":"6b1d1f0e-5c1d-4c3a-9f6e-111111111111","email":"hand-written"}]}},
		{"tag":"managed","protocol":"vless","settings":{"decryption":"none","clients":[]}},
		{"tag":"wg","protocol":"wireguard","settings":{"secretKey":"","peers":[]}}
	]
}`

func newToBytesConfig(t *testing.T) *Config {
	t.Helper()

	cfg, err := NewConfig(toBytesConfig, []string{"static"})
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func toBytesUsers() []*common.User {
	return []*common.User{
		{
			Email:    "1",
			Inbounds: []string{"static", "managed"},
			Proxies:  &common.Proxy{Vless: &common.Vless{Id: "6b1d1f0e-5c1d-4c3a-9f6e-222222222222"}},
		},
		wireguardUser("2", wireguardKey(2), ""),
	}
}

type serializedConfig struct {
	Log      map[string]any `json:"log"`
	Inbounds []struct {
		Tag      string         `json:"tag"`
		Settings map[string]any `json:"settings"`
	} `json:"inbounds"`
}

func serializeConfig(t *testing.T, cfg *Config) serializedConfig {
	t.Helper()

	raw, err := cfg.ToBytes()
	if err != nil {
		t.Fatal(err)
	}
	var out serializedConfig
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func (s serializedConfig) settings(t *testing.T, tag string) map[string]any {
	t.Helper()

	for _, inbound := range s.Inbounds {
		if inbound.Tag == tag {
			return inbound.Settings
		}
	}
	t.Fatalf("inbound %q missing from serialized config", tag)
	return nil
}

func emails(t *testing.T, settings map[string]any, key string) []string {
	t.Helper()

	entries, ok := settings[key].([]any)
	if !ok {
		t.Fatalf("settings[%q] is %T, want a list", key, settings[key])
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		fields, _ := entry.(map[string]any)
		email, _ := fields["email"].(string)
		out = append(out, email)
	}
	return out
}

func TestToBytesKeepsExcludedInboundClients(t *testing.T) {
	cfg := newToBytesConfig(t)
	cfg.syncUsers(toBytesUsers())

	got := emails(t, serializeConfig(t, cfg).settings(t, "static"), "clients")
	if len(got) != 1 || got[0] != "hand-written" {
		t.Fatalf("excluded inbound clients = %v, want only the hand-written client", got)
	}
}

func TestToBytesWritesSyncedClientsAndPeers(t *testing.T) {
	cfg := newToBytesConfig(t)
	cfg.syncUsers(toBytesUsers())
	out := serializeConfig(t, cfg)

	if got := emails(t, out.settings(t, "managed"), "clients"); len(got) != 1 || got[0] != "1" {
		t.Fatalf("managed inbound clients = %v, want [1]", got)
	}

	wg := out.settings(t, "wg")
	if got := emails(t, wg, "peers"); len(got) != 1 || got[0] != "2" {
		t.Fatalf("wireguard peers = %v, want [2]", got)
	}
	if _, ok := wg["clients"]; ok {
		t.Fatalf("wireguard inbound got a clients key: %v", wg)
	}
}

func TestToBytesWritesEmptyListsWithoutUsers(t *testing.T) {
	out := serializeConfig(t, newToBytesConfig(t))

	if got := emails(t, out.settings(t, "managed"), "clients"); len(got) != 0 {
		t.Fatalf("managed inbound clients = %v, want none", got)
	}
	wg := out.settings(t, "wg")
	if got := emails(t, wg, "peers"); len(got) != 0 {
		t.Fatalf("wireguard peers = %v, want none", got)
	}
	if _, ok := wg["clients"]; ok {
		t.Fatalf("wireguard inbound got a clients key: %v", wg)
	}
}

func TestToBytesDropsLogFilesWithoutChangingTheConfig(t *testing.T) {
	cfg := newToBytesConfig(t)
	out := serializeConfig(t, cfg)

	if access, _ := out.Log["access"].(string); access != "" {
		t.Fatalf("serialized access log = %q, want empty", access)
	}
	if errorLog, _ := out.Log["error"].(string); errorLog != "" {
		t.Fatalf("serialized error log = %q, want empty", errorLog)
	}
	if level, _ := out.Log["loglevel"].(string); level != "warning" {
		t.Fatalf("serialized loglevel = %q, want warning", level)
	}
	if cfg.LogConfig.AccessLog != "/var/log/xray/access.log" || cfg.LogConfig.ErrorLog != "/var/log/xray/error.log" {
		t.Fatalf("ToBytes changed the stored log files: access %q, error %q", cfg.LogConfig.AccessLog, cfg.LogConfig.ErrorLog)
	}
}

func TestToBytesDoesNotWriteInboundSettings(t *testing.T) {
	cfg := newToBytesConfig(t)
	cfg.syncUsers(toBytesUsers())

	if _, err := cfg.ToBytes(); err != nil {
		t.Fatal(err)
	}

	for _, inbound := range cfg.InboundConfigs {
		if inbound.Tag != "managed" {
			continue
		}
		clients, ok := inbound.Settings["clients"].([]any)
		if !ok || len(clients) != 0 {
			t.Fatalf("ToBytes wrote the managed inbound's stored settings: clients = %#v", inbound.Settings["clients"])
		}
	}
}

// Run with -race: concurrent serialization must not write shared maps.
func TestToBytesConcurrentCalls(t *testing.T) {
	cfg := newToBytesConfig(t)
	cfg.syncUsers(toBytesUsers())

	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 20 {
				if _, err := cfg.ToBytes(); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	wg.Go(func() {
		for range 20 {
			cfg.syncUsers(toBytesUsers())
		}
	})
	wg.Wait()
}

func TestToBytesSerializesExcludedInboundUnchanged(t *testing.T) {
	const inbound = `{"tag":"static","listen":"127.0.0.1","port":8443,"protocol":"vless",` +
		`"settings":{"decryption":"none","clients":[{"id":"6b1d1f0e-5c1d-4c3a-9f6e-111111111111","email":"hand-written"}]},` +
		`"streamSettings":{"network":"tcp","security":"none"},` +
		`"sniffing":{"enabled":true,"destOverride":["http","tls"]},` +
		`"allocate":{"strategy":"always"}}`

	cfg, err := NewConfig(`{"inbounds":[`+inbound+`]}`, []string{"static"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := cfg.ToBytes()
	if err != nil {
		t.Fatal(err)
	}

	var want map[string]any
	if err := json.Unmarshal([]byte(inbound), &want); err != nil {
		t.Fatal(err)
	}
	var out struct {
		Inbounds []map[string]any `json:"inbounds"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Inbounds) != 1 || !reflect.DeepEqual(out.Inbounds[0], want) {
		t.Fatalf("excluded inbound changed by ToBytes:\n got  %v\n want %v", out.Inbounds, want)
	}
}

// The snapshot copies Inbound fields by hand because Inbound holds a mutex.
// Fill every exported field so a field added later without a matching copy fails here.
func TestSnapshotInboundCopiesEveryExportedField(t *testing.T) {
	original := &Inbound{exclude: true}
	value := reflect.ValueOf(original).Elem()
	for idx := 0; idx < value.NumField(); idx++ {
		field := value.Field(idx)
		if !value.Type().Field(idx).IsExported() {
			continue
		}
		switch field.Kind() {
		case reflect.String:
			field.SetString("value-" + value.Type().Field(idx).Name)
		case reflect.Map:
			field.Set(reflect.ValueOf(map[string]any{"key": value.Type().Field(idx).Name}))
		case reflect.Interface:
			field.Set(reflect.ValueOf(value.Type().Field(idx).Name))
		default:
			t.Fatalf("Inbound.%s has kind %s: extend this test and the snapshot copy", value.Type().Field(idx).Name, field.Kind())
		}
	}

	snap := reflect.ValueOf(snapshotInboundForSerialization(original)).Elem()
	for idx := 0; idx < value.NumField(); idx++ {
		name := value.Type().Field(idx).Name
		if !value.Type().Field(idx).IsExported() {
			continue
		}
		if !reflect.DeepEqual(snap.Field(idx).Interface(), value.Field(idx).Interface()) {
			t.Fatalf("snapshot did not copy Inbound.%s: got %v, want %v", name, snap.Field(idx).Interface(), value.Field(idx).Interface())
		}
	}
}

// Run with -race: a user sync clones the live config while a health-check
// restart serializes it, so ToBytes must not write what Clone reads.
func TestToBytesWhileCloning(t *testing.T) {
	cfg := newToBytesConfig(t)
	cfg.syncUsers(toBytesUsers())

	var wg sync.WaitGroup
	wg.Go(func() {
		for range 50 {
			if _, err := cfg.ToBytes(); err != nil {
				t.Error(err)
				return
			}
		}
	})
	wg.Go(func() {
		for range 50 {
			if _, err := cfg.Clone(); err != nil {
				t.Error(err)
				return
			}
		}
	})
	wg.Wait()
}

const shadowsocks2022Config = `{"inbounds":[
	{"tag":"aes128","protocol":"shadowsocks","settings":{"clients":[],"method":"2022-blake3-aes-128-gcm","password":"MDEyMzQ1Njc4OWFiY2RlZg==","network":"tcp,udp"}},
	{"tag":"aes256","protocol":"shadowsocks","settings":{"clients":[],"method":"2022-blake3-aes-256-gcm","password":"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=","network":"tcp,udp"}},
	{"tag":"chacha","protocol":"shadowsocks","settings":{"clients":[],"method":"2022-blake3-chacha20-poly1305","password":"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=","network":"tcp,udp"}},
	{"tag":"legacy","protocol":"shadowsocks","settings":{"clients":[],"method":"aes-256-gcm","password":"legacy-server-password","network":"tcp,udp"}}
]}`

// buildShadowsocksInbound runs Xray's own config builder on a serialized inbound.
func buildShadowsocksInbound(t *testing.T, settings map[string]any) any {
	t.Helper()

	raw, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	var server conf.ShadowsocksServerConfig
	if err := json.Unmarshal(raw, &server); err != nil {
		t.Fatal(err)
	}
	built, err := server.Build()
	if err != nil {
		t.Fatalf("xray rejected the serialized inbound %v: %v", settings, err)
	}
	return built
}

// Xray builds a single-user Shadowsocks 2022 server from an empty client list. That
// server accepts the bare server key, which every Shadowsocks 2022 link carries, and
// rejects every later AddUser, so the inbound must start in multi-user mode.
func TestToBytesStartsEmptyShadowsocks2022InboundsMultiUser(t *testing.T) {
	cfg, err := NewConfig(shadowsocks2022Config, nil)
	if err != nil {
		t.Fatal(err)
	}
	out := serializeConfig(t, cfg)

	for _, tag := range []string{"aes128", "aes256"} {
		settings := out.settings(t, tag)
		built := buildShadowsocksInbound(t, settings)
		if _, ok := built.(*shadowsocks_2022.MultiUserServerConfig); !ok {
			t.Errorf("%s: an inbound without users was built as %T, want a multi-user server", tag, built)
			continue
		}
		clients, _ := settings["clients"].([]any)
		if len(clients) != 1 {
			t.Fatalf("%s: clients = %v, want one placeholder", tag, clients)
		}
		placeholder, _ := clients[0].(map[string]any)
		if placeholder["password"] == settings["password"] {
			t.Fatalf("%s: the placeholder uses the server key", tag)
		}
	}

	// Xray has no multi-user mode for chacha20: a client there would stop the whole core.
	if got := emails(t, out.settings(t, "chacha"), "clients"); len(got) != 0 {
		t.Fatalf("chacha20 inbound clients = %v, want none", got)
	}
	buildShadowsocksInbound(t, out.settings(t, "chacha"))

	// Legacy Shadowsocks stays multi-user with an empty client list.
	if got := emails(t, out.settings(t, "legacy"), "clients"); len(got) != 0 {
		t.Fatalf("legacy inbound clients = %v, want none", got)
	}

	for _, inbound := range cfg.InboundConfigs {
		if len(inbound.clients) != 0 {
			t.Fatalf("ToBytes stored clients on inbound %s: %v", inbound.Tag, inbound.clients)
		}
	}
}

func TestToBytesWritesOnlyRealShadowsocks2022Users(t *testing.T) {
	cfg, err := NewConfig(shadowsocks2022Config, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.syncUsers([]*common.User{{
		Email:    "1",
		Inbounds: []string{"aes128", "aes256"},
		Proxies:  &common.Proxy{Shadowsocks: &common.Shadowsocks{Password: "user-one-password"}},
	}})
	out := serializeConfig(t, cfg)

	for _, tag := range []string{"aes128", "aes256"} {
		if got := emails(t, out.settings(t, tag), "clients"); len(got) != 1 || got[0] != "1" {
			t.Fatalf("%s clients = %v, want [1]", tag, got)
		}
	}
}
