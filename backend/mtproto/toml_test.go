package mtproto

import (
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// decodeTOML parses rendered output back, so the tests check the values the
// TOML means rather than the encoder's exact spelling.
func decodeTOML(t *testing.T, rendered string) map[string]any {
	t.Helper()
	var tree map[string]any
	if err := toml.Unmarshal([]byte(rendered), &tree); err != nil {
		t.Fatalf("rendered TOML does not decode: %v\n---\n%s", err, rendered)
	}
	return tree
}

// tomlAt returns the value at path in a decoded TOML tree, or nil.
func tomlAt(tree map[string]any, path ...string) any {
	var current any = tree
	for _, key := range path {
		table, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = table[key]
	}
	return current
}

func decodeJSONObject(t *testing.T, raw string) map[string]any {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	var root map[string]any
	if err := decoder.Decode(&root); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestTOMLEscapesControlCharacters(t *testing.T) {
	value := "bell\a vtab\v soh\x01 quote\" backslash\\ newline\n tab\t del\x7f esc\x1b unicodeé"
	key := "key\x01with\\backslash\ttab"
	quotedKey := `say "hi"`

	out, err := renderTOML(map[string]any{
		"general": map[string]any{"value": value, key: "k", quotedKey: "q"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// telemt reads the file line by line before it parses TOML (includes), so
	// no value may spill onto a second line.
	for _, line := range strings.Split(out, "\n") {
		for _, r := range line {
			if (r < 0x20 && r != '\t') || r == 0x7f {
				t.Errorf("rendered line contains raw control character %U: %q", r, line)
			}
		}
	}

	tree := decodeTOML(t, out)
	for name, want := range map[string]string{"value": value, key: "k", quotedKey: "q"} {
		if got := tomlAt(tree, "general", name); got != want {
			t.Errorf("general[%q] round trip = %#v, want %q\n---\n%s", name, got, want, out)
		}
	}
}

func TestTOMLDropsNullValues(t *testing.T) {
	out, err := renderTOML(decodeJSONObject(t, `{"general": {"ad_tag": null, "x": 1}, "server": {"listeners": [{"ip": "::", "announce": null}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "ad_tag") || strings.Contains(out, "announce") {
		t.Errorf("null values must be dropped\n---\n%s", out)
	}
	tree := decodeTOML(t, out)
	if got := tomlAt(tree, "general", "x"); got != int64(1) {
		t.Errorf("general.x = %#v, want 1", got)
	}

	// Inline tables (objects inside a mixed array) drop nulls too.
	out, err = renderTOML(decodeJSONObject(t, `{"general": {"mixed": [1, {"a": null, "b": 2}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "a =") {
		t.Errorf("null inside an inline table must be dropped\n---\n%s", out)
	}

	// A null array element has no TOML meaning and is an error.
	out, err = renderTOML(decodeJSONObject(t, `{"general": {"list": [1, null]}}`))
	if err == nil {
		t.Errorf("null inside an array must be an error, got\n%s", out)
	} else if !strings.Contains(err.Error(), "general.list[1]") {
		t.Errorf("error %q does not name general.list[1]", err)
	}
}

func TestTOMLNumbers(t *testing.T) {
	out, err := renderTOML(decodeJSONObject(t, `{"general": {"int": 443, "neg": -5, "float": 1.5, "exp": 1e5, "whole_float": 1.0, "max": 9223372036854775807}}`))
	if err != nil {
		t.Fatal(err)
	}
	// The encoder writes a json.Number as a string; telemt needs numbers.
	if !strings.Contains(out, "int = 443\n") {
		t.Errorf("integer is not rendered as a bare TOML integer\n---\n%s", out)
	}

	tree := decodeTOML(t, out)
	expect := map[string]any{
		"int":         int64(443),
		"neg":         int64(-5),
		"float":       1.5,
		"exp":         float64(100000),
		"whole_float": float64(1),
		"max":         int64(9223372036854775807),
	}
	for key, want := range expect {
		if got := tomlAt(tree, "general", key); got != want {
			t.Errorf("general.%s = %#v, want %#v\n---\n%s", key, got, want, out)
		}
	}

	for raw, wantInError := range map[string]string{
		`{"general": {"big": 9223372036854775808}}`: "general.big",
		`{"general": {"huge": 1e400}}`:              "general.huge",
	} {
		if out, err := renderTOML(decodeJSONObject(t, raw)); err == nil {
			t.Errorf("%s: want an error, got\n%s", raw, out)
		} else if !strings.Contains(err.Error(), wantInError) {
			t.Errorf("%s: error %q does not name %s", raw, err, wantInError)
		}
	}
}

func TestTOMLArrayOfTables(t *testing.T) {
	out, err := renderTOML(decodeJSONObject(t, `{"server": {"port": 443, "listeners": [{"ip": "0.0.0.0"}, {"ip": "::"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(out, "[[server.listeners]]"); got != 2 {
		t.Errorf("[[server.listeners]] appears %d times, want 2\n---\n%s", got, out)
	}

	tree := decodeTOML(t, out)
	listeners, ok := tomlAt(tree, "server", "listeners").([]any)
	if !ok || len(listeners) != 2 {
		t.Fatalf("server.listeners = %#v, want two tables", tomlAt(tree, "server", "listeners"))
	}
	for index, want := range []string{"0.0.0.0", "::"} {
		listener, _ := listeners[index].(map[string]any)
		if got := listener["ip"]; got != want {
			t.Errorf("server.listeners[%d].ip = %#v, want %q", index, got, want)
		}
	}
	if got := tomlAt(tree, "server", "port"); got != int64(443) {
		t.Errorf("server.port = %#v, want 443", got)
	}
}

func TestTOMLSignedZero(t *testing.T) {
	out, err := renderTOML(decodeJSONObject(t, `{"general": {"int_zero": -0, "float_zero": -0.0}}`))
	if err != nil {
		t.Fatal(err)
	}
	tree := decodeTOML(t, out)
	if got := tomlAt(tree, "general", "int_zero"); got != int64(0) {
		t.Errorf("general.int_zero = %#v, want 0", got)
	}
	if got, ok := tomlAt(tree, "general", "float_zero").(float64); !ok || got != 0 || !math.Signbit(got) {
		t.Errorf("general.float_zero = %#v, want -0.0\n---\n%s", tomlAt(tree, "general", "float_zero"), out)
	}
}

func TestTOMLRefusesUnconvertedContainers(t *testing.T) {
	// A typed container could hold a json.Number the conversion never sees.
	if out, err := renderTOML(map[string]any{"server": map[string]any{"listeners": []map[string]any{{"port": json.Number("443")}}}}); err == nil {
		t.Errorf("typed container rendered without error\n---\n%s", out)
	}
}

// TestRenderGolden pins the whole rendered file, so a go-toml upgrade that
// changes the output shows up here.
func TestRenderGolden(t *testing.T) {
	cfg, err := NewConfig(`{"general": {"ad_tag": null, "modes": {"classic": false, "secure": false, "tls": true}}, "censorship": {"tls_domain": "example.com"}, "server": {"port": 443, "listeners": [{"ip": "0.0.0.0"}, {"ip": "::", "port": 8443}]}}`)
	if err != nil {
		t.Fatal(err)
	}
	out, err := cfg.Render(map[string]*runtimeUser{
		"1": {Username: "1", Secret: testSecret, MaxTCPConns: 4},
		"2": {Username: "2", Secret: otherSecret, UserAdTag: thirdSecret},
	}, &runtimeUser{Username: "pgm_0123456789abcdef", Secret: thirdSecret}, 12345, 23456, "Bearer token")
	if err != nil {
		t.Fatal(err)
	}

	const want = `[access]
[access.user_ad_tags]
2 = '0123456789abcdef0123456789abcdef'

[access.user_enabled]
pgm_0123456789abcdef = false

[access.user_max_tcp_conns]
1 = 4

[access.users]
1 = '00112233445566778899aabbccddeeff'
2 = 'ffeeddccbbaa00112233445566778899'
pgm_0123456789abcdef = '0123456789abcdef0123456789abcdef'

[censorship]
tls_domain = 'example.com'

[general]
disable_colors = true

[general.modes]
classic = false
secure = false
tls = true

[general.telemetry]
user_enabled = true

[logging]
destination = 'stderr'

[server]
metrics_listen = '127.0.0.1:23456'
metrics_port = 23456
metrics_whitelist = ['127.0.0.1/32', '::1/128']
port = 443

[server.api]
auth_header = 'Bearer token'
enabled = true
listen = '127.0.0.1:12345'
read_only = false
whitelist = ['127.0.0.1/32', '::1/128']

[[server.listeners]]
ip = '0.0.0.0'

[[server.listeners]]
ip = '::'
port = 8443
`
	if out != want {
		t.Errorf("rendered config changed\n--- got\n%s\n--- want\n%s", out, want)
	}
}

// checkNoIncludeLines must match exactly the lines telemt's
// preprocess_includes expands: trimmed, "include", optional space, "=".
func TestCheckNoIncludeLines(t *testing.T) {
	for line, expanded := range map[string]bool{
		"include = 'x'":     true,
		"include='x'":       true,
		"\tinclude = 'x'":   true,
		"  include\t= 'x'":  true,
		"include = 'x'\r":   true,
		"include_x = 1":     false,
		"included = 1":      false,
		"Include = 1":       false,
		"'include' = 'x'":   false,
		`"include" = 'x'`:   false,
		"x = 'include = y'": false,
		"[include]":         false,
	} {
		err := checkNoIncludeLines("[general]\n" + line + "\n")
		if got := err != nil; got != expanded {
			t.Errorf("%q: refused = %v, want %v (err %v)", line, got, expanded, err)
		}
	}
}

// telemt expands any line of the form `include = <path>` as a textual include
// before it parses TOML (src/config/load/includes.rs), whatever table it sits
// in. A key named include must therefore never reach telemt.
func TestTOMLRejectsIncludeKeys(t *testing.T) {
	cases := map[string]map[string]any{
		"[general]":            {"general": map[string]any{"include": "/etc/shadow"}},
		"[access.users]":       {"access": map[string]any{"users": map[string]any{"include": testSecret}}},
		"[[server.listeners]]": {"server": map[string]any{"listeners": []any{map[string]any{"include": "/etc/shadow"}}}},
	}
	for table, root := range cases {
		out, err := renderTOML(root)
		if err == nil {
			t.Errorf("%s: include key rendered without error\n---\n%s", table, out)
			continue
		}
		if !strings.Contains(err.Error(), table) {
			t.Errorf("%s: error %q does not name the table", table, err)
		}
	}

	// Only the exact key matches, as in telemt.
	out, err := renderTOML(map[string]any{"general": map[string]any{"included": "x", "inline": map[string]any{"nested": []any{"include = x"}}}})
	if err != nil {
		t.Fatalf("keys that only start with include must render: %v", err)
	}
	if got := tomlAt(decodeTOML(t, out), "general", "included"); got != "x" {
		t.Errorf("general.included = %#v, want x", got)
	}
}

// TestRenderWebGolden pins a whole render with one WEB vhost.
func TestRenderWebGolden(t *testing.T) {
	cfg, err := NewConfig(webTestConfig(`, "user_profile": {"secret_mode": "plain", "max_sessions": 8, "max_streams_per_session": 4}`))
	if err != nil {
		t.Fatal(err)
	}
	out, err := cfg.Render(map[string]*runtimeUser{
		"1": {Username: "1", Secret: testSecret},
		"2": {Username: "2", Secret: otherSecret},
	}, &runtimeUser{Username: "pgm_0123456789abcdef", Secret: thirdSecret}, 12345, 23456, "Bearer token")
	if err != nil {
		t.Fatal(err)
	}

	const want = `[access]
[access.user_enabled]
pgm_0123456789abcdef = false

[access.users]
1 = '00112233445566778899aabbccddeeff'
2 = 'ffeeddccbbaa00112233445566778899'
pgm_0123456789abcdef = '0123456789abcdef0123456789abcdef'

[general]
disable_colors = true

[general.telemetry]
user_enabled = true

[logging]
destination = 'stderr'

[server]
metrics_listen = '127.0.0.1:23456'
metrics_port = 23456
metrics_whitelist = ['127.0.0.1/32', '::1/128']
port = 443

[server.api]
auth_header = 'Bearer token'
enabled = true
listen = '127.0.0.1:12345'
read_only = false
whitelist = ['127.0.0.1/32', '::1/128']

[[server.listeners]]
ip = '0.0.0.0'

[[server.listeners]]
ip = '127.0.0.1'
port = 18080
transport = 'web'
web_trusted_proxy_cidrs = ['127.0.0.1/32']

[web]
enabled = true

[web.limits]
max_profiles = 262144

[[web.vhosts]]
host = 'proxy.example.com'
public_addr = '203.0.113.10:443'

[web.vhosts.decoy]
mode = 'http_upstream'
upstream = 'http://127.0.0.1:18081'

[[web.vhosts.profiles]]
max_sessions = 8
max_streams_per_session = 4
secret_mode = 'plain'
user = '1'

[[web.vhosts.profiles]]
max_sessions = 8
max_streams_per_session = 4
secret_mode = 'plain'
user = '2'
`
	if out != want {
		t.Errorf("rendered config changed\n--- got\n%s\n--- want\n%s", out, want)
	}
}
