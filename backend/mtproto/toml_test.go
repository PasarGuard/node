package mtproto

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pelletier/go-toml"
)

// decodeTOML parses rendered output with an independent TOML decoder, so the
// tests check real TOML validity rather than the renderer's own idea of it.
func decodeTOML(t *testing.T, rendered string) *toml.Tree {
	t.Helper()
	tree, err := toml.Load(rendered)
	if err != nil {
		t.Fatalf("rendered TOML does not decode: %v\n---\n%s", err, rendered)
	}
	return tree
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

	out, err := renderTOML(map[string]any{
		"general": map[string]any{"value": value, key: "k"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// go-toml v1.9.5 cannot decode \" inside a quoted key (TOML 1.0 allows
	// it), so this key is checked on the rendered text only.
	quoted, err := renderTOML(map[string]any{"quoted": map[string]any{`say "hi"`: "q"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(quoted, `"say \"hi\"" = "q"`) {
		t.Errorf("key with a quote is not rendered as an escaped basic string\n---\n%s", quoted)
	}

	for _, want := range []string{`\u0007`, `\u000B`, `\u0001`, `\"`, `\\`, `\n`, `\u007F`, `\u001B`} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered TOML missing escape %s\n---\n%s", want, out)
		}
	}
	for _, invalid := range []string{`\a`, `\v`, `\x`} {
		if strings.Contains(out, invalid) {
			t.Errorf("rendered TOML contains non-TOML escape %s\n---\n%s", invalid, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		for _, r := range line {
			if (r < 0x20 && r != '\t') || r == 0x7f {
				t.Errorf("rendered line contains raw control character %U: %q", r, line)
			}
		}
	}

	tree := decodeTOML(t, out)
	if got := tree.GetPath([]string{"general", "value"}); got != value {
		t.Errorf("value round trip = %q, want %q", got, value)
	}
	if got := tree.GetPath([]string{"general", key}); got != "k" {
		t.Errorf("escaped key round trip = %v, want %q", got, "k")
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
	if got := tree.GetPath([]string{"general", "x"}); got != int64(1) {
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
	if out, err := renderTOML(decodeJSONObject(t, `{"general": {"list": [1, null]}}`)); err == nil {
		t.Errorf("null inside an array must be an error, got\n%s", out)
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
	listeners, ok := tree.GetPath([]string{"server", "listeners"}).([]*toml.Tree)
	if !ok || len(listeners) != 2 {
		t.Fatalf("server.listeners = %#v, want two tables", tree.GetPath([]string{"server", "listeners"}))
	}
	if listeners[0].Get("ip") != "0.0.0.0" || listeners[1].Get("ip") != "::" {
		t.Errorf("listener ips = %v, %v", listeners[0].Get("ip"), listeners[1].Get("ip"))
	}
	if got := tree.GetPath([]string{"server", "port"}); got != int64(443) {
		t.Errorf("server.port = %#v, want 443", got)
	}
}

// telemt expands any line of the form `include = "<path>"` as a textual
// include before it parses TOML (src/config/load/includes.rs), whatever table
// it sits in. A key named include must therefore never render bare.
func TestTOMLQuotesIncludeKeys(t *testing.T) {
	out, err := renderTOML(map[string]any{
		"general": map[string]any{"include": "/etc/shadow"},
		"access":  map[string]any{"users": map[string]any{"include": testSecret}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(out, "\n") {
		rest, found := strings.CutPrefix(strings.TrimSpace(line), "include")
		if found && strings.HasPrefix(strings.TrimSpace(rest), "=") {
			t.Errorf("line would be expanded by telemt as an include: %q", line)
		}
	}

	tree := decodeTOML(t, out)
	if got := tree.GetPath([]string{"general", "include"}); got != "/etc/shadow" {
		t.Errorf("general.include = %v, want the quoted key to round trip", got)
	}
}
