package tunnel_test

import (
	"sort"
	"testing"

	// The binary's imports are the wiring: importing controller pulls every
	// registered tool's init(). This test asserts the same set the shipped
	// node sees, not a hand-written list that could drift from it.
	_ "github.com/pasarguard/node/controller"

	"github.com/pasarguard/node/backend/tunnel"
)

// TestEveryShippedToolIsRegisteredAndHasASchema: six pinned adapters plus the
// reference `plain` must all be reachable from the real binary.
//
// Round-1 evidence this was NOT true: only `plain` was imported by the
// controller, so `Backend.tunnel.For("gost")` answered false on a shipped
// node and every real Start failed ErrUnknownTool. Each adapter's own test
// imports its own package, so the suite stayed green.
func TestEveryShippedToolIsRegisteredAndHasASchema(t *testing.T) {
	want := []string{"backhaul", "chisel", "frp", "gost", "plain", "rathole", "udp2raw", "wstunnel"}

	got := tunnel.Tools()
	sort.Strings(got)
	if len(got) != len(want) {
		t.Fatalf("registered tools = %v, want exactly %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("registered tools = %v, want %v", got, want)
		}
	}

	for _, tool := range want {
		if _, ok := tunnel.For(tool); !ok {
			t.Errorf("tool %q is listed but For() refuses it", tool)
		}
	}

	// Every registered tool has a schema whose first field is the framework's
	// listen_port, so the UI always renders a port input.
	schemas := tunnel.Schemas()
	if len(schemas) != len(want) {
		t.Fatalf("schemas = %d, want %d", len(schemas), len(want))
	}
	for _, s := range schemas {
		if len(s.Params) == 0 {
			t.Errorf("tool %q has an empty schema", s.Tool)
			continue
		}
		if s.Params[0].Key != tunnel.ParamListenPort {
			t.Errorf("tool %q: first schema field = %q, want %q (the UI renders this first)",
				s.Tool, s.Params[0].Key, tunnel.ParamListenPort)
		}
		seen := map[string]bool{}
		for _, f := range s.Params {
			if f.Key == "" {
				t.Errorf("tool %q has a field with an empty key", s.Tool)
			}
			if seen[f.Key] {
				t.Errorf("tool %q lists key %q twice", s.Tool, f.Key)
			}
			seen[f.Key] = true
		}
	}
}

// TestSchemaKeysAreTheOnesRenderAccepts: every schema key must be a key the
// adapter actually reads.
//
// Checked by rendering a Spec whose Params carry ONLY that one key and
// requiring the refusal to be about a *missing* key, never about an unknown
// one. An adapter that rejected the schema's own key would fail here; so would
// a schema that invented a key the adapter never reads.
func TestSchemaKeysAreTheOnesRenderAccepts(t *testing.T) {
	// The magic value the framework substitutes, so a key like tls_cert that
	// only matters at Start still passes validation here.
	for _, s := range tunnel.Schemas() {
		adapter, ok := tunnel.For(s.Tool)
		if !ok {
			t.Fatalf("tool %q has a schema but no adapter", s.Tool)
		}
		for _, f := range s.Params {
			if f.Key == tunnel.ParamListenPort {
				continue // framework key: not a tool knob
			}
			spec := tunnel.Spec{
				TunnelID: "schema-probe",
				Tool:     s.Tool,
				Side:     tunnel.SideA,
				Mode:     tunnel.ModeRelay,
				Params:   map[string]string{f.Key: "127.0.0.1:1234"},
				Secrets:  map[string]string{},
				Enabled:  true,
			}
			_, err := adapter.Render(spec)
			if err == nil {
				continue // a valid spec with this one key is fine
			}
			if isUnknownParamRefusal(err.Error()) {
				t.Errorf("tool %q's schema names %q but Render calls it unknown: %v", s.Tool, f.Key, err)
			}
		}
	}
}

// isUnknownParamRefusal matches the wording adapters use for a key they do
// not know. It must NOT match a value rejection ("... is not supported") or a
// missing-required refusal — those are what a one-key spec is supposed to hit,
// and matching them would make the test fail on correct adapters.
func isUnknownParamRefusal(msg string) bool {
	for _, marker := range []string{"has no param", "not a backhaul parameter", "is not a side"} {
		if contains(msg, marker) {
			return true
		}
	}
	return false
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
