package plain

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/pasarguard/node/backend/tunnel"
	"github.com/pasarguard/node/backend/tunnel/tunneltest"
)

// TestFourPartRelay is the reference run of the four-part testkit: traffic,
// restart, negative control, logs — all four, zero skips. Every Phase 3 tool
// agent reproduces exactly this against their own adapter.
func TestFourPartRelay(t *testing.T) {
	// The factory declares PLAIN_TOKEN as a secret with an empty value; the
	// environment supplies it, the Corrupt hook overrides it for step 3.
	t.Setenv(SecretToken, "four-part-secret")

	alloc := tunnel.NewAllocator()
	kit := tunneltest.Kit{
		Adapter: Adapter{},
		NewSpec: func(e tunneltest.Endpoints) tunnel.Spec {
			return tunnel.Spec{
				TunnelID:    e.TunnelID,
				Tool:        Tool,
				ToolVersion: Version,
				Side:        e.Side,
				Mode:        e.Mode,
				Params: map[string]string{
					"listen_host": "127.0.0.1",
					"peer":        e.Peer,
					"target":      e.Target,
				},
				Secrets: map[string]string{SecretToken: ""},
				Enabled: true,
			}
		},
		Allocate: func() tunnel.Ports { return alloc.AllocPair() },
		Corrupt: func(s *tunnel.Spec) {
			if s.Secrets == nil {
				s.Secrets = map[string]string{}
			}
			s.Secrets[SecretToken] = "deliberately-wrong-token"
		},
	}
	tunneltest.Run(t, kit)
}

// TestRenderIsDeterministicAndTyped covers the two render obligations without
// the full kit: byte-identical output for one Spec, and an explicit refusal of
// a mode whose loopback test never ran (CONTRACT §2.0).
func TestRenderIsDeterministicAndTyped(t *testing.T) {
	spec := tunnel.Spec{
		TunnelID: "render-1",
		Tool:     Tool,
		Side:     tunnel.SideA,
		Mode:     tunnel.ModeRelay,
		Params:   map[string]string{"peer": "127.0.0.1:1", "listen_host": "127.0.0.1"},
	}
	a := Adapter{}
	first, err := a.Render(spec)
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.Render(spec)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("renders differ:\n%s\n---\n%s", first, second)
	}
	if !strings.Contains(first, "mode = relay") || !strings.Contains(first, "side = a") {
		t.Fatalf("render does not spell out mode and side:\n%s", first)
	}

	spec.Mode = tunnel.ModeReverse
	if _, err := a.Render(spec); !errors.Is(err, tunnel.ErrModeUnsupported) {
		t.Fatalf("reverse must be refused by Render, got %v", err)
	}
}

// TestStartRefusesReverse: the refusal has to be at Start too — a caller that
// skips Render must not silently get a relay.
func TestStartRefusesReverse(t *testing.T) {
	spec := tunnel.Spec{
		TunnelID: "reverse-1",
		Tool:     Tool,
		Side:     tunnel.SideA,
		Mode:     tunnel.ModeReverse,
		Params:   map[string]string{"peer": "127.0.0.1:1"},
	}
	_, err := Adapter{}.Start(context.Background(), spec, tunnel.Ports{Listen: 0, Control: 1})
	if !errors.Is(err, tunnel.ErrModeUnsupported) {
		t.Fatalf("want ErrModeUnsupported, got %v", err)
	}
}

// TestPreflightReportsUntestedMode: Preflight must be non-empty for what this
// host/spec cannot do — here, a mode with no passing test — so the panel can
// show a reason instead of "failed to start" (scope test 9).
func TestPreflightReportsUntestedMode(t *testing.T) {
	spec := tunnel.Spec{
		TunnelID: "pf-1",
		Tool:     Tool,
		Side:     tunnel.SideA,
		Mode:     tunnel.ModeReverse,
		Params:   map[string]string{"peer": "127.0.0.1:1"},
	}
	problems := Adapter{}.Preflight(context.Background(), spec)
	if len(problems) == 0 {
		t.Fatal("Preflight returned no problems for an untested mode")
	}
	if problems[0].Check != "mode" {
		t.Fatalf("problem check = %q, want mode", problems[0].Check)
	}

	// And the happy shape is empty: a valid relay side is ready.
	ok := tunnel.Spec{
		TunnelID: "pf-2", Tool: Tool, Side: tunnel.SideA, Mode: tunnel.ModeRelay,
		Params: map[string]string{"peer": "127.0.0.1:1"},
	}
	if got := (Adapter{}).Preflight(context.Background(), ok); len(got) != 0 {
		t.Fatalf("relay side-a preflight should be ready, got %v", got)
	}
}

// TestMissingParamsAreRefused: side a without peer / side b without target
// cannot possibly work, and must say so at Start rather than half-starting.
func TestMissingParamsAreRefused(t *testing.T) {
	a := tunnel.Spec{TunnelID: "p1", Tool: Tool, Side: tunnel.SideA, Mode: tunnel.ModeRelay}
	if _, err := (Adapter{}).Start(context.Background(), a, tunnel.Ports{Listen: 0}); err == nil ||
		!strings.Contains(err.Error(), "peer") {
		t.Fatalf("side a without peer: want an error naming peer, got %v", err)
	}
	b := tunnel.Spec{TunnelID: "p2", Tool: Tool, Side: tunnel.SideB, Mode: tunnel.ModeRelay}
	if _, err := (Adapter{}).Start(context.Background(), b, tunnel.Ports{Listen: 0}); err == nil ||
		!strings.Contains(err.Error(), "target") {
		t.Fatalf("side b without target: want an error naming target, got %v", err)
	}
}
