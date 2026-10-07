package tunneltest

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/pasarguard/node/backend/tunnel"
)

// The kit is the gate six agents cannot skip — so it must be able to fail.
// These tests drive run() with adapters that violate each contract and assert
// the kit reports the violation, instead of trusting that a green run means
// the steps executed.

type fakeAdapter struct {
	deterministic bool
	renders       int
	startErr      error
}

func (f *fakeAdapter) Render(spec tunnel.Spec) (string, error) {
	if f.deterministic {
		return fmt.Sprintf("cfg|%s|%s|%s|%v", spec.TunnelID, spec.Side, spec.Mode, tunnel.SortedParams(spec.Params)), nil
	}
	f.renders++
	return fmt.Sprintf("cfg-drift-%d", f.renders), nil // different bytes every call
}

func (f *fakeAdapter) Start(context.Context, tunnel.Spec, tunnel.Ports) (tunnel.Handle, error) {
	if f.startErr != nil {
		return nil, f.startErr
	}
	return nil, fmt.Errorf("fakeAdapter has no Start")
}

func (f *fakeAdapter) Preflight(context.Context, tunnel.Spec) []tunnel.Problem { return nil }

func selfSpec(tool string) func(Endpoints) tunnel.Spec {
	return func(e Endpoints) tunnel.Spec {
		return tunnel.Spec{
			TunnelID: e.TunnelID,
			Tool:     tool,
			Side:     e.Side,
			Mode:     e.Mode,
			Params:   map[string]string{},
		}
	}
}

func selfAlloc() tunnel.Ports { return tunnel.Ports{Listen: 0, Control: 1} }

func selfCorrupt(*tunnel.Spec) {}

func completeKit(a tunnel.Adapter, tool string) Kit {
	return Kit{
		Adapter:  a,
		NewSpec:  selfSpec(tool),
		Allocate: selfAlloc,
		Corrupt:  selfCorrupt,
	}
}

// A kit missing a hook must fail with the missing step named — never skip it.
func TestKitFailsWhenHooksAreMissing(t *testing.T) {
	cases := []struct {
		name string
		kit  Kit
		want string
	}{
		{"no adapter", Kit{NewSpec: selfSpec("x"), Allocate: selfAlloc, Corrupt: selfCorrupt}, "Adapter"},
		{"no factory", Kit{Adapter: &fakeAdapter{}, Allocate: selfAlloc, Corrupt: selfCorrupt}, "NewSpec"},
		{"no allocate", Kit{Adapter: &fakeAdapter{}, NewSpec: selfSpec("x"), Corrupt: selfCorrupt}, "Allocate"},
		{"no corrupt", Kit{Adapter: &fakeAdapter{}, NewSpec: selfSpec("x"), Allocate: selfAlloc}, "Corrupt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.kit.run(t.TempDir(), t.Cleanup)
			if err == nil {
				t.Fatalf("kit accepted an incomplete kit — a step would have been skipped")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name the missing %q", err, tc.want)
			}
		})
	}
}

// A Render whose output drifts between calls must fail the first step: the
// restart step would otherwise compare two different configs and "pass".
func TestKitFailsOnNondeterministicRender(t *testing.T) {
	kit := completeKit(&fakeAdapter{deterministic: false}, "kit-self-nondet")
	err := kit.run(t.TempDir(), t.Cleanup)
	if err == nil {
		t.Fatal("kit passed with a drifting Render")
	}
	if !strings.Contains(err.Error(), "render-determinism") || !strings.Contains(err.Error(), "not deterministic") {
		t.Fatalf("error does not name the render-determinism step: %v", err)
	}
}

// A Start that errors must fail the traffic step with the adapter's own error
// visible, not be swallowed.
func TestKitFailsWhenStartFails(t *testing.T) {
	const tool = "kit-self-startfail"
	tunnel.Register(tool, &fakeAdapter{
		deterministic: true,
		startErr:      fmt.Errorf("binary exploded"),
	})
	kit := completeKit(&fakeAdapter{deterministic: true}, tool)
	err := kit.run(t.TempDir(), t.Cleanup)
	if err == nil {
		t.Fatal("kit passed although Start failed")
	}
	if !strings.Contains(err.Error(), "traffic") || !strings.Contains(err.Error(), "binary exploded") {
		t.Fatalf("error does not carry the failing step and cause: %v", err)
	}
}
