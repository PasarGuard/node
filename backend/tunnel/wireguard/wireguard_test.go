package wireguard

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/pasarguard/node/backend/tunnel"
)

// The portable half of the suite: Render, param validation, secret hygiene,
// interface naming and Preflight's refusal vocabulary. Nothing here touches
// the network, so it runs on any host — the netns claims live in
// netns_test.go, which says why it cannot run on Windows (CONTRACT §2.3).

func keyOf(b byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32))
}

// fullRowParams is what the panel's one params dict looks like on the wire:
// both sides' prefixed keys present in every Spec (CONTRACT §2.4 row
// encoding). Each side must read only its own prefix.
func fullRowParams() map[string]string {
	return map[string]string{
		"a_address":            "10.67.0.1/24",
		"a_lan_cidr":           "192.168.10.0/24",
		"a_peer_endpoint":      "192.0.2.10:51820",
		"a_peer_public_key":    keyOf(2),
		"a_peer_allowed_cidrs": "10.67.0.2/32,192.168.20.0/24",
		"a_netns":              "",
		"b_address":            "10.67.0.2/24",
		"b_lan_cidr":           "192.168.20.0/24",
		"b_peer_endpoint":      "192.0.2.11:51821",
		"b_peer_public_key":    keyOf(3),
		"b_peer_allowed_cidrs": "10.67.0.1/32,192.168.10.0/24",
		"b_netns":              "",
	}
}

func rowSpec(side tunnel.Side, mutate func(*tunnel.Spec)) tunnel.Spec {
	spec := tunnel.Spec{
		TunnelID: "wgtest-row-0001",
		Tool:     Tool,
		Side:     side,
		Mode:     tunnel.ModeRelay,
		Params:   fullRowParams(),
		Secrets:  map[string]string{SecretPrivateKey: keyOf(1)},
		Enabled:  true,
	}
	if mutate != nil {
		mutate(&spec)
	}
	return spec
}

func TestRenderDeterministicForBothSides(t *testing.T) {
	for _, side := range []tunnel.Side{tunnel.SideA, tunnel.SideB} {
		spec := rowSpec(side, nil)
		first, err := Adapter{}.Render(spec)
		if err != nil {
			t.Fatalf("side %s: render: %v", side, err)
		}
		second, err := Adapter{}.Render(spec)
		if err != nil {
			t.Fatalf("side %s: second render: %v", side, err)
		}
		if first != second {
			t.Fatalf("side %s: Render is not deterministic:\nfirst:\n%s\nsecond:\n%s", side, first, second)
		}
		if !strings.Contains(first, "interface = "+IfName(spec)) {
			t.Errorf("side %s: render does not name the interface:\n%s", side, first)
		}
	}
	a, _ := Adapter{}.Render(rowSpec(tunnel.SideA, nil))
	b, _ := Adapter{}.Render(rowSpec(tunnel.SideB, nil))
	if a == b {
		t.Errorf("both sides render identical configs — the side prefix is being ignored:\n%s", a)
	}
}

func TestRenderRefusesReverse(t *testing.T) {
	spec := rowSpec(tunnel.SideA, func(s *tunnel.Spec) { s.Mode = tunnel.ModeReverse })
	_, err := Adapter{}.Render(spec)
	if !errors.Is(err, tunnel.ErrModeUnsupported) {
		t.Fatalf("Render in mode=reverse: err = %v, want ErrModeUnsupported", err)
	}
	// Start must refuse before it touches anything.
	_, err = Adapter{}.Start(context.Background(), spec, tunnel.Ports{Listen: 51820, Control: 51821})
	if !errors.Is(err, tunnel.ErrModeUnsupported) {
		t.Fatalf("Start in mode=reverse: err = %v, want ErrModeUnsupported", err)
	}
}

func TestRenderNeverContainsThePrivateKey(t *testing.T) {
	secret := keyOf(9)
	spec := rowSpec(tunnel.SideA, func(s *tunnel.Spec) { s.Secrets[SecretPrivateKey] = secret })
	out, err := Adapter{}.Render(spec)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(out, secret) {
		t.Fatal("Render output contains the private key — a determinism failure would print it")
	}
	if !strings.Contains(out, SecretPrivateKey) {
		t.Errorf("render does not mention the secret's name:\n%s", out)
	}
}

func TestRenderRejectsBadValues(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*tunnel.Spec)
		want   string
	}{
		{"missing a_address", func(s *tunnel.Spec) { delete(s.Params, "a_address") }, "a_address"},
		{"address is not a CIDR", func(s *tunnel.Spec) { s.Params["a_address"] = "10.67.0.1" }, "a_address"},
		{"lan_cidr is not a CIDR", func(s *tunnel.Spec) { s.Params["a_lan_cidr"] = "192.168.10.0" }, "a_lan_cidr"},
		{"peer_endpoint missing port", func(s *tunnel.Spec) { s.Params["a_peer_endpoint"] = "192.0.2.10" }, "peer_endpoint"},
		{"peer_public_key not a key", func(s *tunnel.Spec) { s.Params["a_peer_public_key"] = "not-base64!!" }, "peer_public_key"},
		{"allowed cidrs not CIDRs", func(s *tunnel.Spec) { s.Params["a_peer_allowed_cidrs"] = "banana" }, "peer_allowed_cidrs"},
		{"allowed cidrs empty", func(s *tunnel.Spec) { s.Params["a_peer_allowed_cidrs"] = " , " }, "peer_allowed_cidrs"},
		{"unknown param key", func(s *tunnel.Spec) { s.Params["obfuscation"] = "Jc=4" }, "not a wireguard parameter"},
		{"other side key only", func(s *tunnel.Spec) {
			delete(s.Params, "a_address")
			s.Params["b_address"] = "10.67.0.2/24"
		}, "a_address"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := rowSpec(tunnel.SideA, tc.mutate)
			_, err := Adapter{}.Render(spec)
			if err == nil {
				t.Fatalf("render succeeded, want refusal containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestLoadParamsReadsOnlyItsOwnSide(t *testing.T) {
	spec := rowSpec(tunnel.SideA, func(s *tunnel.Spec) {
		s.Params["a_address"] = "10.99.0.1/24"
		s.Params["b_address"] = "10.99.0.2/24"
	})
	sp, err := loadParams(spec)
	if err != nil {
		t.Fatalf("loadParams: %v", err)
	}
	if sp.Address != "10.99.0.1/24" {
		t.Errorf("side a read address %q, want its own a_address", sp.Address)
	}
	spec.Side = tunnel.SideB
	sp, err = loadParams(spec)
	if err != nil {
		t.Fatalf("loadParams side b: %v", err)
	}
	if sp.Address != "10.99.0.2/24" {
		t.Errorf("side b read address %q, want its own b_address", sp.Address)
	}
}

// TestValidateKeepsTheRouteList guards the parse step Start drives the `ip
// route` commands from: validate used to run on a value copy, the list was
// built on the copy, and every LAN route silently vanished (point links still
// worked via the connected /24 — only subnet traffic noticed).
func TestValidateKeepsTheRouteList(t *testing.T) {
	sp, err := loadParams(rowSpec(tunnel.SideA, nil))
	if err != nil {
		t.Fatalf("loadParams: %v", err)
	}
	if err := sp.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	want := []string{"10.67.0.2/32", "192.168.20.0/24"}
	if len(sp.Allowed) != len(want) {
		t.Fatalf("Allowed = %v, want %v", sp.Allowed, want)
	}
	for i := range want {
		if sp.Allowed[i] != want[i] {
			t.Errorf("Allowed[%d] = %q, want %q", i, sp.Allowed[i], want[i])
		}
	}
}

func TestStartRefusesAnUnresolvedSecret(t *testing.T) {
	spec := rowSpec(tunnel.SideA, func(s *tunnel.Spec) { s.Secrets[SecretPrivateKey] = "" })
	_, err := Adapter{}.Start(context.Background(), spec, tunnel.Ports{Listen: 51820, Control: 51821})
	if !errors.Is(err, tunnel.ErrSecretUnresolved) {
		t.Fatalf("err = %v, want ErrSecretUnresolved", err)
	}
}

func TestIfNameIsStableAndFitsIFNAMSIZ(t *testing.T) {
	a := rowSpec(tunnel.SideA, nil)
	b := rowSpec(tunnel.SideB, nil)
	if IfName(a) != IfName(a) {
		t.Fatal("IfName is not stable across calls")
	}
	if IfName(a) == IfName(b) {
		t.Errorf("both sides derive the same interface %s — two sides on one host would collide", IfName(a))
	}
	for _, spec := range []tunnel.Spec{a, b} {
		if n := len(IfName(spec)); n > 15 {
			t.Errorf("IfName %q is %d chars, kernel IFNAMSIZ is 15", IfName(spec), n)
		}
	}
	other := a
	other.TunnelID = "wgtest-row-0002"
	if IfName(other) == IfName(a) {
		t.Error("different tunnel_ids derive the same interface name")
	}
}

// TestPreflightReportsSpecificProblems: every capability the host can lack
// must come back as a named Problem with a fix — never an empty "ready", never
// a raw exec error (CONTRACT §2.3, brief item 6).
func TestPreflightReportsSpecificProblems(t *testing.T) {
	// The absent-module branch: the shared checker called with a module no
	// host has. Restored on exit; production never reassigns this.
	orig := moduleCheck
	moduleCheck = func(name string) []tunnel.Problem {
		return tunnel.CheckKernelModule("pg_module_that_is_never_loaded")
	}
	t.Cleanup(func() { moduleCheck = orig })

	adapter := Adapter{}
	ctx := context.Background()

	assertNoRawExec := func(t *testing.T, problems []tunnel.Problem) {
		t.Helper()
		for _, p := range problems {
			for _, marker := range []string{"exit status", "combined output", "CommandContext"} {
				if strings.Contains(p.Detail, marker) {
					t.Errorf("problem %q carries a raw exec error: %s", p.Check, p.Detail)
				}
			}
			if p.Fix == "" {
				t.Errorf("problem %q has no fix: %s", p.Check, p.Detail)
			}
		}
	}

	t.Run("missing-binary", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		problems := adapter.Preflight(ctx, rowSpec(tunnel.SideA, nil))
		assertNoRawExec(t, problems)
		if !hasCheck(problems, "binary") {
			t.Fatalf("no binary problem with wg off PATH: %v", problems)
		}
		for _, p := range problems {
			if p.Check == "binary" && !strings.Contains(p.Fix, "wireguard-tools") {
				t.Errorf("binary problem fix does not say how to install it: %q", p.Fix)
			}
		}
	})

	t.Run("missing-module", func(t *testing.T) {
		problems := adapter.Preflight(ctx, rowSpec(tunnel.SideA, nil))
		assertNoRawExec(t, problems)
		p := findCheck(problems, "kernel_module")
		if p == nil {
			t.Fatalf("no kernel_module problem for an absent module: %v", problems)
		}
		if p.Fix == "" {
			t.Errorf("kernel_module problem has no fix: %s", p.Detail)
		}
	})

	t.Run("missing-netns", func(t *testing.T) {
		spec := rowSpec(tunnel.SideA, func(s *tunnel.Spec) { s.Params["a_netns"] = "pg-no-such-namespace" })
		problems := adapter.Preflight(ctx, spec)
		assertNoRawExec(t, problems)
		p := findCheck(problems, "netns")
		if p == nil {
			t.Fatalf("no netns problem for a namespace that does not exist: %v", problems)
		}
		if p.Fix == "" {
			t.Errorf("netns problem has no fix: %s", p.Detail)
		}
	})

	t.Run("missing-capability", func(t *testing.T) {
		problems := adapter.Preflight(ctx, rowSpec(tunnel.SideA, nil))
		assertNoRawExec(t, problems)
		if !hasCheck(problems, "capability") {
			if !isLinuxRoot() {
				t.Fatalf("no capability problem for a process without CAP_NET_ADMIN: %v", problems)
			}
			t.Log("running as root on Linux: CAP_NET_ADMIN is present by construction; " +
				"the missing-capability branch is asserted by the non-root server run")
		}
	})
}

func isLinuxRoot() bool {
	return runtime.GOOS == "linux" && os.Geteuid() == 0
}

func hasCheck(problems []tunnel.Problem, check string) bool { return findCheck(problems, check) != nil }

func findCheck(problems []tunnel.Problem, check string) *tunnel.Problem {
	for i := range problems {
		if problems[i].Check == check {
			return &problems[i]
		}
	}
	return nil
}
