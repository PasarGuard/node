package amnezia

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/pasarguard/node/backend/tunnel"
)

// The portable half of the suite: Render, param validation, the version-string
// pin, obfuscation-parameter grammar, secret hygiene, interface naming and
// Preflight's refusal vocabulary. Nothing here touches the network, so it runs
// on any host — the netns claims live in netns_test.go, which says why it
// cannot run on Windows (CONTRACT §2.3).

func keyOf(b byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32))
}

// fullRowParams is what the panel's one params dict looks like on the wire:
// both sides' prefixed keys present in every Spec (CONTRACT §2.4 row
// encoding), obfuscation keys included. Each side must read only its own
// prefix.
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
		TunnelID: "awgtest-row-0001",
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
		if !strings.Contains(first, "uapi_socket = "+sockPath(IfName(spec))) {
			t.Errorf("side %s: render does not name the control socket:\n%s", side, first)
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

// TestRenderCarriesObfuscationParams: the magic-header knobs the row sets are
// rendered for their own side only, in a fixed order (brief item 5's config
// surface, asserted without a network).
func TestRenderCarriesObfuscationParams(t *testing.T) {
	spec := rowSpec(tunnel.SideA, func(s *tunnel.Spec) {
		for k, v := range map[string]string{
			"a_jc": "4", "a_jmin": "40", "a_jmax": "70", "a_s1": "88", "a_s2": "128",
			"a_h1": "255", "a_h2": "191", "a_h3": "127", "a_h4": "63",
			"b_jc": "9",
		} {
			s.Params[k] = v
		}
	})
	out, err := Adapter{}.Render(spec)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, want := range []string{"jc = 4", "jmin = 40", "jmax = 70", "s1 = 88", "s2 = 128",
		"h1 = 255", "h2 = 191", "h3 = 127", "h4 = 63"} {
		if !strings.Contains(out, want) {
			t.Errorf("render does not carry %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "jc = 9") {
		t.Errorf("side A rendered side B's jc=9 — the prefix is being ignored:\n%s", out)
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
		{"jc not a number", func(s *tunnel.Spec) { s.Params["a_jc"] = "four" }, "a_jc"},
		{"h1 not a range", func(s *tunnel.Spec) { s.Params["a_h1"] = "255-100" }, "a_h1"},
		{"unknown param key", func(s *tunnel.Spec) { s.Params["obfuscation"] = "Jc=4" }, "not an amnezia parameter"},
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
		s.Params["a_jc"] = "4"
		s.Params["b_jc"] = "7"
	})
	sp, err := loadParams(spec)
	if err != nil {
		t.Fatalf("loadParams: %v", err)
	}
	if sp.Address != "10.99.0.1/24" {
		t.Errorf("side a read address %q, want its own a_address", sp.Address)
	}
	if sp.Obfs["jc"] != "4" {
		t.Errorf("side a read jc %q, want its own a_jc=4", sp.Obfs["jc"])
	}
	spec.Side = tunnel.SideB
	sp, err = loadParams(spec)
	if err != nil {
		t.Fatalf("loadParams side b: %v", err)
	}
	if sp.Address != "10.99.0.2/24" {
		t.Errorf("side b read address %q, want its own b_address", sp.Address)
	}
	if sp.Obfs["jc"] != "7" {
		t.Errorf("side b read jc %q, want its own b_jc=7", sp.Obfs["jc"])
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

// TestVersionStringPin is the whole install check for a tool with no hash to
// pin (CONTRACT §2.3 rule 2): the first line of --version must equal the pin
// exactly. Factored so it runs green on a machine that has no amnezia binary.
func TestVersionStringPin(t *testing.T) {
	if err := checkVersion(ExpectedVersion); err != nil {
		t.Fatalf("the pin itself does not match: %v", err)
	}
	for _, bad := range []string{
		"",
		"amneziawg-go v3.1.20260829",
		"amneziawg-go v3.0",
		"wireguard-go v0.0.20250521",
		"amneziawg-go v3.1.20260828 (custom)",
	} {
		if err := checkVersion(bad); err == nil {
			t.Errorf("checkVersion(%q) accepted a string that is not the pin", bad)
		} else if !strings.Contains(err.Error(), ExpectedVersion) {
			t.Errorf("checkVersion(%q) = %v, want it to name the pin", bad, err)
		}
	}
}

// TestUAPIConfigShape is the byte-level receipt of what Start sends to the
// daemon: the blank-line terminator this fork requires (not "end"), the hex
// keys, the obfuscation block and exactly one peer.
func TestUAPIConfigShape(t *testing.T) {
	spec := rowSpec(tunnel.SideA, func(s *tunnel.Spec) {
		s.Params["a_jc"] = "4"
		s.Params["a_h1"] = "100-255"
	})
	sp, err := loadParams(spec)
	if err != nil {
		t.Fatalf("loadParams: %v", err)
	}
	if err := sp.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	h := &handle{
		spec: spec, ports: tunnel.Ports{Listen: 51820, Control: 51821}, sp: sp,
		key: spec.Secrets[SecretPrivateKey],
	}
	payload, err := h.uapiConfig()
	if err != nil {
		t.Fatalf("uapiConfig: %v", err)
	}
	if !strings.HasSuffix(payload, "\n\n") {
		t.Errorf("set block must end with a blank line, got %q", payload[len(payload)-8:])
	}
	if strings.Contains(payload, "end\n") {
		t.Errorf("set block must not carry wireguard-go's \"end\" line:\n%s", payload)
	}
	self, err := hexKey(spec.Secrets[SecretPrivateKey], SecretPrivateKey)
	if err != nil {
		t.Fatalf("hexKey: %v", err)
	}
	peer, err := hexKey(sp.PeerPublicKey, "peer_public_key")
	if err != nil {
		t.Fatalf("hexKey peer: %v", err)
	}
	for _, want := range []string{
		"private_key=" + self + "\n",
		"listen_port=51820\n",
		"jc=4\n",
		"h1=100-255\n",
		"replace_peers=true\n",
		"public_key=" + peer + "\n",
		"endpoint=192.0.2.10:51820\n",
		"allowed_ip=10.67.0.2/32\n",
		"allowed_ip=192.168.20.0/24\n",
		"persistent_keepalive_interval=25\n",
	} {
		if !strings.Contains(payload, want) {
			t.Errorf("set block is missing %q:\n%s", want, payload)
		}
	}
	if strings.Contains(payload, keyOf(1)) {
		t.Error("set block carries the base64 private key — the uapi speaks hex, and nothing may echo the secret")
	}
}

// TestParseGetHandshakeAndCounters: the poller and Stats both read the daemon's
// get reply, so the parser is the assertion surface for "did a handshake
// happen" and "how many bytes went through".
func TestParseGetHandshakeAndCounters(t *testing.T) {
	lines := []string{
		"private_key=" + strings.Repeat("ab", 32),
		"listen_port=51820",
		"public_key=" + strings.Repeat("cd", 32),
		"last_handshake_time_sec=0",
		"last_handshake_time_nsec=0",
		"tx_bytes=0",
		"rx_bytes=0",
		"allowed_ip=10.67.0.2/32",
	}
	port, peers := parseGet(lines)
	if port != 51820 {
		t.Errorf("listen_port = %d, want 51820", port)
	}
	if len(peers) != 1 || peers[0].LastHandshake != 0 || peers[0].Tx != 0 {
		t.Fatalf("peers = %+v, want one peer at 0", peers)
	}
	lines = append(lines[:2],
		"public_key="+strings.Repeat("cd", 32),
		"last_handshake_time_sec=1770000000",
		"tx_bytes=1200",
		"rx_bytes=800",
	)
	_, peers = parseGet(lines)
	if len(peers) != 1 || peers[0].LastHandshake != 1770000000 || peers[0].Tx != 1200 || peers[0].Rx != 800 {
		t.Fatalf("peers = %+v, want the live counters", peers)
	}
	// Two peers must not collapse: a map would have lost the first one.
	lines = append(lines,
		"public_key="+strings.Repeat("ee", 32),
		"last_handshake_time_sec=42",
		"tx_bytes=7",
		"rx_bytes=9",
	)
	_, peers = parseGet(lines)
	if len(peers) != 2 {
		t.Fatalf("peers = %+v, want 2", peers)
	}
	if peers[1].LastHandshake != 42 {
		t.Errorf("second peer handshake = %d, want 42", peers[1].LastHandshake)
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
		if n := len(IfName(spec)); n != 15 {
			t.Errorf("IfName %q is %d chars, want exactly 15 (IFNAMSIZ-1)", IfName(spec), n)
		}
	}
	other := a
	other.TunnelID = "awgtest-row-0002"
	if IfName(other) == IfName(a) {
		t.Error("different tunnel_ids derive the same interface name")
	}
}

// TestPreflightReportsSpecificProblems: every capability the host can lack
// must come back as a named Problem with a fix — never an empty "ready", never
// a raw exec error (CONTRACT §2.3, brief item 8).
func TestPreflightReportsSpecificProblems(t *testing.T) {
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
		p := findCheck(problems, "binary")
		if p == nil {
			t.Fatalf("no binary problem with amneziawg-go off PATH: %v", problems)
		}
		if !strings.Contains(p.Fix, "amnezia-vpn/amneziawg-go") || !strings.Contains(p.Fix, "v3.1.20260828") {
			t.Errorf("binary problem fix does not name the source pin: %q", p.Fix)
		}
		if !strings.Contains(p.Detail, BinaryName) {
			t.Errorf("binary problem detail does not name the binary: %q", p.Detail)
		}
	})

	t.Run("missing-tun", func(t *testing.T) {
		// Point the checker at a path that cannot exist so the absent-device
		// branch runs on a host that has a real /dev/net/tun. Restored on
		// exit; production never reassigns it.
		orig := tunDevice
		tunDevice = filepath.Join(t.TempDir(), "no-tun-here")
		t.Cleanup(func() { tunDevice = orig })

		problems := adapter.Preflight(ctx, rowSpec(tunnel.SideA, nil))
		assertNoRawExec(t, problems)
		p := findCheck(problems, "tun")
		if p == nil {
			t.Fatalf("no tun problem when the TUN device is absent: %v", problems)
		}
		if p.Fix == "" {
			t.Errorf("tun problem has no fix: %s", p.Detail)
		}
	})

	t.Run("wrong-version", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skipf("the wrong-version preflight runs a shell script as a fake %s; %s has no /bin/sh — the version-string comparison itself is asserted by TestVersionStringPin", BinaryName, runtime.GOOS)
		}
		dir := t.TempDir()
		bin := filepath.Join(dir, BinaryName)
		if err := os.WriteFile(bin, []byte("#!/bin/sh\necho 'amneziawg-go v0.0.1-not-the-pin'\n"), 0o755); err != nil {
			t.Fatalf("write fake binary: %v", err)
		}
		spec := rowSpec(tunnel.SideA, func(s *tunnel.Spec) { s.Params[tunnel.ParamBinaryPath] = bin })
		problems := adapter.Preflight(ctx, spec)
		assertNoRawExec(t, problems)
		p := findCheck(problems, "binary")
		if p == nil {
			t.Fatalf("a binary reporting the wrong version produced no problem: %v", problems)
		}
		if !strings.Contains(p.Detail, ExpectedVersion) {
			t.Errorf("binary problem does not name the pin: %q", p.Detail)
		}
		if !strings.Contains(p.Fix, "v3.1.20260828") || !strings.Contains(p.Fix, "b5928efb") {
			t.Errorf("binary problem fix does not carry the build provenance: %q", p.Fix)
		}
		// Start must refuse it too, not just Preflight.
		_, err := Adapter{}.Start(ctx, spec, tunnel.Ports{Listen: 51820, Control: 51821})
		if err == nil {
			t.Fatal("Start accepted a binary that reports the wrong version")
		}
		if !strings.Contains(err.Error(), ExpectedVersion) {
			t.Errorf("Start refusal does not name the pin: %v", err)
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
