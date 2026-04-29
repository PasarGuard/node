//go:build linux

package wireguard

import "testing"

func TestNFTMasqueradeRule(t *testing.T) {
	if got := nftMasqueradeRule("wg0", "eth0", true); got != `oifname "eth0" masquerade` {
		t.Fatalf("unexpected egress-only rule: %s", got)
	}

	if got := nftMasqueradeRule("wg0", "eth0", false); got != `iifname "wg0" oifname "eth0" masquerade` {
		t.Fatalf("unexpected interface-scoped rule: %s", got)
	}
}

func TestNFTAlreadyExists(t *testing.T) {
	if nftAlreadyExists(nil) {
		t.Fatalf("nil error must not be treated as already exists")
	}

	if !nftAlreadyExists(staticError("File exists")) {
		t.Fatalf("expected File exists error to be treated as already exists")
	}

	if nftAlreadyExists(staticError("permission denied")) {
		t.Fatalf("unexpected already exists match")
	}
}

type staticError string

func (e staticError) Error() string { return string(e) }
