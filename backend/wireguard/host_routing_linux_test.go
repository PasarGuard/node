//go:build linux

package wireguard

import (
	"strings"
	"testing"
)

func TestNFTMasqueradeRule(t *testing.T) {
	if got := nftMasqueradeRule("wg0", "eth0", true); got != `oifname "eth0" masquerade` {
		t.Fatalf("unexpected egress-only rule: %s", got)
	}

	if got := nftMasqueradeRule("wg0", "eth0", false); got != `iifname "wg0" oifname "eth0" masquerade` {
		t.Fatalf("unexpected interface-scoped rule: %s", got)
	}
}

func TestNFTTableMissing(t *testing.T) {
	if nftTableMissing(nil) {
		t.Fatalf("nil error must not be treated as missing table")
	}

	if !nftTableMissing(staticError("No such file or directory")) {
		t.Fatalf("expected missing table error to be ignored")
	}

	if nftTableMissing(staticError("permission denied")) {
		t.Fatalf("unexpected missing table match")
	}
}

func TestNFTMasqueradeConfigIsScoped(t *testing.T) {
	cfg := nftMasqueradeConfig(`oifname "eth0" masquerade`)

	for _, want := range []string{
		"table ip pg_node_wg_nat",
		"chain postrouting",
		"type nat hook postrouting priority 100; policy accept;",
		`oifname "eth0" masquerade`,
	} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("config missing %q:\n%s", want, cfg)
		}
	}

	if strings.Contains(cfg, "flush ruleset") {
		t.Fatalf("managed config must not flush the global nft ruleset:\n%s", cfg)
	}
}

type staticError string

func (e staticError) Error() string { return string(e) }
