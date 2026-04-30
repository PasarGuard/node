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

func TestNFTForwardConfigIsScoped(t *testing.T) {
	cfg := nftForwardConfig("wg0", "eth0")

	for _, want := range []string{
		"table inet pg_node_wg_filter",
		"chain forward",
		"type filter hook forward priority 0; policy accept;",
		`iifname "wg0" oifname "eth0" accept comment "pg_node_wg_forward wg0 eth0 outbound"`,
		`iifname "eth0" oifname "wg0" ct state established,related accept comment "pg_node_wg_forward wg0 eth0 return"`,
	} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("config missing %q:\n%s", want, cfg)
		}
	}

	if strings.Contains(cfg, "flush ruleset") {
		t.Fatalf("managed config must not flush the global nft ruleset:\n%s", cfg)
	}
}

func TestParseNFTForwardBaseChains(t *testing.T) {
	const ruleset = `{
		"nftables": [
			{"metainfo": {"version": "1.0.9"}},
			{"table": {"family": "ip", "name": "filter"}},
			{"chain": {"family": "ip", "table": "filter", "name": "FORWARD", "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}},
			{"chain": {"family": "inet", "table": "firewalld", "name": "filter_FORWARD", "type": "filter", "hook": "forward", "prio": 10, "policy": "accept"}},
			{"chain": {"family": "ip6", "table": "filter", "name": "FORWARD", "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}},
			{"chain": {"family": "ip", "table": "filter", "name": "INPUT", "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}}
		]
	}`

	chains, err := parseNFTForwardBaseChains([]byte(ruleset))
	if err != nil {
		t.Fatalf("parseNFTForwardBaseChains returned error: %v", err)
	}

	if len(chains) != 2 {
		t.Fatalf("expected 2 supported forward chains, got %#v", chains)
	}

	if chains[0] != (nftBaseChain{family: "ip", table: "filter", name: "FORWARD"}) {
		t.Fatalf("unexpected first chain: %#v", chains[0])
	}
	if chains[1] != (nftBaseChain{family: "inet", table: "firewalld", name: "filter_FORWARD"}) {
		t.Fatalf("unexpected second chain: %#v", chains[1])
	}
}

func TestNFTString(t *testing.T) {
	if got := nftString("pg_node_wg_forward wg0 eth0 outbound"); got != `"pg_node_wg_forward wg0 eth0 outbound"` {
		t.Fatalf("unexpected quoted nft string: %s", got)
	}
}

func TestNFTRuleHandlesWithComment(t *testing.T) {
	const chain = `table ip filter {
	chain FORWARD {
		iifname "wg0" oifname "eth0" accept comment "pg_node_wg_forward wg0 eth0 outbound" # handle 12
		iifname "eth0" oifname "wg0" ct state established,related accept comment "pg_node_wg_forward wg0 eth0 return" # handle 14
		counter packets 0 bytes 0 # handle 20
	}
}`

	handles := nftRuleHandlesWithComment([]byte(chain), nftForwardRulePrefix)
	if strings.Join(handles, ",") != "12,14" {
		t.Fatalf("unexpected handles: %#v", handles)
	}
}

type staticError string

func (e staticError) Error() string { return string(e) }
