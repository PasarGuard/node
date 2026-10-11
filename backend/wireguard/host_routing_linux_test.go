//go:build linux

package wireguard

import (
	"strings"
	"testing"

	"github.com/pasarguard/node/config"
)

func TestNFTMasqueradeRuleArgs(t *testing.T) {
	if got := strings.Join(nftMasqueradeRuleArgs("wg0", "eth0", true), " "); got != `oifname "eth0" masquerade` {
		t.Fatalf("unexpected egress-only args: %s", got)
	}

	if got := strings.Join(nftMasqueradeRuleArgs("wg0", "eth0", false), " "); got != `iifname "wg0" oifname "eth0" masquerade` {
		t.Fatalf("unexpected masquerade args: %s", got)
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

func TestParseNFTForwardBaseChainsSkipsMangleChains(t *testing.T) {
	const ruleset = `{
		"nftables": [
			{"chain": {"family": "ip", "table": "mangle", "name": "FORWARD", "type": "filter", "hook": "forward", "prio": -150, "policy": "accept"}},
			{"chain": {"family": "inet", "table": "fw4", "name": "mangle_forward", "type": "filter", "hook": "forward", "prio": -150, "policy": "accept"}},
			{"chain": {"family": "inet", "table": "fw4", "name": "forward", "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}},
			{"chain": {"family": "ip", "table": "filter", "name": "FORWARD", "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}},
			{"chain": {"family": "ip", "table": "custom", "name": "fwd", "type": "filter", "hook": "forward", "prio": "unexpected", "policy": "accept"}}
		]
	}`

	chains, err := parseNFTForwardBaseChains([]byte(ruleset))
	if err != nil {
		t.Fatalf("parseNFTForwardBaseChains returned error: %v", err)
	}

	want := []nftBaseChain{
		{family: "inet", table: "fw4", name: "forward"},
		{family: "ip", table: "filter", name: "FORWARD"},
		{family: "ip", table: "custom", name: "fwd"},
	}
	if len(chains) != len(want) {
		t.Fatalf("expected %d chains without the mangle ones, got %#v", len(want), chains)
	}
	for i := range want {
		if chains[i] != want[i] {
			t.Fatalf("chain %d: expected %#v, got %#v", i, want[i], chains[i])
		}
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
		iifname "wg0" oifname "eth0" accept comment "pg_node_wg owner=owner-1 type=forward iface=wg0 out=eth0 direction=outbound" # handle 12
		iifname "eth0" oifname "wg0" ct state established,related accept comment "pg_node_wg owner=owner-1 type=forward iface=wg0 out=eth0 direction=return" # handle 14
		iifname "wg2" oifname "eth0" accept comment "pg_node_wg owner=owner-2 type=forward iface=wg2 out=eth0 direction=outbound" # handle 18
		counter packets 0 bytes 0 # handle 20
	}
}`

	handles := nftRuleHandlesWithComment([]byte(chain), nftOwnerCommentPrefix("owner-1"))
	if strings.Join(handles, ",") != "12,14" {
		t.Fatalf("unexpected handles: %#v", handles)
	}
}

func TestNFTOwnerCommentPrefix(t *testing.T) {
	if got := nftOwnerCommentPrefix("owner-1"); got != "pg_node_wg owner=owner-1 " {
		t.Fatalf("unexpected owner prefix: %q", got)
	}
}

func TestSanitizeNFTOwnerPart(t *testing.T) {
	if got := sanitizeNFTOwnerPart(" wg/1:bad "); got != "wg_1_bad" {
		t.Fatalf("unexpected sanitized owner part: %q", got)
	}
	if got := sanitizeNFTOwnerPart(" "); got != "wg" {
		t.Fatalf("unexpected empty sanitized owner part: %q", got)
	}
}

type staticError string

func (e staticError) Error() string { return string(e) }

func TestParsePolicyRoute(t *testing.T) {
	if parsePolicyRoute(nil, "wg0") != nil {
		t.Fatalf("policy route must be nil when cfg is nil")
	}

	cfg := &config.Config{}
	if parsePolicyRoute(cfg, "wg0") != nil {
		t.Fatalf("policy route must be nil when unset")
	}

	cfg.WGRouteTable = "100"
	if parsePolicyRoute(cfg, "wg0") != nil {
		t.Fatalf("policy route must be nil when only table set")
	}

	cfg.WGRouteOutInterface = "xray0"
	got := parsePolicyRoute(cfg, "wg0")
	if got == nil {
		t.Fatalf("expected policy route config when both set")
	}
	if got.wgIface != "wg0" || got.table != "100" || got.outIface != "xray0" {
		t.Fatalf("unexpected policy route config: %#v", got)
	}
}

func TestIPRuleErrorClassifiers(t *testing.T) {
	if !ipRuleExists(staticError("RTNETLINK answers: File exists")) {
		t.Fatalf("File exists must be treated as already-exists")
	}
	if ipRuleExists(nil) {
		t.Fatalf("nil must not be already-exists")
	}
	if !ipRuleMissing(staticError("RTNETLINK answers: No such file or directory")) {
		t.Fatalf("No such must be treated as missing")
	}
	if ipRuleMissing(nil) {
		t.Fatalf("nil must not be missing")
	}
}
