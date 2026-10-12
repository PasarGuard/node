//go:build linux

package wireguard

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/pasarguard/node/config"
)

const (
	envNATOutputInterface = "PG_NODE_WG_NAT_OUTPUT_INTERFACE"
	ipv4ForwardPath       = "/proc/sys/net/ipv4/ip_forward"
	nftTableFamily        = "ip"
	nftTableName          = "pg_node_wg_nat"
	nftPostroutingChain   = "postrouting"
	nftForwardChain       = "forward"
	nftRuleCommentPrefix  = "pg_node_wg "
	nftManglePriority     = -150
)

// applyLinuxHostRouting installs an nftables masquerade rule for traffic from the
// WireGuard interface to the IPv4 default-route egress interface.
//
// wgInterfaceName comes from core JSON interface_name (e.g. wg0, wg1); never hardcoded here.
// The NAT egress interface is resolved in order:
//  1. PG_NODE_WG_NAT_OUTPUT_INTERFACE if set
//  2. IPv4 default route interface (ip -4 -j route, else /proc/net/route)
//  3. eth0 as last-resort fallback
//
// Set PG_NODE_WG_NAT_DISABLE=1 to keep the forward rules but skip masquerade
// (e.g. routing into an Xray TUN where Xray does its own outbound; SNAT there is
// redundant and can interfere).
//
// Optional policy routing: when both PG_NODE_WG_ROUTE_TABLE and
// PG_NODE_WG_ROUTE_OUT_INTERFACE are set, traffic ingressing on the WireGuard
// interface is routed out the given interface via a dedicated table:
//
//	ip rule add iif <wgIf> lookup <table>
//	ip route add default dev <outIface> table <table>
//
// Disable all of this with PG_NODE_WG_HOST_ROUTING=0.
func applyLinuxHostRouting(cfg *config.Config, wgInterfaceName string) func() {
	if cfg != nil && !cfg.WGHostRouting {
		return nil
	}

	wgIf := strings.TrimSpace(wgInterfaceName)
	if wgIf == "" {
		wgIf = "wg0"
	}

	outIf := ""
	if cfg != nil {
		outIf = strings.TrimSpace(cfg.WGNATOutputInterface)
	}
	if outIf == "" {
		var ok bool
		outIf, ok = linuxDefaultRouteInterfaceIPv4()
		if !ok {
			outIf = "eth0"
			log.Printf(
				"wireguard host routing: could not detect default IPv4 egress interface; using fallback %q (set %s)",
				outIf,
				envNATOutputInterface,
			)
		}
	}

	natDisabled := cfg != nil && cfg.WGNATDisable

	egressOnly := true
	if cfg != nil {
		egressOnly = cfg.WGNATEgressOnly
	}
	log.Printf(
		"wireguard host routing: wg interface %q, NAT egress %q (masquerade, egress_only=%v, nat_disabled=%v)",
		wgIf, outIf, egressOnly, natDisabled,
	)

	ownerID := newHostRoutingOwnerID(wgIf)
	log.Printf("wireguard host routing: owner %q", ownerID)

	if err := ensureIPv4Forwarding(); err != nil {
		log.Printf("wireguard host routing: enabling IPv4 forwarding failed: %v", err)
	}

	if !natDisabled {
		if err := ensureNFTMasquerade(wgIf, outIf, egressOnly, ownerID); err != nil {
			log.Printf("wireguard host routing: nftables masquerade failed: %v", err)
		}
	}

	if err := ensureNFTForwarding(wgIf, outIf, ownerID); err != nil {
		log.Printf("wireguard host routing: nftables forward rules failed: %v", err)
	}

	policyRoute := parsePolicyRoute(cfg, wgIf)
	if policyRoute != nil {
		if err := policyRoute.apply(); err != nil {
			log.Printf("wireguard host routing: policy routing failed: %v", err)
		} else {
			log.Printf(
				"wireguard host routing: policy routing iif %q -> table %s default dev %q",
				policyRoute.wgIface, policyRoute.table, policyRoute.outIface,
			)
		}
	}

	return func() {
		if policyRoute != nil {
			if err := policyRoute.cleanup(); err != nil {
				log.Printf("wireguard host routing: policy routing cleanup failed: %v", err)
			}
		}
		if err := cleanupLinuxHostRouting(ownerID); err != nil {
			log.Printf("wireguard host routing: cleanup failed for owner %q: %v", ownerID, err)
		}
	}
}

func envTruthy(s string) bool {
	v := strings.TrimSpace(s)
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}

// policyRouteConfig wires WireGuard ingress traffic into a dedicated routing
// table whose default route points at outIface (e.g. an Xray TUN). This is the
// "selective routing" mechanism: only packets arriving on wgIface are matched,
// host traffic keeps using the main table.
type policyRouteConfig struct {
	wgIface  string
	outIface string
	table    string
}

// parsePolicyRoute returns a config only when both knobs are set; policy
// routing is fully opt-in and independent of NAT.
func parsePolicyRoute(cfg *config.Config, wgIface string) *policyRouteConfig {
	if cfg == nil {
		return nil
	}
	table := strings.TrimSpace(cfg.WGRouteTable)
	outIface := strings.TrimSpace(cfg.WGRouteOutInterface)
	if table == "" || outIface == "" {
		return nil
	}
	return &policyRouteConfig{wgIface: wgIface, outIface: outIface, table: table}
}

func (p *policyRouteConfig) apply() error {
	// ponytail: idempotent via add-then-ignore-exists; no read-back. Ceiling:
	// a stale rule/route from a hard crash (no cleanup) lingers until the next
	// apply re-adds (no-op) — harmless since iif+table are scoped to this wg.
	if err := runIP("rule", "add", "iif", p.wgIface, "lookup", p.table); err != nil && !ipRuleExists(err) {
		return err
	}
	if err := runIP("route", "add", "default", "dev", p.outIface, "table", p.table); err != nil && !ipRuleExists(err) {
		return err
	}
	return nil
}

func (p *policyRouteConfig) cleanup() error {
	var errs []error
	if err := runIP("route", "del", "default", "dev", p.outIface, "table", p.table); err != nil && !ipRuleMissing(err) {
		errs = append(errs, err)
	}
	if err := runIP("rule", "del", "iif", p.wgIface, "lookup", p.table); err != nil && !ipRuleMissing(err) {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func runIP(args ...string) error {
	cmd := exec.Command("ip", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func ipRuleExists(err error) bool {
	return err != nil && strings.Contains(err.Error(), "File exists")
}

func ipRuleMissing(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "No such") || strings.Contains(msg, "not found") || strings.Contains(msg, "does not exist")
}

// ensureNFTMasquerade sets up NAT rules dynamically.
// If egressOnly, only oifname is matched (same idea as "oifname eth0 masquerade" in /etc/nftables.conf).
// Otherwise traffic is matched from the WireGuard interface to the egress interface.
func ensureNFTMasquerade(wgIface, outputIface string, egressOnly bool, ownerID string) error {
	if err := runNFT("add", "table", nftTableFamily, nftTableName); err != nil && !nftAlreadyExists(err) {
		return err
	}

	if err := runNFT(
		"add", "chain", nftTableFamily, nftTableName, nftPostroutingChain,
		"{", "type", "nat", "hook", "postrouting", "priority", "100", ";", "policy", "accept", ";", "}",
	); err != nil && !nftAlreadyExists(err) {
		return err
	}

	chain := nftBaseChain{family: nftTableFamily, table: nftTableName, name: nftPostroutingChain}
	if err := removeNFTRulesWithCommentPrefix(chain, nftOwnerCommentPrefix(ownerID)); err != nil {
		return err
	}

	args := []string{"add", "rule", nftTableFamily, nftTableName, nftPostroutingChain}
	args = append(args, nftMasqueradeRuleArgs(wgIface, outputIface, egressOnly)...)
	args = append(args, "comment", nftString(nftNATRuleComment(ownerID, wgIface, outputIface, egressOnly)))
	return runNFT(args...)
}

func nftMasqueradeRuleArgs(wgIface, outputIface string, egressOnly bool) []string {
	if egressOnly {
		return []string{"oifname", nftString(outputIface), "masquerade"}
	}
	return []string{"iifname", nftString(wgIface), "oifname", nftString(outputIface), "masquerade"}
}

func ensureNFTForwarding(wgIface, outputIface, ownerID string) error {
	chains, err := nftForwardBaseChains()
	if err != nil {
		return err
	}
	for _, chain := range chains {
		if err := removeNFTRulesWithCommentPrefix(chain, nftOwnerCommentPrefix(ownerID)); err != nil {
			return err
		}
		if err := insertNFTForwardRule(chain, wgIface, outputIface, ownerID, false); err != nil {
			return err
		}
		if err := insertNFTForwardRule(chain, wgIface, outputIface, ownerID, true); err != nil {
			return err
		}
	}
	return nil
}

type nftBaseChain struct {
	family string
	table  string
	name   string
}

type nftListRuleset struct {
	NFTables []map[string]json.RawMessage `json:"nftables"`
}

type nftListChain struct {
	Family string          `json:"family"`
	Table  string          `json:"table"`
	Name   string          `json:"name"`
	Hook   string          `json:"hook"`
	Prio   json.RawMessage `json:"prio"`
}

func nftForwardBaseChains() ([]nftBaseChain, error) {
	cmd := exec.Command("nft", "-j", "list", "ruleset")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("nft -j list ruleset: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return parseNFTForwardBaseChains(out)
}

func parseNFTForwardBaseChains(data []byte) ([]nftBaseChain, error) {
	var ruleset nftListRuleset
	if err := json.Unmarshal(data, &ruleset); err != nil {
		return nil, fmt.Errorf("parse nft ruleset: %w", err)
	}

	chains := make([]nftBaseChain, 0)
	for _, item := range ruleset.NFTables {
		raw, ok := item["chain"]
		if !ok {
			continue
		}
		var chain nftListChain
		if err := json.Unmarshal(raw, &chain); err != nil {
			return nil, fmt.Errorf("parse nft chain: %w", err)
		}
		if chain.Hook != nftForwardChain || !nftForwardFamilySupported(chain.Family) || nftMangleChain(chain) {
			continue
		}
		chains = append(chains, nftBaseChain{
			family: chain.Family,
			table:  chain.Table,
			name:   chain.Name,
		})
	}
	return chains, nil
}

func nftForwardFamilySupported(family string) bool {
	return family == "ip" || family == "inet"
}

// nftMangleChain reports forward chains that alter packets rather than filter them, such as
// iptables-nft's mangle FORWARD or fw4's mangle_forward, which hold TCP MSS clamping. An accept
// inserted at their top ends the chain before those rules run, and they do not drop traffic,
// so the forward rules are not inserted there.
func nftMangleChain(chain nftListChain) bool {
	if chain.Table == "mangle" {
		return true
	}
	var prio int
	return json.Unmarshal(chain.Prio, &prio) == nil && prio == nftManglePriority
}

func removeNFTRulesWithCommentPrefix(chain nftBaseChain, commentPrefix string) error {
	cmd := exec.Command("nft", "-a", "list", "chain", chain.family, chain.table, chain.name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft -a list chain %s %s %s: %w: %s", chain.family, chain.table, chain.name, err, strings.TrimSpace(string(out)))
	}

	for _, handle := range nftRuleHandlesWithComment(out, commentPrefix) {
		if err := runNFT("delete", "rule", chain.family, chain.table, chain.name, "handle", handle); err != nil {
			return err
		}
	}
	return nil
}

func nftRuleHandlesWithComment(data []byte, commentPrefix string) []string {
	handles := make([]string, 0)
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.Contains(line, commentPrefix) {
			continue
		}

		before, handle, ok := strings.Cut(line, "# handle ")
		if !ok || strings.TrimSpace(before) == "" {
			continue
		}
		fields := strings.Fields(handle)
		if len(fields) == 0 {
			continue
		}
		handles = append(handles, fields[0])
	}
	return handles
}

func insertNFTForwardRule(chain nftBaseChain, wgIface, outputIface, ownerID string, outbound bool) error {
	comment := nftForwardRuleComment(ownerID, wgIface, outputIface, outbound)
	args := []string{"insert", "rule", chain.family, chain.table, chain.name}
	if outbound {
		args = append(args, "iifname", nftString(wgIface), "oifname", nftString(outputIface), "accept", "comment", nftString(comment))
	} else {
		args = append(args, "iifname", nftString(outputIface), "oifname", nftString(wgIface), "ct", "state", "established,related", "accept", "comment", nftString(comment))
	}
	return runNFT(args...)
}

func nftForwardRuleComment(ownerID, wgIface, outputIface string, outbound bool) string {
	direction := "return"
	if outbound {
		direction = "outbound"
	}
	return fmt.Sprintf("%sowner=%s type=forward iface=%s out=%s direction=%s", nftRuleCommentPrefix, ownerID, wgIface, outputIface, direction)
}

func nftNATRuleComment(ownerID, wgIface, outputIface string, egressOnly bool) string {
	scope := "interface"
	if egressOnly {
		scope = "egress"
	}
	return fmt.Sprintf("%sowner=%s type=nat iface=%s out=%s scope=%s", nftRuleCommentPrefix, ownerID, wgIface, outputIface, scope)
}

func nftOwnerCommentPrefix(ownerID string) string {
	return fmt.Sprintf("%sowner=%s ", nftRuleCommentPrefix, ownerID)
}

func nftString(s string) string {
	return fmt.Sprintf("%q", s)
}

func ensureIPv4Forwarding() error {
	out, err := os.ReadFile(ipv4ForwardPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", ipv4ForwardPath, err)
	}
	if strings.TrimSpace(string(out)) == "1" {
		return nil
	}
	if err := os.WriteFile(ipv4ForwardPath, []byte("1\n"), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", ipv4ForwardPath, err)
	}
	return nil
}

func runNFT(args ...string) error {
	cmd := exec.Command("nft", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func nftAlreadyExists(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "File exists")
}

func cleanupLinuxHostRouting(ownerID string) error {
	var errs []error

	natChain := nftBaseChain{family: nftTableFamily, table: nftTableName, name: nftPostroutingChain}
	if err := removeNFTRulesWithCommentPrefix(natChain, nftOwnerCommentPrefix(ownerID)); err != nil {
		errs = append(errs, err)
	}

	chains, err := nftForwardBaseChains()
	if err != nil {
		errs = append(errs, err)
	} else {
		for _, chain := range chains {
			if err := removeNFTRulesWithCommentPrefix(chain, nftOwnerCommentPrefix(ownerID)); err != nil {
				errs = append(errs, err)
			}
		}
	}

	return errors.Join(errs...)
}

func newHostRoutingOwnerID(wgIface string) string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%s_%d_%d", sanitizeNFTOwnerPart(wgIface), os.Getpid(), time.Now().UnixNano())
	}
	return fmt.Sprintf("%s_%d_%x", sanitizeNFTOwnerPart(wgIface), os.Getpid(), b[:])
}

func sanitizeNFTOwnerPart(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "wg"
	}

	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '_',
			r == '-',
			r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "wg"
	}
	return b.String()
}
