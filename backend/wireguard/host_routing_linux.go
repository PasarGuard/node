//go:build linux

package wireguard

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

const (
	envHostRouting        = "PG_NODE_WG_HOST_ROUTING"
	envNATOutputInterface = "PG_NODE_WG_NAT_OUTPUT_INTERFACE"
	envNATEgressOnly      = "PG_NODE_WG_NAT_EGRESS_ONLY"
	ipv4ForwardPath       = "/proc/sys/net/ipv4/ip_forward"
	nftTableFamily        = "ip"
	nftTableName          = "pg_node_wg_nat"
	nftPostroutingChain   = "postrouting"
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
// Disable all of this with PG_NODE_WG_HOST_ROUTING=0.
func applyLinuxHostRouting(wgInterfaceName string) {
	if v := strings.TrimSpace(os.Getenv(envHostRouting)); v == "0" || strings.EqualFold(v, "false") {
		return
	}

	wgIf := strings.TrimSpace(wgInterfaceName)
	if wgIf == "" {
		wgIf = "wg0"
	}

	outIf := strings.TrimSpace(os.Getenv(envNATOutputInterface))
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

	egressOnly := true
	if env := os.Getenv(envNATEgressOnly); env != "" {
		egressOnly = envTruthy(env)
	}
	log.Printf(
		"wireguard host routing: wg interface %q, NAT egress %q (masquerade, egress_only=%v)",
		wgIf, outIf, egressOnly,
	)

	if err := ensureIPv4Forwarding(); err != nil {
		log.Printf("wireguard host routing: enabling IPv4 forwarding failed: %v", err)
	}

	if err := ensureNFTMasquerade(wgIf, outIf, egressOnly); err != nil {
		log.Printf("wireguard host routing: nftables masquerade failed: %v", err)
	}
}

func envTruthy(s string) bool {
	v := strings.TrimSpace(s)
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}

// ensureNFTMasquerade sets up NAT rules dynamically.
// If egressOnly, only oifname is matched (same idea as "oifname eth0 masquerade" in /etc/nftables.conf).
// Otherwise traffic is matched from the WireGuard interface to the egress interface.
func ensureNFTMasquerade(wgIface, outputIface string, egressOnly bool) error {
	rule := nftMasqueradeRule(wgIface, outputIface, egressOnly)

	if err := runNFT("delete", "table", nftTableFamily, nftTableName); err != nil && !nftTableMissing(err) {
		return err
	}

	return runNFTScript(nftMasqueradeConfig(rule))
}

func nftMasqueradeRule(wgIface, outputIface string, egressOnly bool) string {
	if egressOnly {
		return fmt.Sprintf("oifname %q masquerade", outputIface)
	}
	return fmt.Sprintf("iifname %q oifname %q masquerade", wgIface, outputIface)
}

func nftMasqueradeConfig(rule string) string {
	return fmt.Sprintf(`table %s %s {
	chain %s {
		type nat hook postrouting priority 100; policy accept;
		%s
	}
}
`, nftTableFamily, nftTableName, nftPostroutingChain, rule)
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

func runNFTScript(script string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft -f -: %w: %s", err, strings.TrimSpace(string(out)))
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

func nftTableMissing(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "No such file or directory") ||
		strings.Contains(msg, "does not exist") ||
		strings.Contains(msg, "No such file")
}
