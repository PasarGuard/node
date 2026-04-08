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
)

// applyLinuxHostRouting enables IPv4/IPv6 forwarding and installs an nftables masquerade
// rule for traffic from the WireGuard interface to the IPv4 default-route egress interface.
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

	if err := writeSysctl("net/ipv4/ip_forward", "1"); err != nil {
		log.Printf("wireguard host routing: ipv4 forwarding: %v", err)
	}
	if err := writeSysctl("net/ipv6/conf/all/forwarding", "1"); err != nil {
		log.Printf("wireguard host routing: ipv6 forwarding: %v", err)
	}

	log.Printf("wireguard host routing: wg interface %q, NAT egress %q (masquerade)", wgIf, outIf)

	if err := ensureNFTMasquerade(wgIf, outIf); err != nil {
		log.Printf("wireguard host routing: nftables masquerade (optional): %v", err)
	}
}

func writeSysctl(relPath, value string) error {
	path := "/proc/sys/" + relPath
	return os.WriteFile(path, []byte(value+"\n"), 0)
}

// ensureNFTMasquerade replaces table ip pasarguard_wg. Traffic is matched from the
// configured WireGuard interface to the detected/configured egress interface only.
func ensureNFTMasquerade(wgIface, outputIface string) error {
	del := exec.Command("nft", "delete", "table", "ip", "pasarguard_wg")
	_ = del.Run()

	cfg := fmt.Sprintf(`table ip pasarguard_wg {
	chain postrouting {
		type nat hook postrouting priority 100;
		policy accept;
		iifname %q oifname %q masquerade
	}
}
`, wgIface, outputIface)

	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(cfg)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
