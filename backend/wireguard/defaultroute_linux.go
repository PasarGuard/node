//go:build linux

package wireguard

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
)

// linuxDefaultRouteInterfaceIPv4 returns the egress interface for the IPv4 default route
// (e.g. ens192, eth0, enp0s3). Used when PG_NODE_WG_NAT_OUTPUT_INTERFACE is unset.
func linuxDefaultRouteInterfaceIPv4() (string, bool) {
	if out, err := exec.Command("ip", "-4", "-j", "route", "show", "default").Output(); err == nil {
		var routes []struct {
			Dev string `json:"dev"`
		}
		if err := json.Unmarshal(bytes.TrimSpace(out), &routes); err == nil && len(routes) > 0 {
			if dev := strings.TrimSpace(routes[0].Dev); dev != "" {
				return dev, true
			}
		}
	}
	if out, err := os.ReadFile("/proc/net/route"); err == nil {
		return parseDefaultIfaceFromProcNetRoute(out)
	}
	return "", false
}

// parseDefaultIfaceFromProcNetRoute parses /proc/net/route (kernel ABI).
// Default route rows use destination 00000000.
func parseDefaultIfaceFromProcNetRoute(data []byte) (string, bool) {
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		fields := strings.Fields(string(line))
		if len(fields) < 2 {
			continue
		}
		iface := fields[0]
		if iface == "Iface" {
			continue
		}
		if fields[1] == "00000000" {
			return iface, true
		}
	}
	return "", false
}
