//go:build linux

package mtproto

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// sighupCaught reports whether process pid has a SIGHUP handler installed,
// from the SigCgt mask in /proc/<pid>/status.
func sighupCaught(pid int) (bool, error) {
	if pid <= 0 {
		return false, errors.New("telemt process is not running")
	}
	status, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return false, err
	}
	return parseSIGHUPCaught(string(status))
}

// parseSIGHUPCaught reads the SIGHUP bit of the SigCgt hex mask in the text
// of /proc/<pid>/status: signal n is bit n-1, so SIGHUP (1) is bit 0.
func parseSIGHUPCaught(status string) (bool, error) {
	for _, line := range strings.Split(status, "\n") {
		mask, ok := strings.CutPrefix(line, "SigCgt:")
		if !ok {
			continue
		}
		mask = strings.TrimSpace(mask)
		if mask == "" || strings.Trim(mask, "0123456789abcdefABCDEF") != "" {
			return false, fmt.Errorf("unexpected SigCgt mask %q", mask)
		}
		// The last hex digit holds signals 1 to 4, whatever the mask width.
		digit, _ := strconv.ParseUint(mask[len(mask)-1:], 16, 8)
		return digit&1 != 0, nil
	}
	return false, errors.New("no SigCgt line in the process status")
}
