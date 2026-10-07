//go:build windows

package tunnel

import "errors"

// probeRawSocket is never reached on Windows — CheckRawSocket reports an
// unsupported-check Problem before it runs — but the symbol must exist so the
// file above can stay out of the Windows build.
func probeRawSocket() error {
	return errors.New("raw sockets are not probed on windows")
}
