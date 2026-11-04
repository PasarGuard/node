//go:build !linux

package mtproto

import "errors"

// sighupCaught cannot read signal handlers outside Linux, so the node falls
// back to telemtSignalGrace.
func sighupCaught(int) (bool, error) {
	return false, errors.ErrUnsupported
}
