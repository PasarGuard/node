//go:build !linux

package wireguard

import "errors"

func newAmneziaManager(string, AmneziaConfig) (*Manager, error) {
	return nil, errors.New("AmneziaWG requires Linux and /dev/net/tun")
}
