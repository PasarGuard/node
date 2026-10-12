// Package openvpn registers BackendType_OPENVPN and nothing else.
//
// This is a stub on purpose (batch 5a-0): the seam has to exist before the
// core does, or BackendType_OPENVPN has no Factory and Start fails with
// "unknown backend type 4" instead of naming what is missing. The real core
// lands in openvpn-core and replaces this file's body, never the seam: same
// package path, same init(), same blank import in controller.go.
package openvpn

import (
	"context"
	"errors"

	"github.com/pasarguard/node/backend"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
)

// ErrNotImplemented is what a Start of an openvpn core returns until
// openvpn-core lands. A clear error beats a silent no-op: the panel shows the
// core as failed with this text rather than as started-but-serving-nothing.
var ErrNotImplemented = errors.New("openvpn core is not implemented yet")

func init() {
	backend.Register(common.BackendType_OPENVPN, func(
		ctx context.Context, in *common.Backend, ports backend.Ports, cfg *config.Config,
	) (backend.Backend, error) {
		return nil, ErrNotImplemented
	})
}
