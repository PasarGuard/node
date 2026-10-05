package wireguard

import (
	"context"

	"github.com/pasarguard/node/backend"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
)

func init() {
	// WireGuard opens no API listener: its ports come from its own config
	// string, so the allocation it is handed is unused by design.
	backend.Register(common.BackendType_WIREGUARD, func(
		_ context.Context, in *common.Backend, _ backend.Ports, cfg *config.Config,
	) (backend.Backend, error) {
		c, err := NewConfig(in.GetConfig())
		if err != nil {
			return nil, err
		}
		return New(cfg, c, in.GetUsers())
	})
}
