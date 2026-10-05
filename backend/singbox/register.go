package singbox

import (
	"context"

	"github.com/pasarguard/node/backend"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
)

func init() {
	backend.Register(common.BackendType_SINGBOX, func(
		ctx context.Context, in *common.Backend, ports backend.Ports, cfg *config.Config,
	) (backend.Backend, error) {
		c, err := NewConfig(in.GetConfig(), in.GetExcludeInbounds())
		if err != nil {
			return nil, err
		}
		return New(ctx, c, in.GetUsers(), ports.ApiPort, ports.MetricPort, cfg)
	})
}
