package xray

import (
	"context"

	"github.com/pasarguard/node/backend"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
)

// Registration only. Everything this core needs arrives as parameters, so this
// package is the whole of its footprint outside node/backend/registry.go.
func init() {
	backend.Register(common.BackendType_XRAY, func(
		ctx context.Context, in *common.Backend, ports backend.Ports, cfg *config.Config,
	) (backend.Backend, error) {
		c, err := NewConfig(in.GetConfig(), in.GetExcludeInbounds())
		if err != nil {
			return nil, err
		}
		return New(ctx, c, in.GetUsers(), ports.ApiPort, ports.MetricPort, cfg)
	})
}
