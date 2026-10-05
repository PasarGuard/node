package hysteria

import (
	"context"

	"github.com/pasarguard/node/backend"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
)

// init registers the hysteria2 Factory. This file plus the package it heads is
// the whole integration surface: nothing outside node/backend/hysteria changes,
// which is the point of the seam (CONTRACT §1.3).
//
// The blank import in node/controller/controller.go is the one unavoidable
// exception and it is additive: a new core has to be named somewhere, or Go's
// linker drops the package and its init never runs. Requested from core-runtime
// alongside the executable-path field; see the agent report.
func init() {
	backend.Register(common.BackendType_HYSTERIA2, func(
		ctx context.Context, in *common.Backend, ports backend.Ports, cfg *config.Config,
	) (backend.Backend, error) {
		c, err := NewConfig(in.GetConfig(), in.GetExcludeInbounds())
		if err != nil {
			return nil, err
		}
		// MetricPort is unused: hysteria has no metrics listener, and the
		// traffic stats API takes ApiPort. The port stays reserved rather than
		// handed to anyone else, so a future metric listener cannot collide
		// with this core (CONTRACT §1.4: a port is held for the core's lifetime).
		return New(ctx, c, in.GetUsers(), ports.ApiPort, cfg)
	})
}
