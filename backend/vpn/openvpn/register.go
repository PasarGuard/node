// Package openvpn implements backend.Backend for the OpenVPN core: config
// render, node-owned PKI, the auth executable seam, the management interface,
// the child process and its logs.
//
// One package, one init(), nothing outside it changes — the Phase-1 seam
// (CONTRACT §1.3). The one unavoidable exception is the blank import in
// node/controller/controller.go: without it Go's linker drops this package and
// BackendType_OPENVPN has no Factory ("unknown backend type 4").
//
// GPL: openvpn is GPL-2.0. This package never links it — it renders a config
// file and execve()s a pinned binary, the same relationship the hysteria
// package has to hysteria2.
package openvpn

import (
	"context"

	"github.com/pasarguard/node/backend"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
)

func init() {
	backend.Register(common.BackendType_OPENVPN, func(
		ctx context.Context, in *common.Backend, ports backend.Ports, cfg *config.Config,
	) (backend.Backend, error) {
		c, err := NewConfig(in.GetConfig(), in.GetExcludeInbounds())
		if err != nil {
			return nil, err
		}
		return New(ctx, c, in.GetUsers(), ports, cfg)
	})
}
