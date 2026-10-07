package backhaul

import "github.com/pasarguard/node/backend/tunnel"

// schema.go: built beside config.go's knownParams — Render enforces those;
// this is how they reach the panel (glue-2).
func init() {
	tunnel.RegisterSchema(Tool, []tunnel.ParamField{
		{Key: tunnel.ParamListenPort, Help: "Local listen port. The node allocates a free one when empty; pin it only when the other side's peer must know it in advance."},
		{Key: paramListenHost, Help: "Bind address for this side. Defaults to 127.0.0.1."},
		{Key: paramPeer, RequiredFor: []string{"relay:b", "reverse:b"}, Help: "side b: side a's transport address (host:port); backhaul derives port+1 for control."},
		{Key: paramTarget, RequiredFor: []string{"relay:a", "reverse:a"}, Help: "side a: what side b dials (host:port)."},
		{Key: paramTransport, Help: "backhaul transport (the tool's own vocabulary; empty uses its default)."},
		{Key: paramLogLevel, Help: "backhaul log level (the tool's own vocabulary)."},
		{Key: paramSkipOptz, Help: "backhaul's skip_optz switch; leave empty unless you know you need it."},
	})
}
