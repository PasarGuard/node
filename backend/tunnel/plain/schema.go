package plain

import "github.com/pasarguard/node/backend/tunnel"

// schema.go: built beside plain.go's own side checks — Render enforces them;
// this is how they reach the panel (glue-2). plain is the reference relay and
// refuses reverse (TestStartRefusesReverse).
func init() {
	tunnel.RegisterSchema(Tool, []tunnel.ParamField{
		{Key: tunnel.ParamListenPort, Help: "Local listen port. The node allocates a free one when empty; pin it only when the other side's peer must know it in advance."},
		{Key: paramListenHost, Help: "Bind address for this side. Defaults to 127.0.0.1."},
		{Key: paramPeer, RequiredFor: []string{"relay:a"}, Help: "side a: side b's listen address (host:port)."},
		{Key: paramTarget, RequiredFor: []string{"relay:b"}, Help: "side b: the destination to deliver to (host:port)."},
	})
}
