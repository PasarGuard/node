package rathole

import "github.com/pasarguard/node/backend/tunnel"

// schema.go: built beside config.go's sideParams — Render refuses a key on
// the wrong side there; this is how the keys reach the panel (glue-2).
// rathole implements only CONTRACT 2.0's reverse mode.
func init() {
	tunnel.RegisterSchema(Tool, []tunnel.ParamField{
		{Key: tunnel.ParamListenPort, Help: "Local listen port. The node allocates a free one when empty; pin it only when the other side's peer must know it in advance."},
		{Key: paramListenHost, Help: "Both sides: the address this side's counting tap binds. Defaults to 127.0.0.1."},
		{Key: paramControlHost, Help: "side a only: where rathole's server accepts clients (host:port)."},
		{Key: paramRemoteAddr, RequiredFor: []string{"reverse:b"}, Help: "side b only: the server's control address (host:port)."},
		{Key: paramTarget, RequiredFor: []string{"reverse:b"}, Help: "side b only: where tunneled bytes are delivered (host:port)."},
		{Key: paramService, Help: "rathole service name; must match on both ends. Defaults to tunnel."},
	})
}
