package chisel

import "github.com/pasarguard/node/backend/tunnel"

// schema.go: built beside config.go's requiredParams — Render and Preflight
// both use those; this is how they reach the panel (glue-2).
func init() {
	tunnel.RegisterSchema(Tool, []tunnel.ParamField{
		{Key: tunnel.ParamListenPort, Help: "Local listen port. The node allocates a free one when empty; pin it only when the other side's peer must know it in advance."},
		{Key: paramListenHost, Help: "Bind address for this side. Defaults to 127.0.0.1."},
		{Key: paramPeer, RequiredFor: []string{"relay:a", "reverse:b"}, Help: "The far side's listen address (host:port)."},
		{Key: paramTarget, RequiredFor: []string{"relay:b", "reverse:b"}, Help: "Destination the tunnel delivers to (host:port)."},
		{Key: paramPublishPort, RequiredFor: []string{"reverse:a", "reverse:b"}, Help: "reverse only: the port side a publishes for this tunnel."},
		{Key: paramPath, Help: "WebSocket path chisel handshakes on."},
		{Key: paramHeader, Help: "Extra handshake header, as Name: Value."},
	})
}
