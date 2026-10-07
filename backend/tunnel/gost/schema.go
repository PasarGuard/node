package gost

import "github.com/pasarguard/node/backend/tunnel"

// schema.go: the params surface the UI renders. Built beside config.go's
// toolParams/requiredParams — those tables are what Render enforces; this is
// how they reach the panel (glue-2).
func init() {
	tunnel.RegisterSchema(Tool, []tunnel.ParamField{
		{Key: tunnel.ParamListenPort, Help: "Local listen port. The node allocates a free one when empty; pin it only when the other side's peer must know it in advance."},
		{Key: ParamListenHost, Help: "Bind address for this side. Defaults to 127.0.0.1; 0.0.0.0 must be explicit."},
		{Key: ParamPeer, RequiredFor: []string{"relay:a", "reverse:b"}, Help: "Address this side dials: the other side's listen address (host:port)."},
		{Key: ParamTarget, RequiredFor: []string{"relay:a", "reverse:b"}, Help: "Destination the tunnel delivers to (host:port)."},
		{Key: ParamPublish, RequiredFor: []string{"reverse:b"}, Help: "reverse side b: the address gost opens on side a (host:port)."},
		{Key: ParamMetricsPort, Help: "Loopback Prometheus endpoint the stats reader uses. Allocated when empty."},
	})
}
