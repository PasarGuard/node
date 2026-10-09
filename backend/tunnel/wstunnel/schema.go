package wstunnel

import "github.com/pasarguard/node/backend/tunnel"

// schema.go: built beside config.go's needPeer/needTarget and requiredHostPort
// — Render enforces those; this is how they reach the panel (glue-2).
func init() {
	tunnel.RegisterSchema(Tool, []tunnel.ParamField{
		{Key: tunnel.ParamListenPort, Help: "Local listen port. The node allocates a free one when empty; pin it only when the other side's peer must know it in advance."},
		{Key: paramListenHost, Help: "Bind address for this side. Defaults to 127.0.0.1."},
		{Key: paramPeer, RequiredFor: []string{"relay:a", "reverse:b"}, Help: "Address this side dials (host:port)."},
		{Key: paramTarget, RequiredFor: []string{"relay:a", "reverse:b"}, Help: "Destination the tunnel delivers to (host:port)."},
		{Key: paramRestrictTo, Help: "relay side b only: comma-separated host:port allowlist for where clients may be relayed. Refused in any other shape."},
		{Key: paramBRestrictTo, Help: "relay side b only: same destination allowlist as restrict_to, under the side prefix so one row params map can carry it — read (and enforced) by relay side b; side a ignores it."},
		{Key: paramTransport, Help: "ws or wss."},
		{Key: paramTLSCert, Help: "PEM certificate path for wss (pair with tls_key)."},
		{Key: paramTLSKey, Help: "PEM private key path for wss (pair with tls_cert)."},
	})
}
