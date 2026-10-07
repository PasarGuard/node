package frp

import "github.com/pasarguard/node/backend/tunnel"

// schema.go: built beside config.go's resolve() — it is the only place frp
// params are read; this is how they reach the panel (glue-2).
func init() {
	tunnel.RegisterSchema(Tool, []tunnel.ParamField{
		// frp's Render requires listen_port on BOTH sides (bindPort/proxyPort
		// derive as port+1/port+2), and the Manager injects it at Start, so
		// the UI shows it optional like everywhere else.
		{Key: tunnel.ParamListenPort, Help: "Local listen port. The node allocates a free one when empty; pin it only when the other side's peer must know it in advance."},
		{Key: paramListenHost, Help: "side a: bind address for the ingress. Defaults to 127.0.0.1."},
		{Key: paramServerAddr, RequiredFor: []string{"relay:b", "reverse:b"}, Help: "side b: bare host of frps; the port is listen_port+1."},
		{Key: paramLocalIP, Help: "side b: the real destination host. Defaults to 127.0.0.1."},
		{Key: paramLocalPort, RequiredFor: []string{"relay:b", "reverse:b"}, Help: "side b: the real destination port."},
		{Key: paramProxyName, Help: "frp proxy name; defaults to pg-<tunnel_id>."},
		{Key: paramAdminPort, Help: "frp webServer port (0 = disabled); the node offers an allocated port when 0."},
		{Key: paramType, Help: "frp proxy type; only tcp has a passing loopback test."},
	})
}
