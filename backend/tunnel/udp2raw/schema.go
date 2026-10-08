package udp2raw

import "github.com/pasarguard/node/backend/tunnel"

// schema.go: the params surface the UI renders. Built beside config.go's
// toolParams/requiredParams — those tables are what Render enforces; this is
// how they reach the panel (glue-2).
func init() {
	tunnel.RegisterSchema(Tool, []tunnel.ParamField{
		{Key: tunnel.ParamListenPort, Help: "Local port for this side: the raw-facing listener on side b, the UDP listener applications send to on side a. The node allocates a free one when empty."},
		{Key: ParamListenHost, Help: "Bind address for this side's port. Defaults to 0.0.0.0; 127.0.0.1 restricts the tunnel to this host."},
		{Key: ParamPeer, RequiredFor: []string{"relay:a"}, Help: "Side a only: side b's raw-facing address (host:port) — its listen_host:listen_port."},
		{Key: ParamTarget, RequiredFor: []string{"relay:b"}, Help: "Side b only: the UDP service the tunnel delivers to (host:port)."},
		{Key: ParamRawMode, Help: "udp2raw faking mode, identical on both ends. Pinned build: faketcp (default) | udp | icmp | easy-faketcp."},
		{Key: ParamCipherMode, Help: "Cipher, identical on both ends. aes128cbc (default) | aes128cfb | xor | none."},
		{Key: ParamAuthMode, Help: "Packet auth, identical on both ends. md5 (default) | hmac_sha1 | crc32 | simple | none."},
		{Key: ParamAutoRule, Help: "Let udp2raw add and remove its own iptables rules (true/false). Default: true for raw_mode=faketcp and icmp, false for udp and easy-faketcp."},
		{Key: ParamANetns, Help: "Side a only: existing network namespace to run this side's udp2raw in (ip netns add <name>). Empty = the node process's own namespace. The namespace's rules and packets stay inside it."},
		{Key: ParamBNetns, Help: "Side b only: existing network namespace to run this side's udp2raw in. Empty = the node process's own namespace."},
	})
}
