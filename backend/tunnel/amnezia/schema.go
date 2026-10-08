package amnezia

import "github.com/pasarguard/node/backend/tunnel"

// schema.go: the params surface the UI renders, built beside config.go's
// tables — those tables are what Render enforces; this is how they reach the
// panel (glue-2). The row holds one params dict for both sides (CONTRACT §2.4
// row encoding), so every site and obfuscation key exists twice, prefixed by
// side.
func init() {
	tunnel.RegisterSchema(Tool, []tunnel.ParamField{
		{Key: tunnel.ParamListenPort, Help: "UDP port this side's amnezia interface listens on. The node allocates a free one when empty; pin it only when the other side's peer_endpoint must know it in advance."},
		{Key: "a_address", RequiredFor: []string{"relay:a"}, Help: "Side A's tunnel CIDR (e.g. 10.67.0.1/24)."},
		{Key: "a_lan_cidr", RequiredFor: []string{"relay:a"}, Help: "LAN side A serves and advertises (e.g. 192.168.10.0/24)."},
		{Key: "a_peer_endpoint", RequiredFor: []string{"relay:a"}, Help: "Side A's view of side B: underlay host:port (port = side B's listen_port)."},
		{Key: "a_peer_public_key", RequiredFor: []string{"relay:a"}, Help: "Side B's amnezia public key (not secret)."},
		{Key: "a_peer_allowed_cidrs", RequiredFor: []string{"relay:a"}, Help: "CIDRs side A routes into the tunnel: side B's tunnel /32 plus side B's LAN (e.g. 10.67.0.2/32,192.168.20.0/24)."},
		{Key: "a_netns", Help: "Network namespace side A's interface lives in; empty = the node process's own namespace."},
		{Key: "a_jc", Help: "Obfuscation: junk packet count sent per handshake (e.g. 4). Empty keeps the daemon default; both sides must agree."},
		{Key: "a_jmin", Help: "Obfuscation: minimum junk packet size in bytes. Empty keeps the daemon default; both sides must agree."},
		{Key: "a_jmax", Help: "Obfuscation: maximum junk packet size in bytes. Empty keeps the daemon default; both sides must agree."},
		{Key: "a_s1", Help: "Obfuscation: init packet padding. Empty keeps the daemon default; both sides must agree."},
		{Key: "a_s2", Help: "Obfuscation: response packet padding. Empty keeps the daemon default; both sides must agree."},
		{Key: "a_h1", Help: "Obfuscation: init packet header magic, a number or a range like 100-255. Both sides must agree."},
		{Key: "a_h2", Help: "Obfuscation: response packet header magic, a number or a range like 100-255. Both sides must agree."},
		{Key: "a_h3", Help: "Obfuscation: cookie packet header magic, a number or a range like 100-255. Both sides must agree."},
		{Key: "a_h4", Help: "Obfuscation: transport packet header magic, a number or a range like 100-255. Both sides must agree."},
		{Key: "b_address", RequiredFor: []string{"relay:b"}, Help: "Side B's tunnel CIDR (e.g. 10.67.0.2/24)."},
		{Key: "b_lan_cidr", RequiredFor: []string{"relay:b"}, Help: "LAN side B serves and advertises (e.g. 192.168.20.0/24)."},
		{Key: "b_peer_endpoint", RequiredFor: []string{"relay:b"}, Help: "Side B's view of side A: underlay host:port (port = side A's listen_port)."},
		{Key: "b_peer_public_key", RequiredFor: []string{"relay:b"}, Help: "Side A's amnezia public key (not secret)."},
		{Key: "b_peer_allowed_cidrs", RequiredFor: []string{"relay:b"}, Help: "CIDRs side B routes into the tunnel: side A's tunnel /32 plus side A's LAN (e.g. 10.67.0.1/32,192.168.10.0/24)."},
		{Key: "b_netns", Help: "Network namespace side B's interface lives in; empty = the node process's own namespace."},
		{Key: "b_jc", Help: "Obfuscation: junk packet count sent per handshake (e.g. 4). Empty keeps the daemon default; both sides must agree."},
		{Key: "b_jmin", Help: "Obfuscation: minimum junk packet size in bytes. Empty keeps the daemon default; both sides must agree."},
		{Key: "b_jmax", Help: "Obfuscation: maximum junk packet size in bytes. Empty keeps the daemon default; both sides must agree."},
		{Key: "b_s1", Help: "Obfuscation: init packet padding. Empty keeps the daemon default; both sides must agree."},
		{Key: "b_s2", Help: "Obfuscation: response packet padding. Empty keeps the daemon default; both sides must agree."},
		{Key: "b_h1", Help: "Obfuscation: init packet header magic, a number or a range like 100-255. Both sides must agree."},
		{Key: "b_h2", Help: "Obfuscation: response packet header magic, a number or a range like 100-255. Both sides must agree."},
		{Key: "b_h3", Help: "Obfuscation: cookie packet header magic, a number or a range like 100-255. Both sides must agree."},
		{Key: "b_h4", Help: "Obfuscation: transport packet header magic, a number or a range like 100-255. Both sides must agree."},
	})
}
