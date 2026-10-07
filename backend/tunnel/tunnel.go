// Package tunnel is the adapter seam every Phase 3 tunnel tool plugs into
// (CONTRACT.md §2.1). Nothing in this file knows a tool's name, flags or
// transport: a tool lives in its own subpackage, registers itself from an
// init(), and the six 3.2a agents code against exactly these signatures.
//
// Frozen: after batch 3.1 the exported signatures here must not change — a
// change costs six merge conflicts.
package tunnel

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Side is which end of a tunnel a Spec configures (CONTRACT §2.1).
type Side int

const (
	// SideA is the reachable ingress: it listens (relay), and the service is
	// published here (reverse).
	SideA Side = iota
	// SideB is the far side: it dials the destination (relay), or sits behind
	// NAT and dials out (reverse).
	SideB
)

// String is the wire form used by TunnelSpec.side: "a" / "b".
func (s Side) String() string {
	if s == SideB {
		return "b"
	}
	return "a"
}

// ParseSide accepts the wire form ("a", "b", case-insensitive) and the empty
// string, which means SideA — the panel's default for the ingress side.
func ParseSide(v string) (Side, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "a":
		return SideA, nil
	case "b":
		return SideB, nil
	}
	return SideA, fmt.Errorf("%w: %q (want \"a\" or \"b\")", ErrUnknownSide, v)
}

// Modes (CONTRACT §2.0). Every tunnel carries one; an empty value means the
// tool's default, which must be stated in that tool's docs and must be one of
// the modes the tool's own loopback test passed.
const (
	ModeRelay   = "relay"
	ModeReverse = "reverse"
)

// ValidMode reports whether v is one of the two values the contract allows.
func ValidMode(v string) bool {
	return v == "" || v == ModeRelay || v == ModeReverse
}

// Spec describes one side of one tunnel (CONTRACT §2.1).
//
// Params holds tool knobs and never secret values. Secrets holds resolved
// values keyed by the secret's name — the wire carries names only
// (TunnelSpec.secret_names); ResolveSecrets fills this from the environment
// just before Start, and nothing writes it to disk.
type Spec struct {
	TunnelID    string
	Tool        string
	ToolVersion string
	Side        Side
	Mode        string // "relay" | "reverse"; "" = the tool's default
	Params      map[string]string
	Secrets     map[string]string
	Enabled     bool
}

// Framework-reserved Params keys. A tool may read them; nothing else may
// invent a key in this namespace.
const (
	// ParamConfigDir is the directory this side's rendered config belongs in.
	// The Manager sets it (creating the directory) just before Start, so a tool
	// that needs a file on disk writes it there and nowhere else.
	ParamConfigDir = "pg_config_dir"
	// ParamBinaryPath is the pin-verified executable the Manager resolved for a
	// tool that has a pin. Tools with a pin read it instead of resolving again.
	ParamBinaryPath = "pg_binary_path"
)

// ParamListenPort is the one Params key the CALLER may set to pin the listen
// port: a panel that has to dial this side (it writes the other side's
// `peer = ip:port`) must choose the port itself, because TunnelStatus carries
// no port field to read one back from. When it is absent the node allocates a
// free pair as it does everywhere else (CONTRACT §1.4).
const ParamListenPort = "listen_port"

// Validate checks the fields the framework owns. A tool that needs more (a
// required param, say) validates that itself, in Render and in Start.
func (s Spec) Validate() error {
	switch {
	case s.TunnelID == "":
		return fmt.Errorf("%w: tunnel_id is empty", ErrInvalidSpec)
	case !validTunnelID(s.TunnelID):
		return fmt.Errorf("%w: tunnel_id %q must match [A-Za-z0-9._-]{1,128}", ErrInvalidSpec, s.TunnelID)
	case s.Tool == "":
		return fmt.Errorf("%w: tool is empty", ErrInvalidSpec)
	case !ValidMode(s.Mode):
		return fmt.Errorf("%w: mode %q is not relay|reverse (CONTRACT §2.0)", ErrInvalidSpec, s.Mode)
	}
	return nil
}

// validTunnelID is the filename/registry charset. The id arrives over RPC, so
// it must never be able to climb out of the persistence directory.
func validTunnelID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}

// Clone returns a copy whose maps are copies too, so a Manager can inject
// framework keys without mutating the caller's Spec.
func (s Spec) Clone() Spec {
	out := s
	out.Params = cloneMap(s.Params)
	out.Secrets = cloneMap(s.Secrets)
	return out
}

func cloneMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// Ports are the ports one side of a tunnel owns. They are handed out per side
// and held until that side stops (CONTRACT §1.4's rule, applied per tunnel).
//
// Control is always Listen+1 and is reserved even when the tool never binds
// it: a tool that derives a control port as listen+1 must not collide the way
// sing-box's quota endpoint once could.
type Ports struct {
	Listen  int
	Control int
	// Extra holds further named ports a tool asked for at allocation time.
	// Optional; nil for most tools.
	Extra map[string]int
}

// Addr renders the listen address for a host, or 127.0.0.1 when host is empty.
func (p Ports) Addr(host string) string {
	if host == "" {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("%s:%d", host, p.Listen)
}

// ExtraPort returns a named extra port.
func (p Ports) ExtraPort(name string) (int, bool) {
	v, ok := p.Extra[name]
	return v, ok
}

// Bytes is a tunnel's aggregate counters (CONTRACT §3.5). There is no per-user
// breakdown for a tunnel, ever: a tunnel node holds no user to attribute to.
type Bytes struct {
	Up   uint64
	Down uint64
}

// Handle is one running side of one tunnel.
type Handle interface {
	Started() bool
	Version() string
	Logs() <-chan string
	Restart() error
	Shutdown()
	// Stats returns aggregate up/down for the whole tunnel. Never per-user.
	Stats(context.Context) (Bytes, error)
}

// Adapter is what a tool package implements and registers (CONTRACT §2.1).
//
// Fixed obligations: Render is pure and deterministic (same Spec ⇒
// byte-identical config); Start owns its ports and its log ring; Preflight
// returns an empty slice when the host can do what the tool needs.
type Adapter interface {
	// Render produces the config for one side. Pure: no I/O, no process.
	Render(spec Spec) (config string, err error)
	// Start launches the process (or the in-process relay) for one side.
	Start(ctx context.Context, spec Spec, ports Ports) (Handle, error)
	// Preflight reports what this host cannot do. Empty means "ready".
	Preflight(ctx context.Context, spec Spec) []Problem
}

// SideLabel is the wire/persistence form of a side.
func SideLabel(s Side) string { return s.String() }

// SortedParams returns Params' keys in order, so every Render in this package
// (and every test that compares two renders) walks the map the same way.
func SortedParams(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
