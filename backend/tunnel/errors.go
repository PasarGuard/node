package tunnel

import "errors"

// Sentinel errors. Callers — the RPC layer, the testkit, a tool's own Start —
// match on these with errors.Is; messages may change, these may not.
var (
	// ErrInvalidSpec is a Spec the framework itself rejects (empty or unsafe
	// tunnel_id, a mode that is neither relay nor reverse, no tool).
	ErrInvalidSpec = errors.New("tunnel: invalid spec")
	// ErrUnknownSide is a TunnelSpec.side that is not "a" or "b".
	ErrUnknownSide = errors.New("tunnel: unknown side")
	// ErrUnknownTool means no adapter registered that tool name.
	ErrUnknownTool = errors.New("tunnel: unknown tool")
	// ErrModeUnsupported means the adapter refuses this mode. A tool must
	// refuse a mode whose loopback test it never passed, not fall through to
	// its default (CONTRACT §2.0).
	ErrModeUnsupported = errors.New("tunnel: mode not supported")
	// ErrSecretUnresolved means the spec declares secret_names whose values
	// were never resolved. Start refuses rather than running unauthenticated.
	ErrSecretUnresolved = errors.New("tunnel: secret not resolved")
	// ErrBinaryNotFound means no bundle and no pin-matching executable exists.
	ErrBinaryNotFound = errors.New("tunnel: binary not found")
	// ErrBinaryMismatch means the candidate executable's sha256 is not the
	// pin's. Start refuses it (CONTRACT §2.1 install rule).
	ErrBinaryMismatch = errors.New("tunnel: binary sha256 does not match the pin")
	// ErrNotRunning is a Stop or a status query for a tunnel this node is not
	// running.
	ErrNotRunning = errors.New("tunnel: not running")
	// ErrRoleRefused is what a tunnel-role node answers for Start/SyncUsers:
	// NODE_ROLE_TUNNEL runs no proxy core and holds no users (CONTRACT §1.7).
	ErrRoleRefused = errors.New("node role is tunnel: refused (no proxy cores, no users, CONTRACT §1.7)")
)
