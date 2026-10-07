package controller

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/pasarguard/node/backend"
	"github.com/pasarguard/node/backend/tunnel"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
)

func roleConfig(t *testing.T, role common.NodeRole) *config.Config {
	t.Helper()
	cfg := config.NewTestConfig(t.TempDir(), uuid.New())
	cfg.Role = role
	return cfg
}

// TestTunnelRoleRefusesStart: a tunnel node refuses Start(Backend) with a
// users payload — and, root-cause, with any payload: it runs no proxy core
// (CONTRACT §1.7). The refusal is asserted, not the mere absence of a core.
func TestTunnelRoleRefusesStart(t *testing.T) {
	c := New(roleConfig(t, common.NodeRole_NODE_ROLE_TUNNEL))

	withUsers := &common.Backend{
		Type:   common.BackendType_XRAY,
		Config: "{}",
		Users:  []*common.User{{Email: "someone@example.com"}},
	}
	err := c.StartOrAttach(context.Background(), withUsers)
	if !errors.Is(err, tunnel.ErrRoleRefused) {
		t.Fatalf("Start with users on a tunnel node: want ErrRoleRefused, got %v", err)
	}

	noUsers := &common.Backend{Type: common.BackendType_XRAY, Config: "{}"}
	err = c.StartOrAttach(context.Background(), noUsers)
	if !errors.Is(err, tunnel.ErrRoleRefused) {
		t.Fatalf("Start without users on a tunnel node: want ErrRoleRefused, got %v", err)
	}
	if c.Backend() != nil {
		t.Fatal("a tunnel node must not have a running core after a refused Start")
	}
}

// TestTunnelRoleRefusesUserSync: SyncUsers/SyncUser fan out through
// EachBackend. On a tunnel node the answer is the role refusal — an explicit
// error, stated and asserted, not a silent no-op.
func TestTunnelRoleRefusesUserSync(t *testing.T) {
	c := New(roleConfig(t, common.NodeRole_NODE_ROLE_TUNNEL))

	err := c.EachBackend(func(uint64, backend.Backend) error { return nil })
	if !errors.Is(err, tunnel.ErrRoleRefused) {
		t.Fatalf("user sync on a tunnel node: want ErrRoleRefused, got %v", err)
	}
}

// TestProxyRoleUnchanged is the control: on a proxy node nothing about Start
// or user sync is altered by the role work — an unknown backend type still
// fails as an unknown backend type, never as the role refusal.
func TestProxyRoleUnchanged(t *testing.T) {
	c := New(roleConfig(t, common.NodeRole_NODE_ROLE_PROXY))

	err := c.StartOrAttach(context.Background(), &common.Backend{
		Type:   common.BackendType(42),
		Config: "{}",
	})
	if errors.Is(err, tunnel.ErrRoleRefused) {
		t.Fatalf("proxy node must not get the tunnel refusal, got %v", err)
	}
	if err == nil {
		t.Fatal("expected an unknown-backend error")
	}

	err = c.EachBackend(func(uint64, backend.Backend) error { return nil })
	if errors.Is(err, tunnel.ErrRoleRefused) {
		t.Fatalf("proxy node user sync must not get the tunnel refusal, got %v", err)
	}
}

// TestParseRole covers NODE_ROLE parsing, including the unknown value that
// must fall back to proxy with a warning rather than half-configuring a node.
func TestParseRole(t *testing.T) {
	cases := map[string]common.NodeRole{
		"":         common.NodeRole_NODE_ROLE_PROXY,
		"proxy":    common.NodeRole_NODE_ROLE_PROXY,
		"PROXY":    common.NodeRole_NODE_ROLE_PROXY,
		"tunnel":   common.NodeRole_NODE_ROLE_TUNNEL,
		" TUNNEL ": common.NodeRole_NODE_ROLE_TUNNEL,
		"banana":   common.NodeRole_NODE_ROLE_PROXY,
	}
	for in, want := range cases {
		if got := config.ParseRole(in); got != want {
			t.Fatalf("ParseRole(%q) = %v, want %v", in, got, want)
		}
	}
}
