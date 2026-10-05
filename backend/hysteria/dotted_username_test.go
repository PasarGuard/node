package hysteria

// A real hysteria2 core (pinned v2.13.0) refuses to START when a username
// contains a dot, and every user the panel gives this core gets its email as the
// hysteria username (backend/hysteria/config.go:164, credentialFor).
//
// The panel's own validator ALLOWS dots — `^[a-zA-Z0-9-_@.]+$`
// (panel/app/models/validators.py:201) — and an email is the canonical username,
// so this is reachable from ordinary input rather than from an exotic one.
//
// Upstream decodes auth.userpass with a path-aware decoder that treats `.` as a
// separator, so the key `a.b` arrives as a nested map instead of a string:
//
//	'auth.userpass[a.b]' expected type 'string', got unconvertible type 'map[string]interface {}'
//
// Reproduced directly against the pinned binary with no node code involved
// (2026-10-05): `nodot`, `dot@example` and `dash-user` all start; `a.b` and
// `live-hysteria@example.invalid` both die in config parsing.
//
// This test is RED against the current tree and is filed as a failure, not fixed
// here: production code belongs to the owning agent (my scope is tests only). It
// passes once the core maps a hysteria-internal username that is guaranteed
// dot-free, and keeps the panel-facing identity intact on the read-back path.

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
)

// TestHysteriaDottedUsernameRefusesStartup is the failing reproduction.
//
// The assertion is the one that matters operationally: the core must come UP.
// If upstream's decoder is fed a dotted key, it exits during startup with a
// config-parse FATAL and `New` returns an error, so this test fails here and
// will pass only once the username is made safe for the decoder.
func TestHysteriaDottedUsernameRefusesStartup(t *testing.T) {
	exe := requirePinnedBinary(t)

	apiPort := freePort(t)
	serverPort := freeUDPPort(t)
	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir)

	// The username the panel would send for a user called "user@example.com".
	const email = "user@example.com"
	const password = "correct-horse-battery"

	// The user goes to New, not to a pre-sync: New calls syncUsers(users) itself
	// (hysteria.go:107), so a pre-rendered user list is overwritten by whatever
	// New is handed — passing nil there renders an empty userpass, and hysteria
	// refuses to start on an empty map for an unrelated reason. That would make
	// this test pass for the wrong cause.
	users := []*common.User{{
		Email:    email,
		Proxies:  &common.Proxy{Hysteria: &common.Hysteria{Auth: password}},
		Inbounds: []string{},
	}}

	cfg, err := NewConfig(serverConfigJSON("127.0.0.1:"+strconv.Itoa(serverPort), certPath, keyPath, nil), nil)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}

	nodeCfg := config.NewTestConfig(t.TempDir(), uuid.New())
	t.Setenv(hysteriaExecutablePathEnv, exe)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	h, err := New(ctx, cfg, users, apiPort, nodeCfg)
	if err != nil {
		t.Fatalf("DEFECT: a hysteria core given the ordinary panel username %q refused to start: %v\n"+
			"upstream decodes auth.userpass with a path-aware decoder, so a '.' in the key makes it a "+
			"nested map. The panel allows dots in usernames (validators.py:201) and uses the email as "+
			"this core's username, so every email-named user breaks this core.",
			email, err)
	}
	defer h.Shutdown()

	if !h.Started() {
		t.Fatalf("DEFECT: the core reported not started for username %q", email)
	}
	t.Logf("core started with the dotted username %q", email)
}

// TestHysteriaDotFreeUsernameStarts is the control for the test above: the same
// shape with a dot-free username must come up. Without it, the failing test could
// be passing for a reason that has nothing to do with the dot.
func TestHysteriaDotFreeUsernameStarts(t *testing.T) {
	exe := requirePinnedBinary(t)

	apiPort := freePort(t)
	serverPort := freeUDPPort(t)
	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir)

	const username = "user_at_example"
	h := newTestBackend(t, exe,
		serverConfigJSON("127.0.0.1:"+strconv.Itoa(serverPort), certPath, keyPath, nil),
		[]*common.User{{
			Email:    username,
			Proxies:  &common.Proxy{Hysteria: &common.Hysteria{Auth: "correct-horse-battery"}},
			Inbounds: []string{},
		}}, apiPort)

	if !h.Started() {
		t.Fatalf("the dot-free username %q did not start either, so the dotted test proves nothing", username)
	}
	t.Logf("control OK: the dot-free username %q starts", username)
}

// TestHysteriaUsernameDecoderRules pins the upstream rule this defect rests on,
// so a future hysteria upgrade that changes it is noticed here rather than in
// production. It is a pure config-render check and needs no binary.
func TestHysteriaUsernameDecoderRules(t *testing.T) {
	cases := []struct {
		name     string
		username string
	}{
		{"no dot", "nodot"},
		{"at sign", "dot@example"},
		{"dash", "dash-user"},
		{"underscore", "under_score"},
		{"one dot", "a.b"},
		{"email", "user@example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := NewConfig(`{"auth": {"type": "userpass", "userpass": {}}}`, nil)
			if err != nil {
				t.Fatalf("NewConfig: %v", err)
			}
			cfg.syncUsers([]*common.User{{
				Email:    tc.username,
				Proxies:  &common.Proxy{Hysteria: &common.Hysteria{Auth: "pw"}},
				Inbounds: []string{},
			}})
			out, err := cfg.ToBytes()
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			t.Logf("%-28s -> %s", tc.username, strings.TrimSpace(string(out)))
		})
	}
}
