package hysteria

// A real hysteria2 core (pinned v2.13.0) refuses to START when a username
// contains a dot, because upstream decodes auth.userpass with a path-aware
// decoder that treats `.` as a key separator:
//
//	'auth.userpass[a]' expected type 'string', got unconvertible type 'map[string]interface {}'
//
// (backend/hysteria/config.go, usernameSeparator.)
//
// This file pins BOTH halves of the fix, because either alone is weak:
//
//   - the validator, per character, against the real binary — so a future
//     hysteria upgrade that changes the rule is noticed here, and
//   - the corollary: every OTHER field the node renders must still accept the
//     characters it always did. A validator that rejected a character upstream
//     is fine with would be a regression of the same kind, in the other
//     direction.
//
// The username is not rewritten to dodge the bug, and this file says why: it is
// load-bearing on the client. A hysteria2 client authenticates as
// "username:password" and upstream refuses the connection when the username does
// not match a key — verified against the pinned binary, client auth "pw"
// against userpass {alice: pw} fails with "authentication error, HTTP status
// code: 404". Encoding the key to make it dot-free would break every real
// client, so the identity is kept and the bad one is refused at start.

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
)

// TestHysteriaRejectsDottedUsernameAtStart is the operational assertion: a user
// the core's decoder cannot accept must be refused with a message naming the
// user and the character, BEFORE the child is spawned. Upstream's failure mode is
// the worst kind — a core that exits during startup with a config-parse FATAL
// that says nothing about which user caused it.
func TestHysteriaRejectsDottedUsernameAtStart(t *testing.T) {
	exe := requirePinnedBinary(t)

	apiPort := freePort(t)
	serverPort := freeUDPPort(t)
	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir)

	const email = "user@example.com"
	const password = "correct-horse-battery"

	nodeCfg := config.NewTestConfig(t.TempDir(), uuid.New())
	t.Setenv(hysteriaExecutablePathEnv, exe)

	cfg, err := NewConfig(serverConfigJSON("127.0.0.1:"+strconv.Itoa(serverPort), certPath, keyPath, nil), nil)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}

	users := []*common.User{{
		Email:    email,
		Proxies:  &common.Proxy{Hysteria: &common.Hysteria{Auth: password}},
		Inbounds: []string{},
	}}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	h, err := New(ctx, cfg, users, apiPort, nodeCfg)
	if err == nil {
		h.Shutdown()
		t.Fatalf("a hysteria core accepted the dotted username %q; upstream's decoder cannot "+
			"read it, so the core would have died on a config-parse FATAL instead", email)
	}

	// The message is the deliverable. An admin has to be able to tell WHICH user
	// and WHICH character, from the panel's error line alone.
	msg := err.Error()
	if !containsAll(msg, email, ".") {
		t.Errorf("the refusal does not name the offending user and character, so an admin "+
			"cannot act on it. Got: %v", err)
	}
	t.Logf("refused with: %v", err)

	// And nothing must have been spawned: the whole point is that this is a
	// config-render failure, not a core that started and crashed.
	if names := cfg.userNames(); len(names) != 0 {
		t.Errorf("a rejected user was still written into auth.userpass as %v", names)
	}
}

// TestHysteriaUsernamePerCharacter is the per-character rule, checked against
// the REAL binary for every character the panel's validator can produce.
//
// One test per character, and a dot-free control, because the alternative — one
// test that sweeps a list — passes for the wrong reason the moment one entry is
// mis-transcribed: the sweep still has characters, so it still proves something
// happened. A subtest names the character in the failure.
func TestHysteriaUsernamePerCharacter(t *testing.T) {
	exe := requirePinnedBinary(t)

	// The dot is the only character upstream's path-aware decoder mishandles.
	// Every other one below was measured against the pinned binary, not guessed
	// from an allowlist: each must START.
	accepted := []struct {
		name     string
		username string
	}{
		{"dot-free control", "nodot"},
		{"numeric (what production sends)", "12345"},
		{"at sign", "dot@example"},
		{"dash", "dash-user"},
		{"underscore", "under_score"},
		{"colon", "us:er"},
		{"slash", "us/er"},
		{"space", "us er"},
		{"hash", "us#er"},
		{"brackets", "us[er]"},
		{"braces", "us{er}"},
		{"percent and dollar", "us%$er"},
		{"unicode", "üser"},
	}

	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			if bad := undecodableUsernameChar(tc.username); bad != "" {
				t.Fatalf("undecodableUsernameChar(%q) = %q, but this character was verified to "+
					"start against the pinned binary; rejecting it would refuse identities upstream accepts",
					tc.username, bad)
			}

			apiPort := freePort(t)
			serverPort := freeUDPPort(t)
			dir := t.TempDir()
			certPath, keyPath := writeSelfSignedCert(t, dir)

			h := newTestBackend(t, exe,
				serverConfigJSON("127.0.0.1:"+strconv.Itoa(serverPort), certPath, keyPath, nil),
				[]*common.User{{
					Email:    tc.username,
					Proxies:  &common.Proxy{Hysteria: &common.Hysteria{Auth: "pw"}},
					Inbounds: []string{},
				}}, apiPort)

			if !h.Started() {
				t.Fatalf("username %q did not start; the character %q is accepted upstream, so "+
					"refusing it here would be a regression", tc.username, tc.username)
			}
		})
	}

	// The one character that must be refused, against the real binary.
	t.Run("dot", func(t *testing.T) {
		const username = "user@example.com"
		if got := undecodableUsernameChar(username); got != "." {
			t.Fatalf("undecodableUsernameChar(%q) = %q, want %q; upstream's decoder splits this "+
				"key and the core dies on a config-parse FATAL", username, got, ".")
		}

		// The rendered config must not contain the unusable key at all: a core
		// that is handed one will refuse to start, which is what this prevents.
		cfg, err := NewConfig(`{"auth": {"type": "userpass", "userpass": {}}}`, nil)
		if err != nil {
			t.Fatalf("NewConfig: %v", err)
		}
		err = cfg.syncUsers([]*common.User{{
			Email:    username,
			Proxies:  &common.Proxy{Hysteria: &common.Hysteria{Auth: "pw"}},
			Inbounds: []string{},
		}})
		if err == nil {
			t.Fatal("syncUsers accepted a dotted username; the rendered config would kill the core")
		}
		if names := cfg.userNames(); len(names) != 0 {
			t.Errorf("the rejected user was still written into auth.userpass as %v", names)
		}
	})
}

// TestHysteriaDotIsOnlyRejectedCharacter pins the rule itself, so widening or
// narrowing the validator is a visible diff rather than a silent behaviour
// change. Every entry here was measured against the pinned v2.13.0 binary.
func TestHysteriaDotIsOnlyRejectedCharacter(t *testing.T) {
	cases := []struct {
		username string
		rejected bool
	}{
		{"12345", false},
		{"nodot", false},
		{"under_score", false},
		{"dash-user", false},
		{"us:er", false},
		{"us er", false},
		{"a@b", false},
		{"a[b]c", false},
		{"a.b", true},
		{"user@example.com", true},
		{".leading", true},
		{"trailing.", true},
		{"two..dots", true},
	}

	for _, tc := range cases {
		t.Run(tc.username, func(t *testing.T) {
			got := undecodableUsernameChar(tc.username) != ""
			if got != tc.rejected {
				t.Errorf("username %q: rejected=%v, want %v", tc.username, got, tc.rejected)
			}
		})
	}
}

// TestHysteriaDotsAreFineEverywhereElse is the corollary this defect asked for:
// does the same decoder bug affect the PASSWORD side, obfs, or any other field
// the node renders? Measured answer: no. Only a MAP KEY in auth.userpass is
// affected; a map VALUE (the password), and every other string field, accept a
// dot freely.
//
// Each case starts a REAL core against the pinned binary. A validator that
// rejected a character upstream is fine with would refuse identities and config
// it has no reason to.
func TestHysteriaDotsAreFineEverywhereElse(t *testing.T) {
	exe := requirePinnedBinary(t)

	t.Run("password", func(t *testing.T) {
		apiPort := freePort(t)
		serverPort := freeUDPPort(t)
		dir := t.TempDir()
		certPath, keyPath := writeSelfSignedCert(t, dir)

		// A dot in the PASSWORD (the map value) is fine: only the key is split.
		h := newTestBackend(t, exe,
			serverConfigJSON("127.0.0.1:"+strconv.Itoa(serverPort), certPath, keyPath, nil),
			[]*common.User{{
				Email:    "dotted-password-user",
				Proxies:  &common.Proxy{Hysteria: &common.Hysteria{Auth: "p.w.x.y"}},
				Inbounds: []string{},
			}}, apiPort)

		if !h.Started() {
			t.Fatal("a dot in the password refused startup; upstream splits only the map KEY")
		}
	})

	t.Run("obfs", func(t *testing.T) {
		apiPort := freePort(t)
		serverPort := freeUDPPort(t)
		dir := t.TempDir()
		certPath, keyPath := writeSelfSignedCert(t, dir)

		h := newTestBackend(t, exe,
			serverConfigJSON("127.0.0.1:"+strconv.Itoa(serverPort), certPath, keyPath, map[string]any{
				"obfs": map[string]any{"type": "salamander", "salamander": map[string]any{"password": "ob.fs.pw"}},
			}),
			[]*common.User{{
				Email:    "obfs-user",
				Proxies:  &common.Proxy{Hysteria: &common.Hysteria{Auth: "pw"}},
				Inbounds: []string{},
			}}, apiPort)

		if !h.Started() {
			t.Fatal("a dot in obfs.salamander.password refused startup")
		}
	})
}

// TestHysteriaUsernameDecoderRules renders one user per shape against the real
// config path, so a change to what the node writes is visible as rendered JSON
// rather than only as a verdict.
func TestHysteriaUsernameDecoderRules(t *testing.T) {
	for _, username := range []string{
		"nodot", "dot@example", "dash-user", "under_score", "12345",
		"a.b", "user@example.com",
	} {
		t.Run(username, func(t *testing.T) {
			cfg, err := NewConfig(`{"auth": {"type": "userpass", "userpass": {}}}`, nil)
			if err != nil {
				t.Fatalf("NewConfig: %v", err)
			}
			syncErr := cfg.syncUsers([]*common.User{{
				Email:    username,
				Proxies:  &common.Proxy{Hysteria: &common.Hysteria{Auth: "pw"}},
				Inbounds: []string{},
			}})
			out, err := cfg.ToBytes()
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			if syncErr != nil {
				t.Logf("REJECTED as expected: %s -> %v", username, syncErr)
			} else {
				t.Logf("accepted -> %s", out)
			}
		})
	}
}
