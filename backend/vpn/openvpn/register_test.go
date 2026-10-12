package openvpn

import (
	"context"
	"strings"
	"testing"

	"github.com/pasarguard/node/backend"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
)

// CONTRACT §4.2 rule 4 / §6.1: the enum is appended, never renumbered.
// A new member inserted above HYSTERIA2 would silently retype every existing
// node's traffic as a different core, and nothing else would fail.
func TestBackendTypeEnumIsAdditive(t *testing.T) {
	want := []struct {
		name string
		num  common.BackendType
	}{
		{"XRAY", common.BackendType_XRAY},
		{"WIREGUARD", common.BackendType_WIREGUARD},
		{"SINGBOX", common.BackendType_SINGBOX},
		{"HYSTERIA2", common.BackendType_HYSTERIA2},
		{"OPENVPN", common.BackendType_OPENVPN},
	}
	for i, w := range want {
		if int32(w.num) != int32(i) {
			t.Errorf("%s = %d, want %d — existing members must keep their numbers", w.name, w.num, i)
		}
		if got := w.num.String(); got != w.name {
			t.Errorf("BackendType(%d).String() = %q, want %q", w.num, got, w.name)
		}
	}
	if int32(common.BackendType_OPENVPN) != 4 {
		t.Errorf("OPENVPN = %d, want 4", common.BackendType_OPENVPN)
	}
}

// The blank import in controller.go must reach this init(), or the enum has no
// Factory and Start answers "unknown backend type 4" (the Phase 1.2a bug).
//
// The Factory must also fail on a *named* prerequisite rather than on anything
// generic: with an empty node config there is nowhere to render the PKI, and a
// message that says so is what an operator needs to see.
func TestFactoryIsRegisteredAndNamesItsFirstMissingPrerequisite(t *testing.T) {
	f, ok := backend.For(common.BackendType_OPENVPN)
	if !ok {
		t.Fatal("no Factory registered for BackendType_OPENVPN — the blank import in controller.go is missing")
	}
	_, err := f(context.Background(), &common.Backend{}, backend.Ports{}, &config.Config{})
	if err == nil {
		t.Fatal("Factory with an empty node config succeeded; want an error naming what is missing")
	}
	if !strings.Contains(err.Error(), "generated config path") {
		t.Fatalf("Factory error = %v, want it to name the missing generated config path", err)
	}
}

// An unparseable panel config must be refused before anything touches disk.
func TestFactoryRejectsBadConfigJSON(t *testing.T) {
	f, ok := backend.For(common.BackendType_OPENVPN)
	if !ok {
		t.Fatal("no Factory registered for BackendType_OPENVPN")
	}
	_, err := f(context.Background(), &common.Backend{Config: "{not json"}, backend.Ports{}, &config.Config{})
	if err == nil || !strings.Contains(err.Error(), "invalid openvpn config JSON") {
		t.Fatalf("error = %v, want invalid openvpn config JSON", err)
	}
}
