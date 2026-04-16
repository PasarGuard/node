package xray

import (
	"reflect"
	"testing"
)

func TestCollectUnixSocketPaths(t *testing.T) {
	cfg := &Config{
		InboundConfigs: []*Inbound{
			nil,
			{Listen: ""},
			{Listen: "127.0.0.1"},
			{Listen: "  /run/xray.sock,0666  "},
			{Listen: "/run/xray.sock"},
			{Listen: "example.com"},
			{Listen: "@abstract-socket"},
			{Listen: " /tmp/another.sock , 0600 "},
			{Listen: "0.0.0.0"},
		},
	}

	got := collectUnixSocketPaths(cfg)
	want := []string{"/run/xray.sock", "/tmp/another.sock"}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("collectUnixSocketPaths() = %v, want %v", got, want)
	}
}

func TestCollectUnixSocketPathsNilConfig(t *testing.T) {
	if got := collectUnixSocketPaths(nil); got != nil {
		t.Fatalf("collectUnixSocketPaths(nil) = %v, want nil", got)
	}
}
