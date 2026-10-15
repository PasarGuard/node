package xray

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	"google.golang.org/protobuf/proto"
)

func buildPB(t *testing.T, raw string) []byte {
	t.Helper()
	var jsonConfig conf.Config
	if err := json.Unmarshal([]byte(raw), &jsonConfig); err != nil {
		t.Fatal(err)
	}
	built, err := jsonConfig.Build()
	if err != nil {
		t.Fatal(err)
	}
	data, err := proto.Marshal(built)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseLiveParts(t *testing.T) {
	data := buildPB(t, `{
		"routing": {"rules": [{"type": "field", "ip": ["10.0.0.0/8"], "outboundTag": "block"}]},
		"outbounds": [{"tag": "direct", "protocol": "freedom"}, {"tag": "block", "protocol": "blackhole"}]
	}`)

	parts, err := parseLiveParts(data)
	if err != nil {
		t.Fatal(err)
	}
	if parts.routing.GetType() != "xray.app.router.Config" {
		t.Fatalf("routing message type = %q", parts.routing.GetType())
	}
	if len(parts.outbounds) != 2 || parts.outbounds["block"] == nil {
		t.Fatalf("outbounds = %v", parts.outbounds)
	}
}

func TestParseLivePartsNeedsRouting(t *testing.T) {
	data := buildPB(t, `{"outbounds": [{"tag": "direct", "protocol": "freedom"}]}`)
	if _, err := parseLiveParts(data); err == nil {
		t.Fatal("parseLiveParts accepted a config without routing")
	}
}

func TestExecutableReplaced(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xray")
	if err := os.WriteFile(path, []byte("first"), 0o755); err != nil {
		t.Fatal(err)
	}
	core := &Core{executablePath: path}
	if !core.executableReplaced() {
		t.Fatal("a core that never started must count as replaced")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	core.executable = info
	if core.executableReplaced() {
		t.Fatal("an unchanged binary was reported as replaced")
	}

	if err := os.WriteFile(path, []byte("second build"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !core.executableReplaced() {
		t.Fatal("a rewritten binary was not detected")
	}
}

func TestConvertLivePartsUsesTheInstalledXray(t *testing.T) {
	core, err := NewXRayCore(executablePath, assetsPath, configPath, 10, 10)
	if err != nil {
		t.Fatal(err)
	}

	cfg := livePlanConfig(t, livePlanJSON(
		planOutbounds(planDirect, planBlock),
		`[{"type": "field", "ip": ["geoip:private"], "outboundTag": "block"}]`,
	), nil)
	parts, err := core.convertLiveParts(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if parts.routing == nil || parts.outbounds["direct"] == nil || parts.outbounds["block"] == nil {
		t.Fatalf("converted parts = %+v", parts)
	}

	// xray refuses VLESS without encryption to a public address.
	bad := livePlanConfig(t, livePlanJSON(planOutbounds(planDirect,
		`{"tag": "proxy", "protocol": "vless", "settings": {"vnext": [{"address": "8.8.8.8", "port": 443, "users": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "encryption": "none"}]}]}}`,
	), "[]"), nil)
	if _, err := core.convertLiveParts(context.Background(), bad); err == nil || !strings.Contains(err.Error(), "convert") {
		t.Fatalf("convertLiveParts accepted an outbound xray rejects: %v", err)
	}
}
