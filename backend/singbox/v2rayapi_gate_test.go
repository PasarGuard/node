package singbox

import (
	"os"
	"strings"
	"testing"
)

// TestRequiresV2RayAPITag proves the node refuses a sing-box binary without
// -tags with_v2ray_api (silent stats loss) and that the explicit escape
// hatch lets it through with a warning. Uses SINGBOX_OFFICIAL_EXECUTABLE
// (an official release build); skipped when unset.
func TestRequiresV2RayAPITag(t *testing.T) {
	official := os.Getenv("SINGBOX_OFFICIAL_EXECUTABLE")
	if official == "" {
		t.Skip("SINGBOX_OFFICIAL_EXECUTABLE not set")
	}
	dir := t.TempDir()

	_, err := NewSingBoxCore(official, dir, 10, 10, false)
	if err == nil {
		t.Fatal("expected NewSingBoxCore to refuse a binary without with_v2ray_api")
	}
	if !strings.Contains(err.Error(), "with_v2ray_api") {
		t.Fatalf("error must name the missing tag and the fix, got: %v", err)
	}
	t.Logf("refused: %v", err)

	core, err := NewSingBoxCore(official, dir, 10, 10, true)
	if err != nil {
		t.Fatalf("allowMissing=true should start the probe, got: %v", err)
	}
	if core.Version() == "" {
		t.Error("empty version from official binary")
	}
	t.Logf("allowed with warning, version=%s", core.Version())
}
