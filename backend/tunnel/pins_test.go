package tunnel

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writePin installs a fake pin for a fresh tool name and returns a bundle dir
// containing a valid executable for it. The fake pin is how the pin machinery
// is proven without a real tunnel binary in the tree.
func writePin(t *testing.T, tool, assetName, assetContent, binName, binContent string) string {
	t.Helper()

	dir := t.TempDir()
	assetFile := filepath.Join(dir, assetName)
	if err := os.WriteFile(assetFile, []byte(assetContent), 0o644); err != nil {
		t.Fatal(err)
	}
	assetSum, err := FileSHA256(assetFile)
	if err != nil {
		t.Fatal(err)
	}

	p := Pin{
		Tool:     tool,
		Version:  "9.9.9",
		Upstream: "example/" + tool + "/releases/download/v9.9.9",
		Assets: map[string]PinAsset{
			PlatformKey(): {Name: assetName, SHA256: assetSum},
		},
	}
	if binName != "" {
		// Archive-style pin: the asset is downloaded and verified, the
		// extracted binary is verified separately before it is exec'd.
		binFile := filepath.Join(dir, binName)
		if err := os.WriteFile(binFile, []byte(binContent), 0o755); err != nil {
			t.Fatal(err)
		}
		binSum, err := FileSHA256(binFile)
		if err != nil {
			t.Fatal(err)
		}
		p.Assets[PlatformKey()] = PinAsset{Name: assetName, SHA256: assetSum, Bin: binName, BinSHA256: binSum}
	}
	if err := RegisterPin(p); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestResolveBinaryHappyPath: a bundle file whose sha256 matches the pin is
// resolved and returned.
func TestResolveBinaryHappyPath(t *testing.T) {
	const tool = "testtool-happy"
	dir := writePin(t, tool, "tool.bin", "pinned-bytes", "", "")

	path, err := ResolveBinary(tool, dir)
	if err != nil {
		t.Fatalf("ResolveBinary: %v", err)
	}
	if filepath.Base(path) != "tool.bin" {
		t.Fatalf("resolved %q, want tool.bin", path)
	}
}

// TestResolveBinaryRefusesWrongSHA is the install rule's negative control: the
// same path, wrong bytes → refused with ErrBinaryMismatch, never returned.
func TestResolveBinaryRefusesWrongSHA(t *testing.T) {
	const tool = "testtool-tampered"
	dir := writePin(t, tool, "tool.bin", "pinned-bytes", "", "")

	if err := os.WriteFile(filepath.Join(dir, "tool.bin"), []byte("tampered!!!"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := ResolveBinary(tool, dir)
	if !errors.Is(err, ErrBinaryMismatch) {
		t.Fatalf("want ErrBinaryMismatch, got %v", err)
	}
}

// TestResolveBinaryArchivePin: when pins.json names an extracted binary
// (bin/bin_sha256), the archive hash is not what gates the running executable.
func TestResolveBinaryArchivePin(t *testing.T) {
	const tool = "testtool-archive"
	dir := writePin(t, tool, "tool.tar.gz", "archive-bytes", "tool", "extracted-binary")

	path, err := ResolveBinary(tool, dir)
	if err != nil {
		t.Fatalf("ResolveBinary: %v", err)
	}
	if filepath.Base(path) != "tool" {
		t.Fatalf("resolved %q, want the extracted binary", path)
	}

	if err := os.WriteFile(filepath.Join(dir, "tool"), []byte("other-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveBinary(tool, dir); !errors.Is(err, ErrBinaryMismatch) {
		t.Fatalf("tampered executable: want ErrBinaryMismatch, got %v", err)
	}
}

// TestResolveBinaryWithoutBundle: no TUNNEL_BUNDLE_DIR and nothing on PATH is
// an explicit not-found, not a silent download.
func TestResolveBinaryWithoutBundle(t *testing.T) {
	const tool = "testtool-absent"
	if err := RegisterPin(Pin{
		Tool: tool, Version: "1.0.0", Upstream: "x/y",
		Assets: map[string]PinAsset{PlatformKey(): {Name: "absent.bin", SHA256: strings.Repeat("0", 64)}},
	}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TUNNEL_BUNDLE_DIR", "")
	_, err := ResolveBinary(tool, "")
	if !errors.Is(err, ErrBinaryNotFound) {
		t.Fatalf("want ErrBinaryNotFound, got %v", err)
	}
}

// TestRegisterPinValidation: a pin that cannot possibly verify anything (no
// assets, a truncated hash) is rejected at registration, not at Start.
func TestRegisterPinValidation(t *testing.T) {
	cases := []Pin{
		{Tool: "x"}, // no assets
		{Tool: "", Assets: map[string]PinAsset{PlatformKey(): {Name: "a", SHA256: strings.Repeat("a", 64)}}},
		{Tool: "y", Assets: map[string]PinAsset{PlatformKey(): {Name: "a", SHA256: "deadbeef"}}}, // short hash
		{Tool: "z", Assets: map[string]PinAsset{PlatformKey(): {Name: "", SHA256: strings.Repeat("a", 64)}}},
	}
	for i, p := range cases {
		if err := RegisterPin(p); err == nil {
			t.Fatalf("case %d: want an error, got nil", i)
		}
	}
}
