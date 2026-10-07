package tunnel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sha256Of(t *testing.T, content string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func TestGlobPinsFindsToolPins(t *testing.T) {
	root := t.TempDir()
	toolDir := filepath.Join(root, "backend", "tunnel", "gost")
	if err := os.MkdirAll(toolDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pinPath := filepath.Join(toolDir, "pins.json")
	if err := os.WriteFile(pinPath, []byte(`{"tool":"gost"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := GlobPins(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != pinPath {
		t.Fatalf("GlobPins = %v, want [%s]", got, pinPath)
	}
}

// TestFetchBundleHappyPath: the fetcher downloads against the mirror base,
// verifies every hash, and leaves a SHA256SUMS an operator can re-check with
// sha256sum -c.
func TestFetchBundleHappyPath(t *testing.T) {
	content := "release-asset-bytes"
	sum := sha256Of(t, content)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/tool_a_1.0_linux_amd64.tar.gz") {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(content))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	root := t.TempDir()
	toolDir := filepath.Join(root, "backend", "tunnel", "fetchnormal")
	if err := os.MkdirAll(toolDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pinJSON := `{
	  "tool": "fetchnormal",
	  "version": "1.0",
	  "upstream": "org/fetchnormal/releases/download/v1.0",
	  "assets": {"linux-amd64": {"name": "tool_a_1.0_linux_amd64.tar.gz", "sha256": "` + sum + `"}}
	}`
	pinPath := filepath.Join(toolDir, "pins.json")
	if err := os.WriteFile(pinPath, []byte(pinJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(t.TempDir(), "bundle")
	if err := FetchBundle(context.Background(), out, srv.URL, []string{pinPath}); err != nil {
		t.Fatalf("FetchBundle: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(out, "tool_a_1.0_linux_amd64.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != content {
		t.Fatalf("asset content = %q", data)
	}
	sums, err := os.ReadFile(filepath.Join(out, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	wantLine := sum + "  tool_a_1.0_linux_amd64.tar.gz\n"
	if string(sums) != wantLine {
		t.Fatalf("SHA256SUMS = %q, want %q", sums, wantLine)
	}
}

// TestFetchBundleRefusesBadHash: a mirror that serves the wrong bytes must not
// produce a bundle file at all.
func TestFetchBundleRefusesBadHash(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("wrong-bytes"))
	}))
	defer srv.Close()

	root := t.TempDir()
	toolDir := filepath.Join(root, "backend", "tunnel", "fetchtampered")
	if err := os.MkdirAll(toolDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pinJSON := `{
	  "tool": "fetchtampered",
	  "version": "1.0",
	  "upstream": "org/fetchtampered/releases/download/v1.0",
	  "assets": {"linux-amd64": {"name": "tool.tar.gz", "sha256": "` + sha256Of(t, "correct-bytes") + `"}}
	}`
	pinPath := filepath.Join(toolDir, "pins.json")
	if err := os.WriteFile(pinPath, []byte(pinJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(t.TempDir(), "bundle")
	err := FetchBundle(context.Background(), out, srv.URL, []string{pinPath})
	if !errors.Is(err, ErrBinaryMismatch) {
		t.Fatalf("want ErrBinaryMismatch, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(out, "tool.tar.gz")); !os.IsNotExist(statErr) {
		t.Fatalf("tampered asset must not land in the bundle (stat: %v)", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(out, "SHA256SUMS")); !os.IsNotExist(statErr) {
		t.Fatalf("no SHA256SUMS may be written when a download fails verification (stat: %v)", statErr)
	}
}

// TestAssetURLMirrorAndAbsolute: ${TUNNEL_GITHUB_MIRROR} rewrites GitHub-style
// paths; a plain upstream URL (dest-unreach.org, nginx.org) is never touched.
func TestAssetURLMirrorAndAbsolute(t *testing.T) {
	got := AssetURL("https://mirror.local", "org/repo/releases/download/v1", "a.tar.gz")
	if got != "https://mirror.local/org/repo/releases/download/v1/a.tar.gz" {
		t.Fatalf("mirror join: %s", got)
	}
	got = AssetURL("https://mirror.local", "http://www.dest-unreach.org/socat/ftp", "socat.tar.gz")
	if got != "http://www.dest-unreach.org/socat/ftp/socat.tar.gz" {
		t.Fatalf("absolute upstream must ignore the mirror: %s", got)
	}
	if AssetURL("", "org/repo", "x") != DefaultMirror+"/org/repo/x" {
		t.Fatalf("empty mirror must fall back to %s", DefaultMirror)
	}
}
