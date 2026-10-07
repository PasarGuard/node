package tunnel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// Pin is one tool's declared binary (CONTRACT §2.1 install rule). Each tool
// package embeds its own pins.json and registers it from init() — the
// framework holds no shared pin file, so six agents adding six pins never
// touch one file.
//
// pins.json shape (node/backend/tunnel/<tool>/pins.json):
//
//	{
//	  "tool": "gost",
//	  "version": "3.3.0",
//	  "upstream": "go-gost/gost/releases/download/v3.3.0",
//	  "assets": {
//	    "linux-amd64": {
//	      "name": "gost_3.3.0_linux_amd64.tar.gz",
//	      "sha256": "<hash of the downloaded asset>",
//	      "bin": "gost",
//	      "bin_sha256": "<hash of the executable that actually runs>"
//	    }
//	  }
//	}
//
// name/sha256 are what the bundle fetcher downloads and verifies. bin and
// bin_sha256 are what Start verifies before exec: for a raw-binary asset set
// "bin" to the asset itself (or leave both empty). A tool whose asset is an
// archive must fill bin/bin_sha256 — Start refuses to run a binary it cannot
// verify against the pin.
type Pin struct {
	Tool     string              `json:"tool"`
	Version  string              `json:"version"`
	Upstream string              `json:"upstream"` // "<org>/<repo>/releases/download/<tag>"
	Assets   map[string]PinAsset `json:"assets"`
	Source   string              `json:"-"` // pins.json path, for error messages
}

// PinAsset is one platform's download.
type PinAsset struct {
	Name      string `json:"name"`
	SHA256    string `json:"sha256"`
	Bin       string `json:"bin,omitempty"`        // executable path inside the bundle dir; "" = the asset itself
	BinSHA256 string `json:"bin_sha256,omitempty"` // required unless the asset IS the binary
}

// PlatformKey is the assets map key for this machine: "<GOOS>-<GOARCH>".
func PlatformKey() string { return runtime.GOOS + "-" + runtime.GOARCH }

var (
	pinsMu sync.RWMutex
	pins   = map[string]Pin{}
)

// RegisterPin installs a tool's pin. Called from the tool package's init(),
// usually via RegisterPinJSON(go:embed pins.json).
func RegisterPin(p Pin) error {
	if p.Tool == "" {
		return fmt.Errorf("tunnel: pin has no tool name")
	}
	if len(p.Assets) == 0 {
		return fmt.Errorf("tunnel: pin for %q has no assets", p.Tool)
	}
	for key, a := range p.Assets {
		if a.Name == "" || a.SHA256 == "" {
			return fmt.Errorf("tunnel: pin for %q, platform %q: name and sha256 are required", p.Tool, key)
		}
		if len(a.SHA256) != 64 {
			return fmt.Errorf("tunnel: pin for %q, platform %q: sha256 must be the full 64 hex digits", p.Tool, key)
		}
	}
	pinsMu.Lock()
	defer pinsMu.Unlock()
	pins[p.Tool] = p
	return nil
}

// RegisterPinJSON parses and registers a pins.json blob.
func RegisterPinJSON(data []byte, source string) error {
	var p Pin
	if err := json.Unmarshal(data, &p); err != nil {
		return fmt.Errorf("tunnel: %s: %w", source, err)
	}
	p.Source = source
	return RegisterPin(p)
}

// PinFor returns the pin registered for a tool.
func PinFor(tool string) (Pin, bool) {
	pinsMu.RLock()
	defer pinsMu.RUnlock()
	p, ok := pins[tool]
	return p, ok
}

// AssetFor returns this platform's asset for a pin.
func (p Pin) AssetFor(platform string) (PinAsset, error) {
	a, ok := p.Assets[platform]
	if !ok {
		keys := make([]string, 0, len(p.Assets))
		for k := range p.Assets {
			keys = append(keys, k)
		}
		return PinAsset{}, fmt.Errorf("tunnel: pin for %q has no asset for %s (has: %s)", p.Tool, platform, strings.Join(keys, ", "))
	}
	return a, nil
}

// BundleDir is the operator-supplied bundle directory: TUNNEL_BUNDLE_DIR, or
// "" when the operator has not passed one. There is no other source and no
// download at runtime (CONTRACT §2.1).
func BundleDir(override string) string {
	if override != "" {
		return override
	}
	return os.Getenv("TUNNEL_BUNDLE_DIR")
}

// ResolveBinary finds the executable for a tool and refuses anything whose
// sha256 is not the pin's.
//
// Order:
//  1. TUNNEL_BUNDLE_DIR/<bin> — the offline bundle, hash-checked.
//  2. the tool on PATH — also hash-checked, so a system install of the wrong
//     build is refused rather than silently run.
//
// bundleDir is "" to read the environment; the Manager passes the node
// config's value so a node and its tests agree on one directory.
func ResolveBinary(tool, bundleDir string) (string, error) {
	p, ok := PinFor(tool)
	if !ok {
		return "", fmt.Errorf("%w: %q has no pins.json registered", ErrUnknownTool, tool)
	}
	asset, err := p.AssetFor(PlatformKey())
	if err != nil {
		return "", err
	}
	binName := asset.Bin
	if binName == "" {
		binName = asset.Name
	}

	var candidates []string
	if dir := BundleDir(bundleDir); dir != "" {
		candidates = append(candidates, filepath.Join(dir, filepath.FromSlash(binName)))
	}
	if base := filepath.Base(binName); base == binName {
		if found, err := exec.LookPath(base); err == nil {
			candidates = append(candidates, found)
		}
	}

	want := asset.BinSHA256
	if want == "" {
		// The asset itself is the executable (raw binary release).
		want = asset.SHA256
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("%w: pin %s@%s (set TUNNEL_BUNDLE_DIR to an offline bundle)", ErrBinaryNotFound, tool, p.Version)
	}
	for _, path := range candidates {
		got, err := FileSHA256(path)
		if err != nil {
			continue
		}
		if !strings.EqualFold(got, want) {
			return "", fmt.Errorf("%w: %s has %s, pin wants %s (%s@%s)", ErrBinaryMismatch, path, got, want, tool, p.Version)
		}
		return path, nil
	}
	return "", fmt.Errorf("%w: %s (set TUNNEL_BUNDLE_DIR to an offline bundle)", ErrBinaryNotFound, tool)
}

// FileSHA256 is the hex sha256 of a file, lower case.
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
