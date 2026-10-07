package tunnel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// DefaultMirror is what ${TUNNEL_GITHUB_MIRROR} falls back to.
const DefaultMirror = "https://github.com"

// GlobPins returns every pins.json under a node checkout:
// <nodeRoot>/backend/tunnel/<tool>/pins.json. One file per tool package —
// six tool agents write six files and never share one.
func GlobPins(nodeRoot string) ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(nodeRoot, "backend", "tunnel", "*", "pins.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	return matches, nil
}

// AssetURL is where one asset lives. An upstream that is already a URL is used
// as-is (dest-unreach.org, nginx.org); a GitHub-style path is joined to the
// mirror, which is what makes a mirror substitution one env var.
func AssetURL(mirror, upstream, name string) string {
	if strings.HasPrefix(upstream, "http://") || strings.HasPrefix(upstream, "https://") {
		return strings.TrimRight(upstream, "/") + "/" + name
	}
	if mirror == "" {
		mirror = DefaultMirror
	}
	return strings.TrimRight(mirror, "/") + "/" + strings.TrimLeft(upstream, "/") + "/" + name
}

// FetchBundle downloads every asset of every pin in pinFiles into outDir,
// verifies each sha256 against its pin while writing, and finishes by writing
// outDir/SHA256SUMS and re-verifying every file against that manifest.
// A single mismatch aborts the whole run: a bundle that is not fully verified
// must not be handed to an operator.
//
// There is no fallback to an unverified download. mirror "" reads
// ${TUNNEL_GITHUB_MIRROR}, else DefaultMirror.
func FetchBundle(ctx context.Context, outDir, mirror string, pinFiles []string) error {
	if mirror == "" {
		mirror = os.Getenv("TUNNEL_GITHUB_MIRROR")
	}
	if mirror == "" {
		mirror = DefaultMirror
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}

	sums := map[string]string{} // name -> sha256
	for _, file := range pinFiles {
		data, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		var p Pin
		if err := json.Unmarshal(data, &p); err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
		p.Source = file
		for platform, asset := range p.Assets {
			if _, dup := sums[asset.Name]; dup {
				return fmt.Errorf("tunnel: two pins claim asset %q (%s, %s)", asset.Name, p.Tool, platform)
			}
			sum, err := fetchOne(ctx, outDir, AssetURL(mirror, p.Upstream, asset.Name), asset.Name, asset.SHA256)
			if err != nil {
				return fmt.Errorf("%s (%s %s): %w", p.Tool, p.Version, asset.Name, err)
			}
			sums[asset.Name] = sum
		}
	}

	names := make([]string, 0, len(sums))
	for n := range sums {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		fmt.Fprintf(&b, "%s  %s\n", sums[n], n)
	}
	if err := os.WriteFile(filepath.Join(outDir, "SHA256SUMS"), []byte(b.String()), 0o644); err != nil {
		return err
	}

	// Re-read what landed on disk: a manifest built from memory proves the
	// downloads, not the bundle directory an operator will hand to a node.
	for _, n := range names {
		got, err := FileSHA256(filepath.Join(outDir, n))
		if err != nil {
			return err
		}
		if !strings.EqualFold(got, sums[n]) {
			return fmt.Errorf("%w: %s in %s is %s, manifest says %s", ErrBinaryMismatch, n, outDir, got, sums[n])
		}
	}
	return nil
}

// fetchOne downloads url into outDir/name, checking sha256 while it streams.
// The file appears under its final name only after the hash matches.
func fetchOne(ctx context.Context, outDir, url, name, want string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: %s", url, resp.Status)
	}

	tmp, err := os.CreateTemp(outDir, "."+name+".*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())

	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), resp.Body); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, want) {
		return "", fmt.Errorf("%w: downloaded %s has %s, pin wants %s", ErrBinaryMismatch, url, got, want)
	}
	final := filepath.Join(outDir, name)
	if err := os.Rename(tmp.Name(), final); err != nil {
		return "", err
	}
	return got, nil
}
