// Command fetchbundle builds the offline tunnel binary bundle: it globs every
// backend/tunnel/<tool>/pins.json in a node checkout, downloads each asset
// from ${TUNNEL_GITHUB_MIRROR:-https://github.com}, verifies every sha256, and
// writes the assets plus SHA256SUMS into the output directory.
//
// Usage (from the node repo root):
//
//	go run ./backend/tunnel/cmd/fetchbundle -root . -out /opt/tunnel-bundle
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/pasarguard/node/backend/tunnel"
)

func main() {
	root := flag.String("root", ".", "node checkout root (the directory that contains backend/)")
	out := flag.String("out", "tunnel-bundle", "output directory for assets + SHA256SUMS")
	mirror := flag.String("mirror", "", "download base URL (default $TUNNEL_GITHUB_MIRROR or https://github.com)")
	flag.Parse()

	pins, err := tunnel.GlobPins(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if len(pins) == 0 {
		fmt.Fprintf(os.Stderr, "no pins.json under %s/backend/tunnel/*/\n", *root)
		os.Exit(1)
	}
	fmt.Printf("fetching %d pin file(s) into %s\n", len(pins), *out)
	if err := tunnel.FetchBundle(context.Background(), *out, *mirror, pins); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("ok: every asset verified against its pin; SHA256SUMS written")
}
