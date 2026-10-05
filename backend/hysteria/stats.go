package hysteria

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Hysteria exposes per-user traffic, online counts and a kick endpoint over a
// small HTTP API on its own listener (docs: advanced/Traffic-Stats-API). This
// client is the node's only way to bill a hysteria2 user.
//
// The API is keyed by the *id* the authenticator returned, not by a password:
//   - userpass auth returns the username (extras/auth/userpass.go:38)
//   - password auth returns the fixed string "user" (extras/auth/password.go:21)
//
// The second case is why syncUsers only injects into `userpass`. A `password`
// core authenticates everyone as one identity and every user's traffic lands on
// the single "user" row; the node reports what the API says rather than
// inventing a split it cannot justify.

const (
	trafficPath = "/traffic"
	onlinePath  = "/online"
	kickPath    = "/kick"

	trafficStatLink = "traffic"
)

// statsClient talks to one core's traffic stats API.
type statsClient struct {
	baseURL string
	secret  string
	http    *http.Client
}

func newStatsClient(apiPort int, secret string) *statsClient {
	return &statsClient{
		baseURL: fmt.Sprintf("http://127.0.0.1:%d", apiPort),
		secret:  secret,
		http: &http.Client{
			// Short: the listener is loopback-only, so a slow answer means the
			// core is wedged. A long block here would stall the panel's stats
			// poll across every core.
			Timeout: 10 * time.Second,
		},
	}
}

func (c *statsClient) do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return nil, err
	}
	if c.secret != "" {
		// Upstream compares the Authorization header to the configured secret
		// verbatim (extras/trafficlogger/http.go:100), not as a bearer token.
		req.Header.Set("Authorization", c.secret)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hysteria stats api %s: status %d: %s", path, resp.StatusCode, strings.TrimSpace(string(payload)))
	}
	return payload, nil
}

type trafficEntry struct {
	Tx uint64 `json:"tx"`
	Rx uint64 `json:"rx"`
}

// traffic reads the per-id counters. When clear is set the core zeroes them as
// it answers, which is the equivalent of the v2ray-api `reset` flag: the value
// returned IS the value consumed, so a second poll does not double-bill.
func (c *statsClient) traffic(ctx context.Context, clear bool) (map[string]trafficEntry, error) {
	path := trafficPath
	if clear {
		path += "?clear=1"
	}
	payload, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	entries := map[string]trafficEntry{}
	if len(bytes.TrimSpace(payload)) == 0 {
		return entries, nil
	}
	if err := json.Unmarshal(payload, &entries); err != nil {
		return nil, fmt.Errorf("hysteria stats api returned unparseable traffic: %w", err)
	}
	return entries, nil
}

// online reads id -> number of connected client instances (docs: /online).
func (c *statsClient) online(ctx context.Context) (map[string]int, error) {
	payload, err := c.do(ctx, http.MethodGet, onlinePath, nil)
	if err != nil {
		return nil, err
	}
	entries := map[string]int{}
	if len(bytes.TrimSpace(payload)) == 0 {
		return entries, nil
	}
	if err := json.Unmarshal(payload, &entries); err != nil {
		return nil, fmt.Errorf("hysteria stats api returned unparseable online map: %w", err)
	}
	return entries, nil
}

// kick cuts the named ids' live connections.
//
// The core refuses the next LogTraffic from a kicked id and closes its QUIC
// connection (core/server/server.go:380-387 and :393-400), so this ends
// established sessions rather than only blocking the next connect — which is
// what the panel needs when a user runs out of quota.
//
// It is not a ban: the client reconnects, and the next authenticate succeeds
// unless the panel has also removed the user. Upstream says so in the docs, so
// the node must kick AND the panel must remove, in that order.
func (c *statsClient) kick(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	body, err := json.Marshal(ids)
	if err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodPost, kickPath, body)
	return err
}
