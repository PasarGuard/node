package xray

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/serial"
	xcore "github.com/xtls/xray-core/core"
	"google.golang.org/protobuf/proto"
)

// liveParts holds what a live config update sends to xray. The running xray
// binary builds it, so fields newer than the node's own xray library survive
// and an older xray never gets a message it cannot read.
type liveParts struct {
	routing   *serial.TypedMessage
	outbounds map[string]*xcore.OutboundHandlerConfig
}

var routerConfigType = serial.GetMessageType(&router.Config{})

// convertLiveParts converts the routing and outbounds of cfg with
// `xray convert pb`, which also checks them before anything is applied.
func (c *Core) convertLiveParts(ctx context.Context, cfg *Config) (*liveParts, error) {
	dir, err := os.MkdirTemp("", "pg-node-live-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	input, err := json.Marshal(map[string]any{
		"routing":   cfg.RouterConfig,
		"outbounds": cfg.OutboundConfigs,
	})
	if err != nil {
		return nil, err
	}
	in := filepath.Join(dir, "live.json")
	out := filepath.Join(dir, "live.pb")
	if err := os.WriteFile(in, input, 0o600); err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, c.executablePath, "convert", "pb", "-o", out, in)
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+c.assetsPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("xray convert pb: %w: %s", err, strings.TrimSpace(string(output)))
	}

	data, err := os.ReadFile(out)
	if err != nil {
		return nil, err
	}
	return parseLiveParts(data)
}

func parseLiveParts(data []byte) (*liveParts, error) {
	var pb xcore.Config
	if err := proto.Unmarshal(data, &pb); err != nil {
		return nil, err
	}

	parts := &liveParts{outbounds: make(map[string]*xcore.OutboundHandlerConfig, len(pb.Outbound))}
	for _, app := range pb.App {
		if app.GetType() == routerConfigType {
			parts.routing = app
		}
	}
	if parts.routing == nil {
		return nil, errors.New("converted config has no routing")
	}
	for _, outbound := range pb.Outbound {
		parts.outbounds[outbound.GetTag()] = outbound
	}
	return parts, nil
}

// executableReplaced reports whether the xray binary on disk is no longer the
// one the running process was started from.
func (c *Core) executableReplaced() bool {
	c.mu.Lock()
	started := c.executable
	c.mu.Unlock()
	if started == nil {
		return true
	}

	now, err := os.Stat(c.executablePath)
	if err != nil {
		return true
	}
	return !os.SameFile(started, now) || now.Size() != started.Size() || !now.ModTime().Equal(started.ModTime())
}
