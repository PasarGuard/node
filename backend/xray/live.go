package xray

import (
	"context"
	"fmt"
	"log"

	"github.com/xtls/xray-core/common/serial"
	xcore "github.com/xtls/xray-core/core"

	"github.com/pasarguard/node/backend"
)

var _ backend.LiveConfigApplier = (*Xray)(nil)

// liveAPI is the part of the xray API a live config update calls.
type liveAPI interface {
	AddOutbound(context.Context, *xcore.OutboundHandlerConfig) error
	RemoveOutbound(context.Context, string) error
	ReplaceRouting(context.Context, *serial.TypedMessage) error
}

func runLiveSteps(ctx context.Context, h liveAPI, steps []liveStep, parts *liveParts) error {
	for _, step := range steps {
		if _, ok := parts.outbounds[step.tag]; step.kind == liveAddOutbound && !ok {
			return fmt.Errorf("converted config has no outbound %q", step.tag)
		}
	}

	for _, step := range steps {
		var err error
		switch step.kind {
		case liveAddOutbound:
			err = h.AddOutbound(ctx, parts.outbounds[step.tag])
		case liveRemoveOutbound:
			err = h.RemoveOutbound(ctx, step.tag)
		case liveReplaceRouting:
			err = h.ReplaceRouting(ctx, parts.routing)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", step, err)
		}
	}
	return nil
}

// ApplyConfigLive applies a new panel config to the running xray through its
// API when it differs only in routing rules, balancers and outbounds that can
// be swapped live. It returns false when the change needs a restart.
func (x *Xray) ApplyConfigLive(ctx context.Context, rawConfig string, exclude []string) (bool, error) {
	x.syncMu.Lock()
	defer x.syncMu.Unlock()

	x.mu.RLock()
	closed, cur, handler, core := x.closed, x.config, x.handler, x.core
	x.mu.RUnlock()
	if closed || cur == nil || handler == nil || core == nil || !core.Started() {
		return false, nil
	}

	// Build the new config exactly as New and Core.Start build the running one.
	next, err := NewConfig(rawConfig, exclude)
	if err != nil {
		return false, err
	}
	if err := next.ApplyAPI(x.apiPort, x.metricPort); err != nil {
		return false, err
	}
	next.GetLogFiles()

	steps, reason := planLiveUpdate(cur, next)
	if reason != "" {
		log.Printf("xray needs a restart for the new config: %s", reason)
		return false, nil
	}

	if len(steps) > 0 {
		if core.executableReplaced() {
			log.Println("xray needs a restart for the new config: the xray binary on disk changed")
			return false, nil
		}
		parts, err := core.convertLiveParts(ctx, next)
		if err != nil {
			return false, err
		}
		if err := runLiveSteps(ctx, handler, steps, parts); err != nil {
			return false, err
		}
	}

	updated, err := cur.Clone()
	if err != nil {
		return false, err
	}
	updated.RouterConfig = next.RouterConfig
	updated.OutboundConfigs = next.OutboundConfigs
	x.setConfig(updated)

	log.Printf("applied the new config to xray without a restart (%d API calls)", len(steps))
	return true, nil
}
