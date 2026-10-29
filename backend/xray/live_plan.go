package xray

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

type liveStepKind int

const (
	liveRemoveOutbound liveStepKind = iota
	liveAddOutbound
	liveReplaceRouting
)

// liveStep is one xray API call of a live config update.
type liveStep struct {
	kind liveStepKind
	tag  string
}

func (s liveStep) String() string {
	switch s.kind {
	case liveAddOutbound:
		return fmt.Sprintf("add outbound %q", s.tag)
	case liveRemoveOutbound:
		return fmt.Sprintf("remove outbound %q", s.tag)
	default:
		return "replace routing"
	}
}

// xray's RemoveOutbound only drops the handler from its tag table and never
// closes it. These protocols keep nothing running in the handler itself, so an
// outbound of theirs can be removed or replaced live. Any other protocol
// (wireguard, masque, or one added to xray later) needs a restart.
var outboundProtocolsSafeToRemove = map[string]struct{}{
	"freedom":     {},
	"direct":      {},
	"blackhole":   {},
	"block":       {},
	"loopback":    {},
	"dns":         {},
	"http":        {},
	"socks":       {},
	"shadowsocks": {},
	"vless":       {},
	"vmess":       {},
	"trojan":      {},
	"hysteria":    {},
}

type liveOutbound struct {
	tag  string
	raw  []byte
	safe bool
}

// planLiveUpdate returns the API calls that turn the running config cur into
// next, or the reason next needs a restart instead.
func planLiveUpdate(cur, next *Config) ([]liveStep, string) {
	same, err := sameOutsideLiveParts(cur, next)
	if err != nil {
		return nil, err.Error()
	}
	if !same {
		return nil, "the config changed outside routing rules, balancers and outbounds"
	}

	curOut, err := parseLiveOutbounds(cur.OutboundConfigs)
	if err != nil {
		return nil, "running config: " + err.Error()
	}
	nextOut, err := parseLiveOutbounds(next.OutboundConfigs)
	if err != nil {
		return nil, "new config: " + err.Error()
	}
	if len(curOut) == 0 || len(nextOut) == 0 {
		return nil, "a config without outbounds"
	}

	curByTag := make(map[string]liveOutbound, len(curOut))
	for _, o := range curOut {
		curByTag[o.tag] = o
	}
	nextByTag := make(map[string]liveOutbound, len(nextOut))
	for _, o := range nextOut {
		nextByTag[o.tag] = o
	}

	var steps []liveStep
	add := func(tag string) { steps = append(steps, liveStep{kind: liveAddOutbound, tag: tag}) }
	remove := func(tag string) { steps = append(steps, liveStep{kind: liveRemoveOutbound, tag: tag}) }
	notRemovable := func(tag string) string {
		if !curByTag[tag].safe {
			return fmt.Sprintf("outbound %q would keep running in xray after removal", tag)
		}
		return ""
	}
	handled := make(map[string]bool)

	// xray uses the first outbound as the default. Removing the default leaves
	// none until the next add, which becomes the new default.
	oldDefault, newDefault := curOut[0].tag, nextOut[0].tag
	if oldDefault != newDefault {
		reset := []string{oldDefault}
		if _, existed := curByTag[newDefault]; existed {
			reset = append(reset, newDefault)
		}
		for _, tag := range reset {
			if reason := notRemovable(tag); reason != "" {
				return nil, reason
			}
		}
		for _, tag := range reset {
			remove(tag)
		}
		add(newDefault)
		if _, kept := nextByTag[oldDefault]; kept {
			add(oldDefault)
		}
		handled[oldDefault] = true
		handled[newDefault] = true
	}

	// New outbounds go in before any rule can point at them.
	for _, o := range nextOut {
		if _, existed := curByTag[o.tag]; !existed && !handled[o.tag] {
			add(o.tag)
		}
	}
	// xray has no outbound edit: an edit is a remove and an add of the same tag.
	for _, o := range nextOut {
		old, existed := curByTag[o.tag]
		if !existed || handled[o.tag] || bytes.Equal(old.raw, o.raw) {
			continue
		}
		if reason := notRemovable(o.tag); reason != "" {
			return nil, reason
		}
		remove(o.tag)
		add(o.tag)
	}

	routingChanged, err := liveRoutingChanged(cur, next)
	if err != nil {
		return nil, err.Error()
	}
	if routingChanged {
		steps = append(steps, liveStep{kind: liveReplaceRouting})
	}

	// Deleted outbounds go only after no rule points at them.
	for _, o := range curOut {
		if _, kept := nextByTag[o.tag]; kept || handled[o.tag] {
			continue
		}
		if reason := notRemovable(o.tag); reason != "" {
			return nil, reason
		}
		remove(o.tag)
	}

	return steps, ""
}

// sameOutsideLiveParts reports whether cur and next differ only in routing
// rules, balancers, outbounds and users.
func sameOutsideLiveParts(cur, next *Config) (bool, error) {
	a, err := withoutLiveParts(cur)
	if err != nil {
		return false, err
	}
	b, err := withoutLiveParts(next)
	if err != nil {
		return false, err
	}
	if !bytes.Equal(a, b) || len(cur.InboundConfigs) != len(next.InboundConfigs) {
		return false, nil
	}
	for i := range cur.InboundConfigs {
		if inboundExcluded(cur.InboundConfigs[i]) != inboundExcluded(next.InboundConfigs[i]) {
			return false, nil
		}
	}
	return true, nil
}

// withoutLiveParts serializes c without the parts a live update replaces.
// Users are left out as well: Inbound.clients is not serialized.
func withoutLiveParts(c *Config) ([]byte, error) {
	stripped := *c
	stripped.OutboundConfigs = nil
	if c.RouterConfig != nil {
		router := *c.RouterConfig
		router.RuleList = nil
		router.Balancers = nil
		stripped.RouterConfig = &router
	}
	return json.Marshal(&stripped)
}

func inboundExcluded(i *Inbound) bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.exclude
}

func liveRoutingChanged(cur, next *Config) (bool, error) {
	a, err := json.Marshal(liveRouting(cur))
	if err != nil {
		return false, err
	}
	b, err := json.Marshal(liveRouting(next))
	if err != nil {
		return false, err
	}
	return !bytes.Equal(a, b), nil
}

func liveRouting(c *Config) any {
	if c.RouterConfig == nil {
		return nil
	}
	return []any{c.RouterConfig.RuleList, c.RouterConfig.Balancers}
}

func parseLiveOutbounds(raw any) ([]liveOutbound, error) {
	if raw == nil {
		return nil, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, errors.New("outbounds is not a list")
	}

	out := make([]liveOutbound, 0, len(list))
	seen := make(map[string]struct{}, len(list))
	for _, item := range list {
		obj, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("an outbound is not an object")
		}
		tag, _ := obj["tag"].(string)
		if tag == "" {
			return nil, errors.New("an outbound has no tag")
		}
		if _, dup := seen[tag]; dup {
			return nil, fmt.Errorf("outbound tag %q is used twice", tag)
		}
		seen[tag] = struct{}{}

		data, err := json.Marshal(obj)
		if err != nil {
			return nil, err
		}
		protocol, _ := obj["protocol"].(string)
		out = append(out, liveOutbound{tag: tag, raw: data, safe: outboundSafeToRemove(strings.ToLower(protocol), obj["settings"])})
	}
	return out, nil
}

func outboundSafeToRemove(protocol string, settings any) bool {
	if _, ok := outboundProtocolsSafeToRemove[protocol]; !ok {
		return false
	}
	// A VLESS outbound with reverse keeps its reverse connection up, and one
	// with testpre keeps opening connections ahead of use. Both stop only on
	// the Close that RemoveOutbound never calls.
	return protocol != "vless" || !hasSetValue(settings, "reverse", "testpre")
}

// hasSetValue reports whether any of keys appears anywhere in v with a value
// other than null, false, 0 or "".
func hasSetValue(v any, keys ...string) bool {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if slices.Contains(keys, k) && !isUnsetJSONValue(val) {
				return true
			}
			if hasSetValue(val, keys...) {
				return true
			}
		}
	case []any:
		for _, val := range t {
			if hasSetValue(val, keys...) {
				return true
			}
		}
	}
	return false
}

func isUnsetJSONValue(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case bool:
		return !t
	case float64:
		return t == 0
	case string:
		return t == ""
	}
	return false
}
