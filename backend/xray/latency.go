package xray

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"time"

	"github.com/pasarguard/node/common"
)

type observatoryEntry struct {
	Alive        bool   `json:"alive"`
	Delay        int64  `json:"delay"`
	OutboundTag  string `json:"outbound_tag"`
	LastSeenTime int64  `json:"last_seen_time"`
	LastTryTime  int64  `json:"last_try_time"`
}

type debugVarsResponse struct {
	Observatory map[string]observatoryEntry `json:"observatory"`
}

const xrayObservatoryReadTimeout = 5 * time.Second

func shouldIncludeObservatoryOutbound(protocolByTag map[string]string, tag string) bool {
	protocol, ok := protocolByTag[tag]
	if !ok {
		return true
	}
	_, excluded := observatoryExcludedProtocols[protocol]
	return !excluded
}

func (x *Xray) GetOutboundsLatency(ctx context.Context, request *common.LatencyRequest) (*common.LatencyResponse, error) {
	x.mu.RLock()
	started := x.core != nil && x.core.Started()
	metricPort := x.metricPort
	protocolByTag := map[string]string(nil)
	if x.config != nil {
		protocolByTag = x.config.outboundProtocolByTag()
	}
	x.mu.RUnlock()

	if !started {
		return nil, errors.New("xray not started")
	}

	client := &http.Client{Timeout: xrayObservatoryReadTimeout}
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(metricPort))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr.String()+"/debug/vars", nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("read xray observatory metrics: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("read xray observatory metrics: unexpected status %d", resp.StatusCode)
	}

	var vars debugVarsResponse
	if err := json.NewDecoder(resp.Body).Decode(&vars); err != nil {
		return nil, fmt.Errorf("decode xray observatory metrics: %w", err)
	}
	if len(vars.Observatory) == 0 {
		return nil, errors.New("xray outbound latency is not available")
	}

	name := request.GetName()
	keys := make([]string, 0, len(vars.Observatory))
	for key := range vars.Observatory {
		if name != "" && key != name {
			continue
		}
		if !shouldIncludeObservatoryOutbound(protocolByTag, key) {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)

	latencies := make([]*common.Latency, 0, len(keys))
	for _, key := range keys {
		entry := vars.Observatory[key]
		linkName := entry.OutboundTag
		if linkName == "" {
			linkName = key
		}
		latencies = append(latencies, &common.Latency{
			Name:         key,
			Alive:        entry.Alive,
			Delay:        entry.Delay,
			Link:         linkName,
			LastSeenTime: entry.LastSeenTime,
			LastTryTime:  entry.LastTryTime,
			Source:       "xray-observatory",
		})
	}

	return &common.LatencyResponse{Latencies: latencies}, nil
}
