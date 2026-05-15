package wireguard

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pasarguard/node/common"
)

const wireGuardNATOutputInterfaceEnv = "PG_NODE_WG_NAT_OUTPUT_INTERFACE"

func (wg *WireGuard) latencyProbeInterface() string {
	if iface := strings.TrimSpace(os.Getenv(wireGuardNATOutputInterfaceEnv)); iface != "" {
		return iface
	}

	wg.mu.RLock()
	defer wg.mu.RUnlock()
	if wg.config == nil {
		return ""
	}
	return strings.TrimSpace(wg.config.InterfaceName)
}

func (wg *WireGuard) GetOutboundsLatency(ctx context.Context, request *common.LatencyRequest) (*common.LatencyResponse, error) {
	wg.mu.RLock()
	state := wg.state
	testURL := ""
	timeoutSeconds := 0
	if wg.config != nil && wg.config.Latency != nil {
		testURL = wg.config.Latency.TestURL
		timeoutSeconds = wg.config.Latency.TimeoutSeconds
	}
	wg.mu.RUnlock()

	if state != lifecycleRunning {
		return nil, errWireGuardNotStarted
	}

	iface := wg.latencyProbeInterface()
	name := iface
	if name == "" {
		name = "wireguard"
	}

	requestName := strings.TrimSpace(request.GetName())
	if requestName != "" && requestName != name {
		return &common.LatencyResponse{Latencies: []*common.Latency{}}, nil
	}

	client := &http.Client{
		Timeout:   time.Duration(timeoutSeconds) * time.Second,
		Transport: latencyHTTPTransport(iface),
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, testURL, nil)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	resp, err := client.Do(req)
	delay := time.Since(start).Milliseconds()
	now := time.Now().Unix()

	alive := err == nil
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}

	latency := &common.Latency{
		Name:        name,
		Alive:       alive,
		Delay:       delay,
		Link:        testURL,
		LastTryTime: now,
		Source:      "wireguard-probe",
	}
	if alive {
		latency.LastSeenTime = now
	}

	return &common.LatencyResponse{Latencies: []*common.Latency{latency}}, nil
}
