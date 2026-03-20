package wireguard

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/pkg/stats"
)

const onlineActivityThreshold = 45 * time.Second

func (wg *WireGuard) getInterfaceCounters() (int64, int64, error) {
	wg.mu.RLock()
	mgr := wg.manager
	wg.mu.RUnlock()

	if mgr == nil {
		return 0, 0, errWireGuardManagerNotInitialized
	}

	return mgr.GetInterfaceStats()
}

func (wg *WireGuard) handleUserStats(ctx context.Context, request *common.StatRequest) (*common.StatResponse, error) {
	var keys []string
	if peer := wg.peerStore.GetByEmail(request.GetName()); peer != nil {
		keys = []string{peer.PublicKey.String()}
	}
	if len(keys) == 0 {
		return &common.StatResponse{Stats: []*common.Stat{}}, nil
	}

	return wg.statsTracker.GetStats(ctx, keys, request.GetReset_()), nil
}

func (wg *WireGuard) handleUsersStats(ctx context.Context, request *common.StatRequest) (*common.StatResponse, error) {
	return wg.statsTracker.GetUsersStats(ctx, request.GetReset_()), nil
}

func (wg *WireGuard) handleInterfaceOutboundStats(name string, reset bool) (*common.StatResponse, error) {
	if name == "" {
		name = wg.config.InterfaceName
	}

	currentRx, currentTx, err := wg.getInterfaceCounters()
	if err != nil {
		return nil, err
	}

	deltaRx, deltaTx := wg.interfaceStats.Delta(currentRx, currentTx, reset)
	return &common.StatResponse{
		Stats: stats.BuildInterfaceStats(name, "interface", deltaRx, deltaTx),
	}, nil
}

func (wg *WireGuard) GetStats(ctx context.Context, request *common.StatRequest) (*common.StatResponse, error) {
	wg.mu.RLock()
	state := wg.state
	wg.mu.RUnlock()

	if state != lifecycleRunning {
		return nil, errWireGuardNotStarted
	}

	switch request.GetType() {
	case common.StatType_UserStat:
		return wg.handleUserStats(ctx, request)

	case common.StatType_UsersStat:
		return wg.handleUsersStats(ctx, request)

	case common.StatType_Outbound, common.StatType_Outbounds:
		// handleInterfaceOutboundStats falls back to the configured interface name when GetName() is empty,
		// so both stat types are satisfied by the same call.
		return wg.handleInterfaceOutboundStats(request.GetName(), request.GetReset_())

	case common.StatType_Inbound, common.StatType_Inbounds:
		return nil, errors.New("inbound stats not applicable for wireguard")
	default:
		return nil, errors.New("unsupported stat type")
	}
}

func (wg *WireGuard) GetUserOnlineStats(ctx context.Context, email string) (*common.OnlineStatResponse, error) {
	wg.mu.RLock()
	state := wg.state
	wg.mu.RUnlock()

	if state != lifecycleRunning {
		return nil, errWireGuardNotStarted
	}

	// Get user's public key directly from PeerStore
	var keys []string
	if peer := wg.peerStore.GetByEmail(email); peer != nil {
		keys = []string{peer.PublicKey.String()}
	}
	if len(keys) == 0 {
		return &common.OnlineStatResponse{
			Name:  email,
			Value: 0,
		}, nil
	}

	if wg.statsTracker.AnyActiveSince(keys, time.Now().Add(-onlineActivityThreshold)) {
		return &common.OnlineStatResponse{
			Name:  email,
			Value: 1,
		}, nil
	}

	return &common.OnlineStatResponse{
		Name:  email,
		Value: 0,
	}, nil
}

func (wg *WireGuard) GetUserOnlineIpListStats(ctx context.Context, email string) (*common.StatsOnlineIpListResponse, error) {
	wg.mu.RLock()
	state := wg.state
	wg.mu.RUnlock()

	if state != lifecycleRunning {
		return nil, errWireGuardNotStarted
	}

	response := &common.StatsOnlineIpListResponse{
		Name: email,
		Ips:  make(map[string]int64),
	}

	// Get user's public key directly from PeerStore
	var keys []string
	if peer := wg.peerStore.GetByEmail(email); peer != nil {
		keys = []string{peer.PublicKey.String()}
	}
	if len(keys) == 0 {
		return response, nil
	}

	endpointActivity := wg.statsTracker.EndpointActivity(keys)
	for endpointIP, ts := range endpointActivity {
		response.Ips[endpointIP] = ts
	}

	return response, nil
}

// GetSysStats returns system stats for the WireGuard backend
func (wg *WireGuard) GetSysStats(ctx context.Context) (*common.BackendStatsResponse, error) {
	wg.mu.RLock()
	state := wg.state
	mgr := wg.manager
	wg.mu.RUnlock()

	if err := lifecycleReadinessError(state); err != nil {
		return nil, err
	}
	if mgr == nil {
		return nil, errWireGuardManagerNotInitialized
	}
	if _, _, err := mgr.GetInterfaceStats(); err != nil {
		return nil, fmt.Errorf("wireguard interface not available: %w", err)
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	stats := common.BackendStatsResponse{
		NumGoroutine: uint32(runtime.NumGoroutine()),
		NumGc:        memStats.NumGC,
		Alloc:        memStats.Alloc,
		TotalAlloc:   memStats.TotalAlloc,
		Sys:          memStats.Sys,
		Mallocs:      memStats.Mallocs,
		Frees:        memStats.Frees,
		LiveObjects:  memStats.Mallocs - memStats.Frees,
		PauseTotalNs: memStats.PauseTotalNs,
		Uptime:       uint32(time.Since(wg.startTime).Seconds()),
	}

	return &stats, nil
}
