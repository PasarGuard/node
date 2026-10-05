package hysteria

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/pasarguard/node/common"
)

// Panel-facing stat types. The panel matches on these exact strings
// (panel/app/jobs/record_usages.py reads Stat.type "uplink"/"downlink" and
// Stat.link "traffic").
const (
	uplinkType   = "uplink"
	downlinkType = "downlink"
)

// GetSysStats reports the core's uptime and zeroes the Go runtime counters.
//
// Hysteria is a separate process, so its heap, goroutine count and GC stats are
// properties of a program this code does not own and cannot measure — reporting
// the node's own numbers under a hysteria2 node's name would be a lie dressed as
// a metric. Only Uptime is meaningful, and it is the one field the controller
// reads (controller/controller.go:703).
//
// An error here is NOT an acceptable alternative: get_backend_stats is the
// panel's node health check (panel/app/jobs/node_checker.py:101), so returning
// one marks a perfectly healthy hysteria2 node BROKEN.
//
// ponytail: the honest zero. If per-core memory is ever wanted, the way to get
// it is hysteria reporting it, or the node sampling the child's rusage — both
// need an upstream change this package does not carry.
func (h *Hysteria) GetSysStats(_ context.Context) (*common.BackendStatsResponse, error) {
	h.mu.RLock()
	var uptime time.Duration
	if h.core != nil {
		uptime = h.core.Uptime()
	}
	h.mu.RUnlock()

	return &common.BackendStatsResponse{Uptime: uint32(uptime.Seconds())}, nil
}

func (h *Hysteria) statsHandler() (*statsClient, error) {
	h.mu.RLock()
	handler := h.handler
	h.mu.RUnlock()
	if handler == nil {
		return nil, errors.New("hysteria stats client not ready")
	}
	return handler, nil
}

// GetStats maps the panel's StatRequest onto hysteria's traffic stats API.
//
// Type support, and why:
//
//   - UsersStat / UserStat read /traffic. This is the only place a hysteria2
//     user's bytes come from.
//   - Outbounds / Inbound have no counterpart: hysteria has no outbound or
//     inbound concept, only client ids. Returning an empty response rather than
//     an error keeps the node-stats job, which polls these types for every
//     core, working unchanged (CONTRACT §3.2 relies on it).
//   - The `reset` flag maps onto `?clear=1`, which is exactly the same
//     read-and-zero contract as the v2ray-api reset, so the panel's
//     poll-with-reset accounting needs no special case.
//
// The pendingStats trap this must not regress: pending rows are per-USER, so
// only a user-facing read with reset=true may consume them. An Outbounds poll
// that cleared them would drop the bytes on the floor — the node-stats job
// ticks 15s after scheduler start, before the usage job's 30s first tick
// (backend/singbox/stats.go:77-84 documents the incident).
func (h *Hysteria) GetStats(ctx context.Context, request *common.StatRequest) (*common.StatResponse, error) {
	handler, err := h.statsHandler()
	if err != nil {
		return nil, err
	}

	reset := request.GetReset_()

	switch request.GetType() {
	case common.StatType_UsersStat, common.StatType_UserStat:
	default:
		// No hysteria-side data for this type. Merged with pending rows below so
		// a node-stats poll still shows the user's traffic, never consumes it.
		return h.mergePendingStats(nil, false), nil
	}

	entries, err := handler.traffic(ctx, reset)
	if err != nil {
		return nil, err
	}

	live := make([]*common.Stat, 0, len(entries)*2)
	for id, entry := range entries {
		if request.GetType() == common.StatType_UserStat && request.GetName() != "" && id != request.GetName() {
			continue
		}
		if entry.Tx > 0 {
			live = append(live, &common.Stat{Name: id, Link: trafficStatLink, Type: uplinkType, Value: int64(entry.Tx)})
		}
		if entry.Rx > 0 {
			live = append(live, &common.Stat{Name: id, Link: trafficStatLink, Type: downlinkType, Value: int64(entry.Rx)})
		}
	}
	sortStats(live)

	consume := reset
	return h.mergePendingStats(live, consume), nil
}

// mergePendingStats folds counters drained before a planned restart into the
// live response, so usage survives the restart window. Pending entries are
// dropped only when a user-facing caller consumes them with reset=true.
func (h *Hysteria) mergePendingStats(live []*common.Stat, consume bool) *common.StatResponse {
	h.syncMu.Lock()
	pending := h.pendingStats
	if consume && len(pending) > 0 {
		h.pendingStats = map[string]int64{}
	}
	h.syncMu.Unlock()

	acc := map[string]*common.Stat{}
	order := make([]string, 0, len(live)+len(pending))
	add := func(name, statType string, value int64) {
		key := name + "\x00" + statType
		row, ok := acc[key]
		if !ok {
			row = &common.Stat{Name: name, Link: trafficStatLink, Type: statType}
			acc[key] = row
			order = append(order, key)
		}
		row.Value += value
	}
	for _, stat := range live {
		add(stat.GetName(), stat.GetType(), stat.GetValue())
	}
	for key, value := range pending {
		name, statType, ok := splitPendingKey(key)
		if !ok {
			continue
		}
		add(name, statType, value)
	}

	out := &common.StatResponse{Stats: make([]*common.Stat, 0, len(order))}
	for _, key := range order {
		out.Stats = append(out.Stats, acc[key])
	}
	sortStats(out.Stats)
	return out
}

// splitPendingKey parses the "<name>|<type>" keys flushCountersLocked writes.
// A name containing "|" is preserved: the split is on the last separator only.
func splitPendingKey(key string) (name, statType string, ok bool) {
	for i := len(key) - 1; i >= 0; i-- {
		if key[i] != '|' {
			continue
		}
		switch key[i+1:] {
		case uplinkType:
			return key[:i], uplinkType, true
		case downlinkType:
			return key[:i], downlinkType, true
		}
	}
	return "", "", false
}

func sortStats(stats []*common.Stat) {
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].GetName() != stats[j].GetName() {
			return stats[i].GetName() < stats[j].GetName()
		}
		return stats[i].GetType() < stats[j].GetType()
	})
}

// GetUserOnlineStats reads hysteria's /online map: id -> number of connected
// client instances. This is a real online count, not sing-box's "unsupported".
func (h *Hysteria) GetUserOnlineStats(ctx context.Context, email string) (*common.OnlineStatResponse, error) {
	handler, err := h.statsHandler()
	if err != nil {
		return nil, err
	}
	online, err := handler.online(ctx)
	if err != nil {
		return nil, err
	}
	return &common.OnlineStatResponse{Name: email, Value: int64(online[email])}, nil
}

// GetUserOnlineIpListStats: hysteria's API exposes no per-client IP list. The
// /dump/streams endpoint does carry the client's request addresses, but it
// describes proxy streams rather than the client's own address, so it is not
// this field. Error rather than a fabricated row.
func (h *Hysteria) GetUserOnlineIpListStats(_ context.Context, email string) (*common.StatsOnlineIpListResponse, error) {
	return nil, errors.New("online IP list is not supported by the hysteria backend (user " + email + ")")
}

// GetOutboundsLatency: latency probing is an xray observatory feature. Hysteria
// has no outbound concept at all.
func (h *Hysteria) GetOutboundsLatency(_ context.Context, _ *common.LatencyRequest) (*common.LatencyResponse, error) {
	return nil, errors.New("outbound latency is not supported by the hysteria backend")
}
