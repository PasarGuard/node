package singbox

import (
	"context"
	"errors"
	"fmt"

	"github.com/xtls/xray-core/app/stats/command"

	"github.com/pasarguard/node/common"
)

func (s *SingBox) GetSysStats(ctx context.Context) (*common.BackendStatsResponse, error) {
	handler := s.handler
	if handler == nil {
		return nil, errors.New("sing-box stats client not ready")
	}
	resp, err := handler.sysStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get sys stats: %w", err)
	}
	return &common.BackendStatsResponse{
		NumGoroutine: resp.GetNumGoroutine(),
		NumGc:        resp.GetNumGC(),
		Alloc:        resp.GetAlloc(),
		TotalAlloc:   resp.GetTotalAlloc(),
		Sys:          resp.GetSys(),
		Mallocs:      resp.GetMallocs(),
		Frees:        resp.GetFrees(),
		LiveObjects:  resp.GetLiveObjects(),
		PauseTotalNs: resp.GetPauseTotalNs(),
		Uptime:       resp.GetUptime(),
	}, nil
}

func (s *SingBox) GetStats(ctx context.Context, request *common.StatRequest) (*common.StatResponse, error) {
	handler := s.handler
	if handler == nil {
		return nil, errors.New("sing-box stats client not ready")
	}

	reset := request.GetReset_()
	var (
		raw []*command.Stat
		err error
	)

	switch request.GetType() {
	case common.StatType_Outbounds:
		raw, err = handler.queryStats(ctx, "outbound>>>", reset)
	case common.StatType_Outbound:
		if request.GetName() == "" {
			return nil, errors.New("name required")
		}
		raw, err = handler.queryStats(ctx, fmt.Sprintf("outbound>>>%s>>>", request.GetName()), reset)
	case common.StatType_Inbounds:
		raw, err = handler.queryStats(ctx, "inbound>>>", reset)
	case common.StatType_Inbound:
		if request.GetName() == "" {
			return nil, errors.New("name required")
		}
		raw, err = handler.queryStats(ctx, fmt.Sprintf("inbound>>>%s>>>", request.GetName()), reset)
	case common.StatType_UsersStat:
		raw, err = handler.queryStats(ctx, "user>>>", reset)
	case common.StatType_UserStat:
		if request.GetName() == "" {
			return nil, errors.New("name required")
		}
		raw, err = handler.queryStats(ctx, fmt.Sprintf("user>>>%s>>>", request.GetName()), reset)
	default:
		return nil, errors.New("not implemented stat type")
	}
	if err != nil {
		return nil, err
	}
	return s.mergePendingStats(raw, request.GetReset_()), nil
}

// mergePendingStats folds counters that were drained before a planned restart
// into the live response, so usage survives the restart window. Pending
// entries are dropped once the caller consumes them with reset=true (the
// panel's poll mode).
func (s *SingBox) mergePendingStats(live []*command.Stat, consume bool) *common.StatResponse {
	s.syncMu.Lock()
	pending := s.pendingStats
	if consume && len(pending) > 0 {
		s.pendingStats = map[string]int64{}
	}
	s.syncMu.Unlock()

	merged := make(map[string]int64, len(live)+len(pending))
	order := make([]string, 0, len(live)+len(pending))
	add := func(name, statType, link string, v int64) {
		key := name + "|" + statType + "|" + link
		if _, seen := merged[key]; !seen {
			order = append(order, key)
		}
		merged[key] += v
	}
	for _, st := range live {
		name, link, statType, ok := parseStatName(st.GetName())
		if !ok {
			continue
		}
		add(name, statType, link, st.GetValue())
	}
	for key, v := range pending {
		var name, statType, link string
		if parts := splitKey(key); len(parts) == 3 {
			name, statType, link = parts[0], parts[1], parts[2]
		} else {
			continue
		}
		add(name, statType, link, v)
	}

	resp := &common.StatResponse{}
	for _, key := range order {
		parts := splitKey(key)
		if len(parts) != 3 {
			continue
		}
		resp.Stats = append(resp.Stats, &common.Stat{
			Name:  parts[0],
			Type:  parts[1],
			Link:  parts[2],
			Value: merged[key],
		})
	}
	return resp
}

func splitKey(key string) []string {
	out := make([]string, 0, 3)
	start := 0
	for i := 0; i < len(key); i++ {
		if key[i] == '|' {
			out = append(out, key[start:i])
			start = i + 1
		}
	}
	return append(out, key[start:])
}

// GetUserOnlineStats: sing-box's v2ray_api exposes no online counters
// (GetStatsOnline does not exist). Panel degrades to an error state.
func (s *SingBox) GetUserOnlineStats(_ context.Context, email string) (*common.OnlineStatResponse, error) {
	return nil, fmt.Errorf("online stats are not supported by the sing-box backend (user %s)", email)
}

func (s *SingBox) GetUserOnlineIpListStats(_ context.Context, email string) (*common.StatsOnlineIpListResponse, error) {
	return nil, fmt.Errorf("online IP list is not supported by the sing-box backend (user %s)", email)
}

// GetOutboundsLatency: outbound latency probing is an xray observatory feature;
// sing-box has no equivalent metric endpoint yet.
func (s *SingBox) GetOutboundsLatency(_ context.Context, _ *common.LatencyRequest) (*common.LatencyResponse, error) {
	return nil, errors.New("outbound latency is not supported by the sing-box backend")
}
