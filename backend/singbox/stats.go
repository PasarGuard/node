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
	return buildStatResponse(raw), nil
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
