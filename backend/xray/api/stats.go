package api

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/xtls/xray-core/app/stats/command"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pasarguard/node/common"
)

func (x *XrayHandler) GetSysStats(ctx context.Context) (*common.BackendStatsResponse, error) {
	client := *x.StatsServiceClient
	resp, err := client.GetSysStats(ctx, &command.SysStatsRequest{})
	if err != nil {
		code := codes.Unknown
		if st, ok := status.FromError(err); ok {
			code = st.Code()
		}
		return nil, status.Errorf(code, "failed to get sys stats: %v", err)
	}

	return &common.BackendStatsResponse{
		NumGoroutine: resp.NumGoroutine,
		NumGc:        resp.NumGC,
		Alloc:        resp.Alloc,
		TotalAlloc:   resp.TotalAlloc,
		Sys:          resp.Sys,
		Mallocs:      resp.Mallocs,
		Frees:        resp.Frees,
		LiveObjects:  resp.LiveObjects,
		PauseTotalNs: resp.PauseTotalNs,
		Uptime:       resp.Uptime,
	}, nil
}

func (x *XrayHandler) QueryStats(ctx context.Context, pattern string, reset bool) (*command.QueryStatsResponse, error) {
	client := *x.StatsServiceClient
	resp, err := client.QueryStats(ctx, &command.QueryStatsRequest{Pattern: pattern, Reset_: reset})
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (x *XrayHandler) GetUserOnlineStats(ctx context.Context, email string) (*common.OnlineStatResponse, error) {
	if email == "" {
		return nil, errors.New("email required")
	}
	client := *x.StatsServiceClient
	resp, err := client.GetStatsOnline(ctx, &command.GetStatsRequest{Name: fmt.Sprintf("user>>>%s>>>online", email)})
	if err != nil {
		return nil, err
	}

	return &common.OnlineStatResponse{Name: email, Value: resp.GetStat().GetValue()}, nil
}

func (x *XrayHandler) GetUserOnlineIpListStats(ctx context.Context, email string) (*common.StatsOnlineIpListResponse, error) {
	if email == "" {
		return nil, errors.New("email required")
	}
	client := *x.StatsServiceClient
	resp, err := client.GetStatsOnlineIpList(ctx, &command.GetStatsRequest{Name: fmt.Sprintf("user>>>%s>>>online", email)})
	if err != nil {
		return nil, err
	}

	return &common.StatsOnlineIpListResponse{Name: email, Ips: resp.GetIps()}, nil
}

func (x *XrayHandler) GetUsersStats(ctx context.Context, reset bool) (*common.StatResponse, error) {
	resp, err := x.QueryStats(ctx, "user>>>", reset)
	if err != nil {
		return nil, err
	}

	return buildStatResponse(resp.GetStat()), nil
}

func (x *XrayHandler) GetInboundsStats(ctx context.Context, reset bool) (*common.StatResponse, error) {
	resp, err := x.QueryStats(ctx, "inbound>>>", reset)
	if err != nil {
		return nil, err
	}

	return buildStatResponse(resp.GetStat()), nil
}

func (x *XrayHandler) GetOutboundsStats(ctx context.Context, reset bool) (*common.StatResponse, error) {
	resp, err := x.QueryStats(ctx, "outbound>>>", reset)
	if err != nil {
		return nil, err
	}

	return buildStatResponse(resp.GetStat()), nil
}

func (x *XrayHandler) GetUserStats(ctx context.Context, email string, reset bool) (*common.StatResponse, error) {
	if email == "" {
		return nil, errors.New("email required")
	}
	resp, err := x.QueryStats(ctx, fmt.Sprintf("user>>>%s>>>", email), reset)
	if err != nil {
		return nil, err
	}

	return buildStatResponse(resp.GetStat()), nil
}

func (x *XrayHandler) GetInboundStats(ctx context.Context, tag string, reset bool) (*common.StatResponse, error) {
	if tag == "" {
		return nil, errors.New("tag required")
	}
	resp, err := x.QueryStats(ctx, fmt.Sprintf("inbound>>>%s>>>", tag), reset)
	if err != nil {
		return nil, err
	}

	return buildStatResponse(resp.GetStat()), nil
}

func (x *XrayHandler) GetOutboundStats(ctx context.Context, tag string, reset bool) (*common.StatResponse, error) {
	if tag == "" {
		return nil, errors.New("tag required")
	}
	resp, err := x.QueryStats(ctx, fmt.Sprintf("outbound>>>%s>>>", tag), reset)
	if err != nil {
		return nil, err
	}

	return buildStatResponse(resp.GetStat()), nil
}

func buildStatResponse(queryStats []*command.Stat) *common.StatResponse {
	stats := &common.StatResponse{}
	for _, stat := range queryStats {
		name, link, statType, ok := parseStatName(stat.GetName())
		if !ok {
			continue
		}

		stats.Stats = append(stats.Stats, &common.Stat{
			Name:  name,
			Type:  statType,
			Link:  link,
			Value: stat.GetValue(),
		})
	}

	return stats
}

func parseStatName(raw string) (name, link, statType string, ok bool) {
	parts := strings.Split(raw, ">>>")
	if len(parts) < 4 {
		return "", "", "", false
	}
	if parts[1] == "" || parts[2] == "" || parts[3] == "" {
		return "", "", "", false
	}

	return parts[1], parts[2], parts[3], true
}
