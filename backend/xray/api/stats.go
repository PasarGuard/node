package api

import (
	"context"
	"fmt"
	"strings"

	"github.com/xtls/xray-core/app/stats/command"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/m03ed/marzban-node-go/common"
)

type LinkType string

const (
	Downlink LinkType = "downlink"
	Uplink   LinkType = "uplink"
)

func (l LinkType) String() string {
	return string(l)
}

type UserStatsResponse struct {
	Email    string `json:"email"`
	Uplink   int64  `json:"uplink"`
	Downlink int64  `json:"downlink"`
}

type StatsResponse struct {
	Tag      string `json:"tag"`
	Uplink   int64  `json:"uplink"`
	Downlink int64  `json:"downlink"`
}

func (x *XrayHandler) GetSysStats(ctx context.Context) (*common.BackendStatsResponse, error) {
	client := *x.StatsServiceClient
	resp, err := client.GetSysStats(ctx, &command.SysStatsRequest{})
	if err != nil {
		return nil, status.Errorf(codes.Unknown, "failed to get sys stats: %v", err)
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

func (x *XrayHandler) GetStatOnline(ctx context.Context, email string) (*common.OnlineStatResponse, error) {
	client := *x.StatsServiceClient
	resp, err := client.GetStatsOnline(ctx, &command.GetStatsRequest{Name: email})
	if err != nil {
		return nil, err
	}

	return &common.OnlineStatResponse{Email: email, Value: resp.GetStat().Value}, nil
}

func (x *XrayHandler) GetUsersStats(ctx context.Context, reset bool) (*common.StatResponse, error) {
	resp, err := x.QueryStats(ctx, fmt.Sprintf("user>>>"), reset)
	if err != nil {
		return nil, err
	}

	stats := &common.StatResponse{}
	for _, stat := range resp.GetStat() {
		data := stat.GetName()
		value := stat.GetValue()

		// Extract the type from the name (e.g., "traffic")
		parts := strings.Split(data, ">>>")
		name := parts[1]
		link := parts[2]
		statType := parts[3]

		stats.Stats = append(stats.Stats, &common.Stat{
			Name:  name,
			Type:  statType,
			Link:  link,
			Value: value,
		})
	}

	return stats, nil
}

func (x *XrayHandler) GetInboundsStats(ctx context.Context, reset bool) (*common.StatResponse, error) {
	resp, err := x.QueryStats(ctx, fmt.Sprintf("inbound>>>"), reset)
	if err != nil {
		return nil, err
	}

	stats := &common.StatResponse{}
	for _, stat := range resp.GetStat() {
		data := stat.GetName()
		value := stat.GetValue()

		// Extract the type from the name (e.g., "traffic")
		parts := strings.Split(data, ">>>")
		name := parts[1]
		link := parts[2]
		statType := parts[3]

		stats.Stats = append(stats.Stats, &common.Stat{
			Name:  name,
			Type:  statType,
			Link:  link,
			Value: value,
		})
	}

	return stats, nil
}

func (x *XrayHandler) GetOutboundsStats(ctx context.Context, reset bool) (*common.StatResponse, error) {
	resp, err := x.QueryStats(ctx, fmt.Sprintf("outbound>>>"), reset)
	if err != nil {
		return nil, err
	}

	stats := &common.StatResponse{}
	for _, stat := range resp.GetStat() {
		data := stat.GetName()
		value := stat.GetValue()

		parts := strings.Split(data, ">>>")
		name := parts[1]
		statType := parts[2]
		link := parts[3]

		stats.Stats = append(stats.Stats, &common.Stat{
			Name:  name,
			Type:  statType,
			Link:  link,
			Value: value,
		})
	}

	return stats, nil
}

func (x *XrayHandler) GetUserStats(ctx context.Context, email string, reset bool) (*UserStatsResponse, error) {
	resp, err := x.QueryStats(ctx, fmt.Sprintf("user>>>%s>>>", email), reset)
	if err != nil {
		return nil, err
	}

	var stats UserStatsResponse

	for _, stat := range resp.GetStat() {
		data := stat.GetName()
		value := stat.GetValue()

		// Extract the type from the name (e.g., "traffic")
		parts := strings.Split(data, ">>>")
		link := parts[len(parts)]

		if link == Downlink.String() {
			stats.Downlink = value
		} else if link == Uplink.String() {
			stats.Uplink = value
		}
	}
	stats.Email = email

	return &stats, nil
}

func (x *XrayHandler) GetInboundStats(ctx context.Context, tag string, reset bool) (*StatsResponse, error) {
	resp, err := x.QueryStats(ctx, fmt.Sprintf("inbound>>>%s>>>", tag), reset)
	if err != nil {
		return nil, err
	}

	var stats StatsResponse

	for _, stat := range resp.GetStat() {
		data := stat.GetName()
		value := stat.GetValue()

		// Extract the type from the name (e.g., "traffic")
		parts := strings.Split(data, ">>>")
		link := parts[len(parts)]

		if link == Downlink.String() {
			stats.Downlink = value
		} else if link == Uplink.String() {
			stats.Uplink = value
		}
	}
	stats.Tag = tag

	return &stats, nil
}

func (x *XrayHandler) GetOutboundStats(ctx context.Context, tag string, reset bool) (*StatsResponse, error) {
	resp, err := x.QueryStats(ctx, fmt.Sprintf("outbound>>>%s>>>", tag), reset)
	if err != nil {
		return nil, err
	}

	var stats StatsResponse

	for _, stat := range resp.GetStat() {
		data := stat.GetName()
		value := stat.GetValue()

		// Extract the type from the name (e.g., "traffic")
		parts := strings.Split(data, ">>>")
		link := parts[len(parts)]

		if link == Downlink.String() {
			stats.Downlink = value
		} else if link == Uplink.String() {
			stats.Uplink = value
		}
	}
	stats.Tag = tag

	return &stats, nil
}
