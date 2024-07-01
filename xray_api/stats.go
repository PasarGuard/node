package xray_api

import (
	"context"
	"fmt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"marzban-node/xray_api/proto/app/stats/command"
	"strings"
)

type LinkType string

const (
	Downlink LinkType = "downlink"
	Uplink   LinkType = "uplink"
)

type SysStatsResponse struct {
	NumGoroutine uint32 `json:"NumGoroutine,omitempty"`
	NumGC        uint32 `json:"NumGC,omitempty"`
	Alloc        uint64 `json:"Alloc,omitempty"`
	TotalAlloc   uint64 `json:"TotalAlloc,omitempty"`
	Sys          uint64 `json:"Sys,omitempty"`
	Mallocs      uint64 `json:"Mallocs,omitempty"`
	Frees        uint64 `json:"Frees,omitempty"`
	LiveObjects  uint64 `json:"LiveObjects,omitempty"`
	PauseTotalNs uint64 `json:"PauseTotalNs,omitempty"`
	Uptime       uint32 `json:"Uptime,omitempty"`
}

func (l LinkType) String() string {
	return string(l)
}

type StatResponse struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Link  string `json:"link"`
	Value int64  `json:"value"`
}

type UserStatsResponse struct {
	Email    string `json:"email"`
	Uplink   int64  `json:"uplink"`
	Downlink int64  `json:"downlink"`
}

type InboundStatsResponse struct {
	Tag      string `json:"tag"`
	Uplink   int64  `json:"uplink"`
	Downlink int64  `json:"downlink"`
}

type OutboundStatsResponse struct {
	Tag      string `json:"tag"`
	Uplink   int64  `json:"uplink"`
	Downlink int64  `json:"downlink"`
}

func (x *XrayAPI) GetSysStats(ctx context.Context) (*SysStatsResponse, error) {
	client := *x.StatsServiceClient
	resp, err := client.GetSysStats(ctx, &command.SysStatsRequest{})
	if err != nil {
		return nil, status.Errorf(codes.Unknown, "failed to get sys stats: %v", err)
	}

	return &SysStatsResponse{
		NumGoroutine: resp.NumGoroutine,
		NumGC:        resp.NumGC,
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

func (x *XrayAPI) QueryStats(ctx context.Context, pattern string, reset bool) (*command.QueryStatsResponse, error) {
	client := *x.StatsServiceClient
	resp, err := client.QueryStats(ctx, &command.QueryStatsRequest{Pattern: pattern, Reset_: reset})
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (x *XrayAPI) GetUsersStats(ctx context.Context, reset bool) ([]StatResponse, error) {
	resp, err := x.QueryStats(ctx, fmt.Sprintf("user>>>"), reset)
	if err != nil {
		return nil, err
	}

	var stats []StatResponse
	for _, stat := range resp.GetStat() {
		data := stat.GetName()
		value := stat.GetValue()

		// Extract the type from the name (e.g., "traffic")
		parts := strings.Split(data, ">>>")
		name := parts[1]
		link := parts[2]
		statType := parts[3]

		// Create a new StatResponse object and add it to the slice
		stats = append(stats, StatResponse{
			Name:  name,
			Type:  statType,
			Link:  link,
			Value: value,
		})
	}

	return stats, nil
}

func (x *XrayAPI) GetInboundsStats(ctx context.Context, reset bool) ([]StatResponse, error) {
	resp, err := x.QueryStats(ctx, fmt.Sprintf("inbound>>>"), reset)
	if err != nil {
		return nil, err
	}

	var stats []StatResponse
	for _, stat := range resp.GetStat() {
		data := stat.GetName()
		value := stat.GetValue()

		// Extract the type from the name (e.g., "traffic")
		parts := strings.Split(data, ">>>")
		name := parts[1]
		link := parts[2]
		statType := parts[3]

		// Create a new StatResponse object and add it to the slice
		stats = append(stats, StatResponse{
			Name:  name,
			Type:  statType,
			Link:  link,
			Value: value,
		})
	}

	return stats, nil
}

func (x *XrayAPI) GetOutboundsStats(ctx context.Context, reset bool) ([]StatResponse, error) {
	resp, err := x.QueryStats(ctx, fmt.Sprintf("outbound>>>"), reset)
	if err != nil {
		return nil, err
	}

	var stats []StatResponse
	for _, stat := range resp.GetStat() {
		data := stat.GetName()
		value := stat.GetValue()

		parts := strings.Split(data, ">>>")
		name := parts[1]
		statType := parts[2]
		link := parts[3]

		// Create a new StatResponse object and add it to the slice
		stats = append(stats, StatResponse{
			Name:  name,
			Type:  statType,
			Link:  link,
			Value: value,
		})
	}

	return stats, nil
}

func (x *XrayAPI) GetUserStats(ctx context.Context, email string, reset bool) (*UserStatsResponse, error) {
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

func (x *XrayAPI) GetInboundStats(ctx context.Context, tag string, reset bool) (*InboundStatsResponse, error) {
	resp, err := x.QueryStats(ctx, fmt.Sprintf("inbound>>>%s>>>", tag), reset)
	if err != nil {
		return nil, err
	}

	var stats InboundStatsResponse

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

func (x *XrayAPI) GetOutboundStats(ctx context.Context, tag string, reset bool) (*OutboundStatsResponse, error) {
	resp, err := x.QueryStats(ctx, fmt.Sprintf("outbound>>>%s>>>", tag), reset)
	if err != nil {
		return nil, err
	}

	var stats OutboundStatsResponse

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
