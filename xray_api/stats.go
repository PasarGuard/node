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

func (l LinkType) String() string {
	return string(l)
}

type StatResponse struct {
	Name  string
	Type  string
	Link  string
	Value int64
}

type UserStatsResponse struct {
	Email    string
	Uplink   int64
	Downlink int64
}

type InboundStatsResponse struct {
	Tag      string
	Uplink   int64
	Downlink int64
}

type OutboundStatsResponse struct {
	Tag      string
	Uplink   int64
	Downlink int64
}

func (x *XrayClient) GetSysStats(ctx context.Context) (*command.SysStatsResponse, error) {
	client := command.NewStatsServiceClient(x.channel)
	resp, err := client.GetSysStats(ctx, &command.SysStatsRequest{})
	if err != nil {
		return nil, status.Errorf(codes.Unknown, "failed to get sys stats: %v", err)
	}

	return resp, nil
}

func (x *XrayClient) QueryStats(ctx context.Context, pattern string, reset bool) (*command.QueryStatsResponse, error) {
	client := command.NewStatsServiceClient(x.channel)
	resp, err := client.QueryStats(ctx, &command.QueryStatsRequest{Pattern: pattern, Reset_: reset})
	if err != nil {
		return nil, status.Errorf(codes.Unknown, "failed to get sys stats: %v", err)
	}

	return resp, nil
}

func (x *XrayClient) GetUsersStats(ctx context.Context, reset bool) ([]StatResponse, error) {
	resp, err := x.QueryStats(ctx, fmt.Sprintf("user>>>"), reset)
	if err != nil {
		return nil, err
	}

	var stats []StatResponse
	for _, stat := range resp.GetStat() {
		name := stat.GetName()
		value := stat.GetValue()

		// Extract the type from the name (e.g., "traffic")
		parts := strings.Split(name, ">>>")
		link := parts[len(parts)]
		statType := parts[len(parts)-1]

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

func (x *XrayClient) GetInboundsStats(ctx context.Context, reset bool) ([]StatResponse, error) {
	resp, err := x.QueryStats(ctx, fmt.Sprintf("inbound>>>"), reset)
	if err != nil {
		return nil, err
	}

	var stats []StatResponse
	for _, stat := range resp.GetStat() {
		name := stat.GetName()
		value := stat.GetValue()

		// Extract the type from the name (e.g., "traffic")
		parts := strings.Split(name, ">>>")
		link := parts[len(parts)]
		statType := parts[len(parts)-1]

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

func (x *XrayClient) GetOutboundsStats(ctx context.Context, reset bool) ([]StatResponse, error) {
	resp, err := x.QueryStats(ctx, fmt.Sprintf("outbound>>>"), reset)
	if err != nil {
		return nil, err
	}

	var stats []StatResponse
	for _, stat := range resp.GetStat() {
		name := stat.GetName()
		value := stat.GetValue()

		// Extract the type from the name (e.g., "traffic")
		parts := strings.Split(name, ">>>")
		link := parts[len(parts)]
		statType := parts[len(parts)-1]

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

func (x *XrayClient) GetUserStats(ctx context.Context, email string, reset bool) (*UserStatsResponse, error) {
	resp, err := x.QueryStats(ctx, fmt.Sprintf("user>>>%s>>>", email), reset)
	if err != nil {
		return nil, err
	}

	var stats UserStatsResponse

	for _, stat := range resp.GetStat() {
		name := stat.GetName()
		value := stat.GetValue()

		// Extract the type from the name (e.g., "traffic")
		parts := strings.Split(name, ">>>")
		link := parts[len(parts)]

		if link == Downlink.String() {
			stats.Downlink = value
		} else if link == Uplink.String() {
			stats.Uplink = value
		}
	}

	return &stats, nil
}

func (x *XrayClient) GetInboundStats(ctx context.Context, tag string, reset bool) (*InboundStatsResponse, error) {
	resp, err := x.QueryStats(ctx, fmt.Sprintf("inbound>>>%s>>>", tag), reset)
	if err != nil {
		return nil, err
	}

	var stats InboundStatsResponse

	for _, stat := range resp.GetStat() {
		name := stat.GetName()
		value := stat.GetValue()

		// Extract the type from the name (e.g., "traffic")
		parts := strings.Split(name, ">>>")
		link := parts[len(parts)]

		if link == Downlink.String() {
			stats.Downlink = value
		} else if link == Uplink.String() {
			stats.Uplink = value
		}
	}

	return &stats, nil
}

func (x *XrayClient) GetOutboundStats(ctx context.Context, tag string, reset bool) (*OutboundStatsResponse, error) {
	resp, err := x.QueryStats(ctx, fmt.Sprintf("outbound>>>%s>>>", tag), reset)
	if err != nil {
		return nil, err
	}

	var stats OutboundStatsResponse

	for _, stat := range resp.GetStat() {
		name := stat.GetName()
		value := stat.GetValue()

		// Extract the type from the name (e.g., "traffic")
		parts := strings.Split(name, ">>>")
		link := parts[len(parts)]

		if link == Downlink.String() {
			stats.Downlink = value
		} else if link == Uplink.String() {
			stats.Uplink = value
		}
	}

	return &stats, nil
}
