package singbox

import (
	"context"
	"fmt"
	"strings"

	"github.com/xtls/xray-core/app/stats/command"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/pasarguard/node/common"
)

// sing-box registers the Xray-compatible StatsService under the original v2ray
// path (experimental/v2rayapi/stats.go overrides ServiceName); xray-core uses
// /xray.app.../ so the generated xray client cannot be reused as-is. Message
// types are wire-identical (pattern=1, reset=2, Stat name=1 value=2).
const statsServicePath = "/v2ray.core.app.stats.command.StatsService/"

const maxStatsMessageSize = 64 * 1024 * 1024

// statsClient talks to sing-box experimental.v2ray_api (requires a build with
// -tags with_v2ray_api).
type statsClient struct {
	conn *grpc.ClientConn
}

func newStatsClient(port int) (*statsClient, error) {
	target := fmt.Sprintf("127.0.0.1:%d", port)
	conn, err := grpc.NewClient(target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(maxStatsMessageSize),
			grpc.MaxCallSendMsgSize(maxStatsMessageSize),
		),
	)
	if err != nil {
		return nil, err
	}
	return &statsClient{conn: conn}, nil
}

func (s *statsClient) Close() error {
	if s == nil || s.conn == nil {
		return nil
	}
	return s.conn.Close()
}

// buildStatsQuery carries both filter spellings — see common/stats_query.proto.
// sing-box matches Patterns with strings.Contains; an empty filter means "all",
// which must never be sent with reset=true against a shared core.
func buildStatsQuery(pattern string, reset bool) *common.QueryStatsRequest {
	req := &common.QueryStatsRequest{Pattern: pattern, Reset_: reset}
	if pattern != "" {
		req.Patterns = []string{pattern}
	}
	return req
}

func (s *statsClient) queryStats(ctx context.Context, pattern string, reset bool) ([]*command.Stat, error) {
	req := buildStatsQuery(pattern, reset)
	resp := &command.QueryStatsResponse{}
	if err := s.conn.Invoke(ctx, statsServicePath+"QueryStats", req, resp); err != nil {
		return nil, err
	}
	return resp.GetStat(), nil
}

func (s *statsClient) sysStats(ctx context.Context) (*command.SysStatsResponse, error) {
	req := &command.SysStatsRequest{}
	resp := &command.SysStatsResponse{}
	if err := s.conn.Invoke(ctx, statsServicePath+"GetSysStats", req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// buildStatResponse converts raw counters into the panel-facing shape:
// "user>>>{uid}>>>traffic>>>{uplink}" -> Stat{Name: uid, Link: traffic, Type: uplink}.
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
