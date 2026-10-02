package api

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/stats/command"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// sing-box (with -tags with_v2ray_api) registers the Xray-compatible StatsService
// under its original v2ray path, not xray-core's renamed one.
const singBoxStatsService = "/v2ray.core.app.stats.command.StatsService/"

// TestV2rayAPIProbe verifies per-user traffic counters from a running sing-box
// build with experimental.v2ray_api. Skipped unless V2API_ADDR=127.0.0.1:PORT.
func TestV2rayAPIProbe(t *testing.T) {
	addr := os.Getenv("V2API_ADDR")
	if addr == "" {
		t.Skip("V2API_ADDR not set")
	}

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp := &command.QueryStatsResponse{}
	req := &command.QueryStatsRequest{Pattern: "user>>>", Reset_: false}
	if err := conn.Invoke(ctx, singBoxStatsService+"QueryStats", req, resp); err != nil {
		t.Fatalf("QueryStats: %v", err)
	}

	t.Logf("sing-box user stats: %+v", resp.GetStat())
	found := false
	for _, s := range resp.GetStat() {
		t.Logf("  %s = %d", s.GetName(), s.GetValue())
		if s.GetName() == "user>>>alice>>>traffic>>>uplink" {
			found = true
			if s.GetValue() <= 0 {
				t.Errorf("uplink counter has no traffic: %d", s.GetValue())
			}
		}
	}
	if !found {
		t.Errorf("no user>>>alice>>>traffic>>>uplink counter; got %d stats", len(resp.GetStat()))
	}
}
