package controller

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/pasarguard/node/config"
)

func TestConnectCancelsPreviousStatsCollector(t *testing.T) {
	c := New(config.NewTestConfig(t.TempDir(), uuid.New()))
	t.Cleanup(c.Disconnect)

	ctx, cancel := context.WithCancel(context.Background())
	c.cancelFunc = cancel

	c.Connect(0)

	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("Connect did not cancel the previous stats collector")
	}
}
