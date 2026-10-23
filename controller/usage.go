package controller

import (
	"context"

	"github.com/pasarguard/node/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type usageBackend interface {
	UsageSnapshot(context.Context, common.StatType) (string, *common.StatResponse, error)
}

func (c *Controller) CollectUsage(ctx context.Context, request *common.UsageRequest) (*common.UsageReceipt, error) {
	if c.usageStore == nil {
		return nil, status.Error(codes.FailedPrecondition, "usage journal unavailable")
	}
	// Replay does not require a running core. Only a new snapshot enters this
	// callback. A durable pending receipt remains retrievable after core failure.
	return c.usageStore.Collect(ctx, request.GetType(), func(ctx context.Context) (string, *common.StatResponse, error) {
		c.controlMu.Lock()
		defer c.controlMu.Unlock()
		back, ok := c.Backend().(usageBackend)
		if !ok {
			return "", nil, status.Error(codes.Unavailable, "backend does not support cumulative usage snapshots")
		}
		return back.UsageSnapshot(ctx, request.GetType())
	})
}

func (c *Controller) AcknowledgeUsage(ctx context.Context, request *common.UsageAck) (*common.Empty, error) {
	if c.usageStore == nil {
		return nil, status.Error(codes.FailedPrecondition, "usage journal unavailable")
	}
	if err := c.usageStore.Acknowledge(ctx, request.GetType(), request.GetReceiptId()); err != nil {
		return nil, err
	}
	return &common.Empty{}, nil
}

// GetStats preserves the legacy API until receipt accounting is activated.
func (c *Controller) GetStats(ctx context.Context, request *common.StatRequest) (*common.StatResponse, error) {
	read := func() (*common.StatResponse, error) {
		back := c.Backend()
		if back == nil {
			return nil, status.Error(codes.Unavailable, "backend not initialized")
		}
		return back.GetStats(ctx, request)
	}
	if !request.GetReset_() {
		return read()
	}
	kind := request.GetType()
	switch kind {
	case common.StatType_UserStat:
		kind = common.StatType_UsersStat
	case common.StatType_Outbound:
		kind = common.StatType_Outbounds
	case common.StatType_Inbound, common.StatType_Inbounds:
		return read()
	}
	if c.usageStore == nil {
		return nil, status.Error(codes.FailedPrecondition, "usage journal unavailable")
	}
	return c.usageStore.LegacyReset(kind, read)
}
