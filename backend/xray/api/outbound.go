package api

import (
	"context"

	"github.com/xtls/xray-core/app/proxyman/command"
	routingCommand "github.com/xtls/xray-core/app/router/command"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
)

func (x *XrayHandler) AddOutbound(ctx context.Context, outbound *core.OutboundHandlerConfig) error {
	client := *x.HandlerServiceClient
	_, err := client.AddOutbound(ctx, &command.AddOutboundRequest{Outbound: outbound})
	return err
}

func (x *XrayHandler) RemoveOutbound(ctx context.Context, tag string) error {
	client := *x.HandlerServiceClient
	_, err := client.RemoveOutbound(ctx, &command.RemoveOutboundRequest{Tag: tag})
	return err
}

// ReplaceRouting swaps all routing rules and balancers for those in config, a
// router.Config message. Open connections keep the outbound they already have.
func (x *XrayHandler) ReplaceRouting(ctx context.Context, config *serial.TypedMessage) error {
	client := *x.RoutingServiceClient
	_, err := client.AddRule(ctx, &routingCommand.AddRuleRequest{Config: config, ShouldAppend: false})
	return err
}
