package api

import (
	"context"
	"encoding/json"
	"net"
	"strings"

	"github.com/pasarguard/node/common"
	routingCommand "github.com/xtls/xray-core/app/router/command"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/infra/conf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func toCommonRoutingRules(resp *routingCommand.ListRuleResponse) *common.RoutingRulesResponse {
	out := &common.RoutingRulesResponse{}
	for _, r := range resp.GetRules() {
		out.Rules = append(out.Rules, &common.RoutingRule{
			OutboundTag: r.GetTag(),
			RuleTag:     r.GetRuleTag(),
		})
	}
	return out
}

func toCommonBalancerInfo(resp *routingCommand.GetBalancerInfoResponse) *common.BalancerInfoResponse {
	out := &common.BalancerInfoResponse{}
	if b := resp.GetBalancer(); b != nil {
		if o := b.GetOverride(); o != nil {
			out.OverrideTarget = o.GetTarget()
		}
		if p := b.GetPrincipleTarget(); p != nil {
			out.PrincipleTarget = p.GetTag()
		}
	}
	return out
}

func networkFromString(s string) xnet.Network {
	switch strings.ToLower(s) {
	case "udp":
		return xnet.Network_UDP
	case "tcp":
		return xnet.Network_TCP
	default:
		return xnet.Network_Unknown
	}
}

func buildTestRouteRequest(req *common.TestRouteRequest) *routingCommand.TestRouteRequest {
	rc := &routingCommand.RoutingContext{
		InboundTag:   req.GetInboundTag(),
		Network:      networkFromString(req.GetNetwork()),
		TargetDomain: req.GetTargetDomain(),
		TargetPort:   req.GetTargetPort(),
		Protocol:     req.GetProtocol(),
		User:         req.GetUser(),
		Attributes:   req.GetAttributes(),
	}
	if ip := net.ParseIP(req.GetTargetIp()); ip != nil {
		rc.TargetIPs = [][]byte{ip}
	}
	return &routingCommand.TestRouteRequest{
		RoutingContext: rc,
		FieldSelectors: req.GetFieldSelectors(),
		PublishResult:  req.GetPublishResult(),
	}
}

func toCommonRouteResult(rc *routingCommand.RoutingContext) *common.RouteResult {
	return &common.RouteResult{
		OutboundTag:       rc.GetOutboundTag(),
		OutboundGroupTags: rc.GetOutboundGroupTags(),
		InboundTag:        rc.GetInboundTag(),
		Network:           strings.ToLower(rc.GetNetwork().String()),
		TargetDomain:      rc.GetTargetDomain(),
	}
}

// addRuleConfig parses one routing-rule JSON (same shape as routing.rules[]) into
// the TypedMessage that RoutingService.AddRule expects, using only exported
// xray-core API. xray's Router.AddRule unwraps the message and requires a
// *router.Config (it rejects a bare *router.RoutingRule with "config type
// error"), so the whole built config — carrying the single parsed rule — is sent.
func addRuleConfig(ruleJSON string) (*serial.TypedMessage, error) {
	rc := &conf.RouterConfig{RuleList: []json.RawMessage{json.RawMessage(ruleJSON)}}
	built, err := rc.Build()
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "parse routing rule: %v", err)
	}
	if len(built.Rule) == 0 {
		return nil, status.Error(codes.InvalidArgument, "no routing rule parsed from JSON")
	}
	return serial.ToTypedMessage(built), nil
}

func (x *XrayHandler) ListRoutingRules(ctx context.Context) (*common.RoutingRulesResponse, error) {
	client := *x.RoutingServiceClient
	resp, err := client.ListRule(ctx, &routingCommand.ListRuleRequest{})
	if err != nil {
		return nil, err
	}
	return toCommonRoutingRules(resp), nil
}

func (x *XrayHandler) GetBalancerInfo(ctx context.Context, tag string) (*common.BalancerInfoResponse, error) {
	client := *x.RoutingServiceClient
	resp, err := client.GetBalancerInfo(ctx, &routingCommand.GetBalancerInfoRequest{Tag: tag})
	if err != nil {
		return nil, err
	}
	return toCommonBalancerInfo(resp), nil
}

func (x *XrayHandler) TestRoute(ctx context.Context, req *common.TestRouteRequest) (*common.RouteResult, error) {
	client := *x.RoutingServiceClient
	resp, err := client.TestRoute(ctx, buildTestRouteRequest(req))
	if err != nil {
		return nil, err
	}
	return toCommonRouteResult(resp), nil
}

func (x *XrayHandler) AddRoutingRule(ctx context.Context, ruleJSON string, shouldAppend bool) error {
	tm, err := addRuleConfig(ruleJSON)
	if err != nil {
		return err
	}
	client := *x.RoutingServiceClient
	_, err = client.AddRule(ctx, &routingCommand.AddRuleRequest{Config: tm, ShouldAppend: shouldAppend})
	return err
}

func (x *XrayHandler) RemoveRoutingRule(ctx context.Context, ruleTag string) error {
	client := *x.RoutingServiceClient
	_, err := client.RemoveRule(ctx, &routingCommand.RemoveRuleRequest{RuleTag: ruleTag})
	return err
}

func (x *XrayHandler) OverrideBalancerTarget(ctx context.Context, balancerTag, target string) error {
	client := *x.RoutingServiceClient
	_, err := client.OverrideBalancerTarget(ctx, &routingCommand.OverrideBalancerTargetRequest{
		BalancerTag: balancerTag,
		Target:      target,
	})
	return err
}
