package api

import (
	"testing"

	"github.com/pasarguard/node/common"
	"github.com/xtls/xray-core/app/router"
	routingCommand "github.com/xtls/xray-core/app/router/command"
	xnet "github.com/xtls/xray-core/common/net"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestToCommonRoutingRules(t *testing.T) {
	in := &routingCommand.ListRuleResponse{
		Rules: []*routingCommand.ListRuleItem{
			{Tag: "direct", RuleTag: "r1"},
			{Tag: "proxy", RuleTag: ""},
		},
	}
	got := toCommonRoutingRules(in)
	if len(got.GetRules()) != 2 {
		t.Fatalf("rules len = %d, want 2", len(got.GetRules()))
	}
	if got.Rules[0].GetOutboundTag() != "direct" || got.Rules[0].GetRuleTag() != "r1" {
		t.Fatalf("rule[0] = %+v", got.Rules[0])
	}
}

func TestToCommonBalancerInfo(t *testing.T) {
	in := &routingCommand.GetBalancerInfoResponse{
		Balancer: &routingCommand.BalancerMsg{
			Override:        &routingCommand.OverrideInfo{Target: "out-a"},
			PrincipleTarget: &routingCommand.PrincipleTargetInfo{Tag: []string{"out-a", "out-b"}},
		},
	}
	got := toCommonBalancerInfo(in)
	if got.GetOverrideTarget() != "out-a" {
		t.Fatalf("override = %q, want out-a", got.GetOverrideTarget())
	}
	if len(got.GetPrincipleTarget()) != 2 {
		t.Fatalf("principle len = %d, want 2", len(got.GetPrincipleTarget()))
	}
}

func TestBuildTestRouteRequest(t *testing.T) {
	req := buildTestRouteRequest(&common.TestRouteRequest{
		InboundTag:    "in",
		Network:       "udp",
		TargetIp:      "1.1.1.1",
		TargetDomain:  "example.com",
		TargetPort:    443,
		Protocol:      "tls",
		User:          "u",
		Attributes:    map[string]string{"k": "v"},
		PublishResult: true,
	})
	if req.RoutingContext.Network != xnet.Network_UDP {
		t.Fatalf("network = %v, want UDP", req.RoutingContext.Network)
	}
	if req.RoutingContext.TargetPort != 443 {
		t.Fatalf("port = %d, want 443", req.RoutingContext.TargetPort)
	}
	if len(req.RoutingContext.TargetIPs) != 1 {
		t.Fatalf("targetIPs = %v, want one entry", req.RoutingContext.TargetIPs)
	}
	if !req.PublishResult {
		t.Fatal("publishResult not forwarded")
	}
}

func TestToCommonRouteResult(t *testing.T) {
	rc := &routingCommand.RoutingContext{
		OutboundTag:       "proxy",
		OutboundGroupTags: []string{"g1"},
		InboundTag:        "in",
		Network:           xnet.Network_TCP,
		TargetDomain:      "example.com",
	}
	got := toCommonRouteResult(rc)
	if got.GetOutboundTag() != "proxy" || got.GetNetwork() != "tcp" {
		t.Fatalf("result = %+v", got)
	}
}

func TestAddRuleConfigParsesJSON(t *testing.T) {
	tm, err := addRuleConfig(`{"type":"field","outboundTag":"direct","domain":["example.com"],"ruleTag":"r1"}`)
	if err != nil {
		t.Fatalf("addRuleConfig error: %v", err)
	}
	// xray's Router.AddRule unwraps the message and requires a *router.Config;
	// a bare *router.RoutingRule is rejected with "config type error".
	inst, err := tm.GetInstance()
	if err != nil {
		t.Fatalf("GetInstance error: %v", err)
	}
	if _, ok := inst.(*router.Config); !ok {
		t.Fatalf("typed message instance = %T, want *router.Config", inst)
	}
}

func TestAddRuleConfigRejectsGarbage(t *testing.T) {
	_, err := addRuleConfig(`{not json`)
	if err == nil {
		t.Fatal("expected error for malformed rule JSON")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
	}
}
