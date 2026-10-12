package xray

import (
	"context"
	"errors"

	"github.com/pasarguard/node/backend"
	"github.com/pasarguard/node/common"
)

// var _ asserts at compile time that *Xray satisfies backend.RoutingBackend.
var _ backend.RoutingBackend = (*Xray)(nil)

// handler is the subset of *api.XrayHandler that routing delegates to. Using a
// local interface keeps this file self-documenting (*api.XrayHandler satisfies it).
type handler interface {
	ListRoutingRules(context.Context) (*common.RoutingRulesResponse, error)
	GetBalancerInfo(context.Context, string) (*common.BalancerInfoResponse, error)
	TestRoute(context.Context, *common.TestRouteRequest) (*common.RouteResult, error)
	AddRoutingRule(context.Context, string, bool) error
	RemoveRoutingRule(context.Context, string) error
	OverrideBalancerTarget(context.Context, string, string) error
}

func (x *Xray) routingHandler() (handler, error) {
	x.mu.RLock()
	h := x.handler
	started := x.core != nil && x.core.Started()
	x.mu.RUnlock()
	if !started || h == nil {
		return nil, errors.New("xray not started")
	}
	return h, nil
}

func (x *Xray) ListRoutingRules(ctx context.Context) (*common.RoutingRulesResponse, error) {
	h, err := x.routingHandler()
	if err != nil {
		return nil, err
	}
	return h.ListRoutingRules(ctx)
}

func (x *Xray) GetBalancerInfo(ctx context.Context, tag string) (*common.BalancerInfoResponse, error) {
	h, err := x.routingHandler()
	if err != nil {
		return nil, err
	}
	return h.GetBalancerInfo(ctx, tag)
}

func (x *Xray) TestRoute(ctx context.Context, req *common.TestRouteRequest) (*common.RouteResult, error) {
	h, err := x.routingHandler()
	if err != nil {
		return nil, err
	}
	return h.TestRoute(ctx, req)
}

func (x *Xray) AddRoutingRule(ctx context.Context, ruleJSON string, shouldAppend bool) error {
	h, err := x.routingHandler()
	if err != nil {
		return err
	}
	return h.AddRoutingRule(ctx, ruleJSON, shouldAppend)
}

func (x *Xray) RemoveRoutingRule(ctx context.Context, ruleTag string) error {
	h, err := x.routingHandler()
	if err != nil {
		return err
	}
	return h.RemoveRoutingRule(ctx, ruleTag)
}

func (x *Xray) OverrideBalancerTarget(ctx context.Context, balancerTag, target string) error {
	h, err := x.routingHandler()
	if err != nil {
		return err
	}
	return h.OverrideBalancerTarget(ctx, balancerTag, target)
}
