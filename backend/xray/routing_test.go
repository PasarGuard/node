package xray

import (
	"context"
	"testing"

	"github.com/pasarguard/node/common"
)

// TestRoutingMethodsErrorWhenNotStarted verifies every RoutingBackend method on
// *Xray goes through the routingHandler() guard and errors (rather than panics)
// when the core is not started / the handler is nil.
func TestRoutingMethodsErrorWhenNotStarted(t *testing.T) {
	x := &Xray{} // core nil, handler nil => not started
	ctx := context.Background()

	if _, err := x.ListRoutingRules(ctx); err == nil {
		t.Fatal("ListRoutingRules: expected error when not started")
	}
	if _, err := x.GetBalancerInfo(ctx, "b"); err == nil {
		t.Fatal("GetBalancerInfo: expected error when not started")
	}
	if _, err := x.TestRoute(ctx, &common.TestRouteRequest{}); err == nil {
		t.Fatal("TestRoute: expected error when not started")
	}
	if err := x.AddRoutingRule(ctx, "{}", false); err == nil {
		t.Fatal("AddRoutingRule: expected error when not started")
	}
	if err := x.RemoveRoutingRule(ctx, "r"); err == nil {
		t.Fatal("RemoveRoutingRule: expected error when not started")
	}
	if err := x.OverrideBalancerTarget(ctx, "b", "t"); err == nil {
		t.Fatal("OverrideBalancerTarget: expected error when not started")
	}
}
