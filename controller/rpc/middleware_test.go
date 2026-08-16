package rpc

import "testing"

func TestRoutingMethodsAreBackendGated(t *testing.T) {
	methods := []string{
		"/service.NodeService/ListRoutingRules",
		"/service.NodeService/GetBalancerInfo",
		"/service.NodeService/TestRoute",
		"/service.NodeService/AddRoutingRule",
		"/service.NodeService/RemoveRoutingRule",
		"/service.NodeService/OverrideBalancerTarget",
	}
	for _, m := range methods {
		if !backendMethods[m] {
			t.Errorf("%s missing from backendMethods (skips backend-started gating)", m)
		}
	}
}
