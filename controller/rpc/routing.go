package rpc

import (
	"context"

	"github.com/pasarguard/node/backend"
	"github.com/pasarguard/node/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// asRoutingBackend adapts a backend to RoutingBackend, returning Unimplemented
// for backends (e.g. WireGuard) that do not support xray routing. Kept as a free
// function so it is unit-testable without a live controller/backend.
func asRoutingBackend(b backend.Backend) (backend.RoutingBackend, error) {
	rb, ok := b.(backend.RoutingBackend)
	if !ok {
		return nil, status.Errorf(codes.Unimplemented, "routing is only supported by the xray backend")
	}
	return rb, nil
}

func (s *Service) routingBackend() (backend.RoutingBackend, error) {
	b, err := s.backend()
	if err != nil {
		return nil, err
	}
	return asRoutingBackend(b)
}

func (s *Service) ListRoutingRules(ctx context.Context, _ *common.Empty) (*common.RoutingRulesResponse, error) {
	rb, err := s.routingBackend()
	if err != nil {
		return nil, err
	}
	resp, err := rb.ListRoutingRules(ctx)
	if err != nil {
		return nil, common.InterceptNotFound(err)
	}
	return resp, nil
}

func (s *Service) GetBalancerInfo(ctx context.Context, request *common.BalancerInfoRequest) (*common.BalancerInfoResponse, error) {
	rb, err := s.routingBackend()
	if err != nil {
		return nil, err
	}
	resp, err := rb.GetBalancerInfo(ctx, request.GetTag())
	if err != nil {
		return nil, common.InterceptNotFound(err)
	}
	return resp, nil
}

func (s *Service) TestRoute(ctx context.Context, request *common.TestRouteRequest) (*common.RouteResult, error) {
	rb, err := s.routingBackend()
	if err != nil {
		return nil, err
	}
	resp, err := rb.TestRoute(ctx, request)
	if err != nil {
		return nil, common.InterceptNotFound(err)
	}
	return resp, nil
}

func (s *Service) AddRoutingRule(ctx context.Context, request *common.AddRoutingRuleRequest) (*common.Empty, error) {
	rb, err := s.routingBackend()
	if err != nil {
		return nil, err
	}
	if err := rb.AddRoutingRule(ctx, request.GetRule(), !request.GetShouldReset()); err != nil {
		return nil, err
	}
	return &common.Empty{}, nil
}

func (s *Service) RemoveRoutingRule(ctx context.Context, request *common.RemoveRoutingRuleRequest) (*common.Empty, error) {
	rb, err := s.routingBackend()
	if err != nil {
		return nil, err
	}
	if err := rb.RemoveRoutingRule(ctx, request.GetRuleTag()); err != nil {
		return nil, common.InterceptNotFound(err)
	}
	return &common.Empty{}, nil
}

func (s *Service) OverrideBalancerTarget(ctx context.Context, request *common.OverrideBalancerTargetRequest) (*common.Empty, error) {
	rb, err := s.routingBackend()
	if err != nil {
		return nil, err
	}
	if err := rb.OverrideBalancerTarget(ctx, request.GetBalancerTag(), request.GetTarget()); err != nil {
		return nil, common.InterceptNotFound(err)
	}
	return &common.Empty{}, nil
}
