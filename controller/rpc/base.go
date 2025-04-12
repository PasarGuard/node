package rpc

import (
	"context"
	"errors"
	"log"
	"net"

	"github.com/m03ed/gozargah-node/backend"
	"github.com/m03ed/gozargah-node/backend/xray"
	"github.com/m03ed/gozargah-node/common"
	"google.golang.org/grpc/peer"
)

func (s *Service) Start(ctx context.Context, detail *common.Backend) (*common.BaseInfoResponse, error) {
	ctx, err := s.detectBackend(ctx, detail)
	if err != nil {
		return nil, err
	}

	clientIP := ""
	if p, ok := peer.FromContext(ctx); ok {
		// Extract IP address from peer address
		if tcpAddr, ok := p.Addr.(*net.TCPAddr); ok {
			clientIP = tcpAddr.IP.String()
		} else {
			// For other address types, extract just the IP without the port
			addr := p.Addr.String()
			if host, _, err := net.SplitHostPort(addr); err == nil {
				clientIP = host
			} else {
				// If SplitHostPort fails, use the whole address
				clientIP = addr
			}
		}
	}

	if s.GetBackend() != nil {
		log.Println("New connection from ", clientIP, " core control access was taken away from previous client.")
		s.Disconnect()
	}

	if err = s.StartBackend(ctx, detail.GetType()); err != nil {
		return nil, err
	}

	s.Connect(clientIP, detail.GetKeepAlive())

	return s.BaseInfoResponse(), nil
}

func (s *Service) Stop(_ context.Context, _ *common.Empty) (*common.Empty, error) {
	s.Disconnect()
	return nil, nil
}

func (s *Service) detectBackend(ctx context.Context, detail *common.Backend) (context.Context, error) {
	if detail.GetType() == common.BackendType_XRAY {
		config, err := xray.NewXRayConfig(detail.GetConfig())
		if err != nil {
			return nil, err
		}
		ctx = context.WithValue(ctx, backend.ConfigKey{}, config)
	} else {
		return nil, errors.New("unknown backend type")
	}

	ctx = context.WithValue(ctx, backend.UsersKey{}, detail.GetUsers())

	return ctx, nil
}

func (s *Service) GetBaseInfo(_ context.Context, _ *common.Empty) (*common.BaseInfoResponse, error) {
	return s.BaseInfoResponse(), nil
}
