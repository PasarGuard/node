package rpc

import (
	"context"
	"log"
	"net"

	"github.com/pasarguard/node/common"
	"google.golang.org/grpc/peer"
)

func (s *Service) Start(ctx context.Context, data *common.Backend) (*common.BaseInfoResponse, error) {
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

	if s.Backend() != nil {
		log.Println("New connection from ", clientIP, " core control access was taken away from previous client.")
		s.Disconnect()
	}

	if err := s.StartBackend(ctx, data); err != nil {
		return nil, err
	}

	s.Connect(clientIP, data.GetKeepAlive())

	return s.BaseInfoResponse(), nil
}

func (s *Service) Stop(_ context.Context, _ *common.Empty) (*common.Empty, error) {
	s.Disconnect()
	return nil, nil
}

func (s *Service) GetBaseInfo(_ context.Context, _ *common.Empty) (*common.BaseInfoResponse, error) {
	return s.BaseInfoResponse(), nil
}
