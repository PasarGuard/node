package api

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/xtls/xray-core/app/proxyman/command"
	statsService "github.com/xtls/xray-core/app/stats/command"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type XrayHandler struct {
	HandlerServiceClient *command.HandlerServiceClient
	StatsServiceClient   *statsService.StatsServiceClient
	GrpcClient           *grpc.ClientConn
}

const maxGRPCMessageSize = 64 * 1024 * 1024 // 64MB

func NewXrayAPI(apiPort int) (*XrayHandler, error) {
	x := &XrayHandler{}
	target := fmt.Sprintf("127.0.0.1:%v", apiPort)
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1")},
	}

	var err error
	x.GrpcClient, err = grpc.NewClient(
		target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(maxGRPCMessageSize),
			grpc.MaxCallSendMsgSize(maxGRPCMessageSize),
		),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			conn, dialErr := dialer.DialContext(ctx, "tcp4", addr)
			if dialErr == nil {
				return conn, nil
			}

			var fallback net.Dialer
			return fallback.DialContext(ctx, "tcp", addr)
		}),
	)

	if err != nil {
		return nil, err
	}

	hsClient := command.NewHandlerServiceClient(x.GrpcClient)
	ssClient := statsService.NewStatsServiceClient(x.GrpcClient)
	x.HandlerServiceClient = &hsClient
	x.StatsServiceClient = &ssClient

	return x, nil
}

func (x *XrayHandler) Close() {
	if x.GrpcClient != nil {
		_ = x.GrpcClient.Close()
	}
	x.StatsServiceClient = nil
	x.HandlerServiceClient = nil
}
