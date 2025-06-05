package api

import (
	"fmt"
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

func NewXrayAPI(apiPort int) (*XrayHandler, error) {
	x := &XrayHandler{}

	var err error
	x.GrpcClient, err = grpc.NewClient(fmt.Sprintf("127.0.0.1:%v", apiPort), grpc.WithTransportCredentials(insecure.NewCredentials()))

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
