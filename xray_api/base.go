package xray_api

import (
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"marzban-node/xray_api/proto/app/proxyman/command"
	statsService "marzban-node/xray_api/proto/app/stats/command"
)

type XrayAPI struct {
	HandlerServiceClient *command.HandlerServiceClient
	StatsServiceClient   *statsService.StatsServiceClient
	GrpcClient           *grpc.ClientConn
}

func NewXrayAPI(apiPort int) (*XrayAPI, error) {
	x := &XrayAPI{}

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

func (x *XrayAPI) Close() {
	if x.GrpcClient != nil {
		x.GrpcClient.Close()
	}
	x.StatsServiceClient = nil
	x.HandlerServiceClient = nil
}
