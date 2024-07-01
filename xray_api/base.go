package xray_api

import (
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type XrayClient struct {
	address string
	port    int
	channel *grpc.ClientConn
}

func NewXrayClient(address string, port int, sslCert, sslTargetName string) (*XrayClient, error) {
	if sslTargetName == "" {
		sslTargetName = "Gozargah"
	}

	x := &XrayClient{
		address: address,
		port:    port,
	}

	creds, err := credentials.NewClientTLSFromFile(sslCert, sslTargetName)
	if err != nil {
		return nil, err
	}
	opts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}

	conn, err := grpc.NewClient(fmt.Sprintf("%s:%d", address, port), opts...)
	if err != nil {
		return nil, err
	}
	x.channel = conn

	return x, nil
}
