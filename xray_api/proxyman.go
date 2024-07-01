package xray_api

import (
	"context"
	"marzban-node/xray_api/proto/app/proxyman/command"
	"marzban-node/xray_api/proto/common/protocol"
	"marzban-node/xray_api/proto/common/serial"
	"marzban-node/xray_api/types"
)

func (x *XrayAPI) AlertInbound(ctx context.Context, tag string, operation *serial.TypedMessage) error {
	client := *x.HandlerServiceClient
	_, err := client.AlterInbound(ctx, &command.AlterInboundRequest{Tag: tag, Operation: operation})
	if err != nil {
		return err
	}
	return nil
}

func (x *XrayAPI) AlertOutbound(ctx context.Context, tag string, operation *serial.TypedMessage) error {
	client := *x.HandlerServiceClient
	_, err := client.AlterOutbound(ctx, &command.AlterOutboundRequest{Tag: tag, Operation: operation})
	if err != nil {
		return err
	}
	return nil
}

func (x *XrayAPI) AddInboundUser(ctx context.Context, tag string, user types.Account) error {
	// Create the AddUserOperation message
	account, err := user.Message()
	if err != nil {
		return err
	}
	operation, err := types.ToTypedMessage(&command.AddUserOperation{
		User: &protocol.User{
			Level:   user.GetLevel(),
			Email:   user.GetEmail(),
			Account: account,
		},
	})
	if err != nil {
		return err
	}

	// Call the AlterInbound method with the AddUserOperation message
	return x.AlertInbound(ctx, tag, operation)
}

func (x *XrayAPI) RemoveInboundUser(ctx context.Context, tag, email string) error {
	operation, err := types.ToTypedMessage(&command.RemoveUserOperation{
		Email: email,
	})
	if err != nil {
		return err
	}

	// Call the AlterInbound method with the AddUserOperation message
	return x.AlertInbound(ctx, tag, operation)
}

func (x *XrayAPI) AddOutboundUser(ctx context.Context, tag string, user types.Account) error {
	// Create the AddUserOperation message
	account, err := user.Message()
	if err != nil {
		return err
	}
	operation, err := types.ToTypedMessage(&command.AddUserOperation{
		User: &protocol.User{
			Level:   user.GetLevel(),
			Email:   user.GetEmail(),
			Account: account,
		},
	})
	if err != nil {
		return err
	}

	// Call the AlterInbound method with the AddUserOperation message
	return x.AlertOutbound(ctx, tag, operation)
}

func (x *XrayAPI) RemoveOutboundUser(ctx context.Context, tag, email string) error {
	operation, err := types.ToTypedMessage(&command.RemoveUserOperation{
		Email: email,
	})
	if err != nil {
		return err
	}

	// Call the AlterInbound method with the AddUserOperation message
	return x.AlertOutbound(ctx, tag, operation)
}
