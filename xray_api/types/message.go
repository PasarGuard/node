package types

import (
	"google.golang.org/protobuf/proto"

	"marzban-node/xray_api/proto/common/serial"
)

func ToTypedMessage(account proto.Message) (*serial.TypedMessage, error) {
	data, err := proto.Marshal(account)
	if err != nil {
		return nil, err
	}
	return &serial.TypedMessage{
		Type:  string(proto.MessageName(account)),
		Value: data,
	}, nil
}
