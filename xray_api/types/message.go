package types

import (
	"github.com/golang/protobuf/proto"

	"marzban-node/xray_api/proto/common/serial"
)

func ToTypedMessage(account proto.Message) (*serial.TypedMessage, error) {
	data, err := proto.Marshal(account)
	if err != nil {
		return nil, err
	}
	return &serial.TypedMessage{
		Type:  proto.MessageName(account),
		Value: data,
	}, nil
}
