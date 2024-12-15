package api

import (
	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/common/serial"
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
