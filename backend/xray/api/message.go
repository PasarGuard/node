package api

import (
	"github.com/xtls/xray-core/common/serial"
	"google.golang.org/protobuf/proto"
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
