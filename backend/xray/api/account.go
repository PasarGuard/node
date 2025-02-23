package api

import (
	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vmess"

	"github.com/m03ed/gozargah-node/common"
)

type Account interface {
	GetEmail() string
	GetLevel() uint32
	Message() (*serial.TypedMessage, error)
}

type BaseAccount struct {
	Email string `json:"email"`
	Level uint32 `json:"level"`
}

func (ba *BaseAccount) GetEmail() string {
	return ba.Email
}

func (ba *BaseAccount) GetLevel() uint32 {
	return ba.Level
}

type VmessAccount struct {
	BaseAccount
	ID uuid.UUID `json:"id"`
}

func (va *VmessAccount) Message() (*serial.TypedMessage, error) {
	return ToTypedMessage(&vmess.Account{Id: va.ID.String()})
}

func NewVmessAccount(user *common.User) (*VmessAccount, error) {
	id, err := uuid.Parse(user.GetProxies().GetVmess().GetId())
	if err != nil {
		return nil, err
	}
	return &VmessAccount{
		BaseAccount: BaseAccount{
			Email: user.GetEmail(),
			Level: 0,
		},
		ID: id,
	}, nil
}

type VlessAccount struct {
	BaseAccount
	ID   uuid.UUID `json:"id"`
	Flow string    `json:"flow"`
}

func (va *VlessAccount) Message() (*serial.TypedMessage, error) {
	return ToTypedMessage(&vless.Account{Id: va.ID.String(), Flow: va.Flow})
}

func NewVlessAccount(user *common.User) (*VlessAccount, error) {
	id, err := uuid.Parse(user.GetProxies().GetVless().GetId())
	if err != nil {
		return nil, err
	}
	return &VlessAccount{
		BaseAccount: BaseAccount{
			Email: user.GetEmail(),
			Level: 0,
		},
		ID:   id,
		Flow: user.GetProxies().GetVless().GetFlow(),
	}, nil
}

type TrojanAccount struct {
	BaseAccount
	Password string `json:"password"`
}

func (ta *TrojanAccount) Message() (*serial.TypedMessage, error) {
	return ToTypedMessage(&trojan.Account{Password: ta.Password})
}

func NewTrojanAccount(user *common.User) *TrojanAccount {
	return &TrojanAccount{
		BaseAccount: BaseAccount{
			Email: user.GetEmail(),
			Level: 0,
		},
		Password: user.GetProxies().GetTrojan().GetPassword(),
	}
}

type CipherType int32

const (
	CipherType_AES_128_GCM        CipherType = 5
	CipherType_AES_256_GCM        CipherType = 6
	CipherType_CHACHA20_POLY1305  CipherType = 7
	CipherType_XCHACHA20_POLY1305 CipherType = 8
	CipherType_NONE               CipherType = 9
)

// Enum value maps for CipherType.
var (
	CipherType_name = map[int32]string{
		5: "aes-128-gcm",
		6: "aes-256-gcm",
		7: "chacha20-poly1305",
		8: "xchacha20-poly1305",
		9: "none",
	}
	CipherType_value = map[string]int32{
		"aes-128-gcm":        5,
		"aes-256-gcm":        6,
		"chacha20-poly1305":  7,
		"xchacha20-poly1305": 8,
		"none":               9,
	}
)

type ShadowsocksAccount struct {
	BaseAccount
	Password string `json:"password"`
}

func (sa *ShadowsocksAccount) Message() (*serial.TypedMessage, error) {
	return ToTypedMessage(&shadowsocks_2022.Account{Key: sa.Password})
}

func NewShadowsocksAccount(user *common.User) *ShadowsocksAccount {
	return &ShadowsocksAccount{
		BaseAccount: BaseAccount{
			Email: user.GetEmail(),
			Level: 0,
		},
		Password: user.GetProxies().GetShadowsocks().GetPassword(),
	}
}

type ShadowsocksTcpAccount struct {
	ShadowsocksAccount
	Method string `json:"method"`
}

func (sa *ShadowsocksTcpAccount) CipherType() string {
	return sa.Method
}

func (sa *ShadowsocksTcpAccount) Message() (*serial.TypedMessage, error) {
	return ToTypedMessage(&shadowsocks.Account{Password: sa.Password, CipherType: shadowsocks.CipherType(CipherType_value[sa.Method])})
}

func NewShadowsocksTcpAccount(user *common.User) *ShadowsocksTcpAccount {
	method := user.GetProxies().GetShadowsocks().GetMethod()
	if _, ok := CipherType_value[method]; !ok {
		method = CipherType_name[9]
	}

	return &ShadowsocksTcpAccount{
		ShadowsocksAccount: ShadowsocksAccount{
			BaseAccount: BaseAccount{
				Email: user.GetEmail(),
				Level: 0,
			},
			Password: user.GetProxies().GetShadowsocks().GetPassword(),
		},
		Method: method,
	}
}

type ProxySettings struct {
	Vmess           *VmessAccount
	Vless           *VlessAccount
	Trojan          *TrojanAccount
	Shadowsocks     *ShadowsocksTcpAccount
	Shadowsocks2022 *ShadowsocksAccount
}
