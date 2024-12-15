package api

import (
	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vmess"
)

type Account interface {
	GetEmail() string
	GetLevel() uint32
	Message() (*serial.TypedMessage, error)
}

type BaseAccount struct {
	Email string
	Level uint32
}

func (ba *BaseAccount) GetEmail() string {
	return ba.Email
}

func (ba *BaseAccount) GetLevel() uint32 {
	return ba.Level
}

type VMessAccount struct {
	BaseAccount
	ID uuid.UUID
}

func (va *VMessAccount) Message() (*serial.TypedMessage, error) {
	return ToTypedMessage(&vmess.Account{Id: va.ID.String()})
}

type XTLSFlows string

const (
	NONE   XTLSFlows = ""
	VISION XTLSFlows = "xtls-rprx-vision"
)

type VLESSAccount struct {
	BaseAccount
	ID   uuid.UUID
	Flow XTLSFlows
}

func (va *VLESSAccount) Message() (*serial.TypedMessage, error) {
	return ToTypedMessage(&vless.Account{Id: va.ID.String(), Flow: string(va.Flow)})
}

type TrojanAccount struct {
	BaseAccount
	Password string
}

func (ta *TrojanAccount) Message() (*serial.TypedMessage, error) {
	return ToTypedMessage(&trojan.Account{Password: ta.Password})
}

type ShadowsocksAccount struct {
	BaseAccount
	Password string
	Method   shadowsocks.CipherType
}

func (sa *ShadowsocksAccount) CipherType() string {
	return string(sa.Method)
}

func (sa *ShadowsocksAccount) Message() (*serial.TypedMessage, error) {
	return ToTypedMessage(&shadowsocks.Account{Password: sa.Password, CipherType: sa.Method})
}

type Shadowsocks2022Account struct {
	BaseAccount
	Key string
}

func (sa *Shadowsocks2022Account) Message() (*serial.TypedMessage, error) {
	return ToTypedMessage(&shadowsocks_2022.Account{Key: sa.Key})
}

type ProxySettings struct {
	Vmess           *VMessAccount
	Vless           *VLESSAccount
	Trojan          *TrojanAccount
	Shadowsocks     *ShadowsocksAccount
	Shadowsocks2022 *Shadowsocks2022Account
}
