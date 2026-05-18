package xray

import (
	"testing"

	"github.com/google/uuid"

	"github.com/pasarguard/node/backend/xray/api"
	"github.com/pasarguard/node/common"
)

func TestAccountForAPIUsesInboundFlowOverrideWhenPresent(t *testing.T) {
	user := &common.User{
		Email: "user@example.com",
		Proxies: &common.Proxy{
			Vless: &common.Vless{
				Id:   uuid.New().String(),
				Flow: "user-flow",
			},
		},
	}

	account, err := api.NewVlessAccount(user)
	if err != nil {
		t.Fatal(err)
	}

	inbound := &Inbound{
		Settings: map[string]any{
			"flow": "inbound-flow",
		},
	}

	apiAccount := accountForAPI(inbound, account)
	vlessAccount, ok := apiAccount.(*api.VlessAccount)
	if !ok {
		t.Fatalf("unexpected account type: %T", apiAccount)
	}
	if vlessAccount.Flow != "inbound-flow" {
		t.Fatalf("unexpected flow: got %q want %q", vlessAccount.Flow, "inbound-flow")
	}
	if account.Flow != "user-flow" {
		t.Fatalf("original account flow was mutated: got %q want %q", account.Flow, "user-flow")
	}
}

func TestAccountForAPIUsesUserFlowWhenInboundFlowEmpty(t *testing.T) {
	user := &common.User{
		Email: "user@example.com",
		Proxies: &common.Proxy{
			Vless: &common.Vless{
				Id:   uuid.New().String(),
				Flow: "user-flow",
			},
		},
	}

	account, err := api.NewVlessAccount(user)
	if err != nil {
		t.Fatal(err)
	}

	inbound := &Inbound{
		Settings: map[string]any{
			"flow": "",
		},
	}

	apiAccount := accountForAPI(inbound, account)
	vlessAccount, ok := apiAccount.(*api.VlessAccount)
	if !ok {
		t.Fatalf("unexpected account type: %T", apiAccount)
	}
	if vlessAccount.Flow != "user-flow" {
		t.Fatalf("unexpected flow: got %q want %q", vlessAccount.Flow, "user-flow")
	}
}

func TestIsActiveInboundKeepsUserFlowForConfigStorage(t *testing.T) {
	user := &common.User{
		Email:    "user@example.com",
		Inbounds: []string{"vless-in"},
		Proxies: &common.Proxy{
			Vless: &common.Vless{
				Id:   uuid.New().String(),
				Flow: "user-flow",
			},
		},
	}

	settings, err := setupUserAccount(user)
	if err != nil {
		t.Fatal(err)
	}

	inbound := &Inbound{
		Tag:      "vless-in",
		Protocol: Vless,
		Settings: map[string]any{
			"flow": "inbound-flow",
		},
	}

	account, ok := isActiveInbound(inbound, user.Inbounds, settings)
	if !ok {
		t.Fatal("expected inbound to be active")
	}
	vlessAccount, ok := account.(*api.VlessAccount)
	if !ok {
		t.Fatalf("unexpected account type: %T", account)
	}
	if vlessAccount.Flow != "user-flow" {
		t.Fatalf("unexpected config flow: got %q want %q", vlessAccount.Flow, "user-flow")
	}
}
