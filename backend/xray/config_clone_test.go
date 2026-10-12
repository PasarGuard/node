package xray

import (
	"testing"

	"github.com/google/uuid"

	"github.com/pasarguard/node/backend/xray/api"
)

func TestConfigClonePreservesRuntimeClientsAndExclude(t *testing.T) {
	account := &api.VlessAccount{
		BaseAccount: api.BaseAccount{
			Email: "user@example.com",
			Level: 0,
		},
		ID:   uuid.New(),
		Flow: "xtls-rprx-vision",
	}

	original := &Config{
		InboundConfigs: []*Inbound{
			{
				Tag:      "vless-in",
				Protocol: Vless,
				Settings: map[string]any{
					"clients": []any{"stale serialized clients"},
				},
				exclude: true,
				clients: map[string]api.Account{
					account.GetEmail(): account,
				},
			},
		},
	}

	cloned, err := original.Clone()
	if err != nil {
		t.Fatal(err)
	}

	if cloned == original {
		t.Fatal("expected a distinct config")
	}
	if len(cloned.InboundConfigs) != 1 {
		t.Fatalf("unexpected cloned inbound count: %d", len(cloned.InboundConfigs))
	}

	clonedInbound := cloned.InboundConfigs[0]
	if !clonedInbound.exclude {
		t.Fatal("expected exclude flag to be preserved")
	}

	clonedAccount, ok := clonedInbound.clients[account.GetEmail()].(*api.VlessAccount)
	if !ok {
		t.Fatalf("unexpected cloned account type: %T", clonedInbound.clients[account.GetEmail()])
	}
	if clonedAccount == account {
		t.Fatal("expected cloned account pointer to be distinct")
	}
	if clonedAccount.Flow != account.Flow || clonedAccount.ID != account.ID {
		t.Fatalf("unexpected cloned account: got %+v want %+v", clonedAccount, account)
	}

	clonedAccount.Flow = "changed"
	if account.Flow != "xtls-rprx-vision" {
		t.Fatalf("mutating clone changed original account flow: %q", account.Flow)
	}
}
