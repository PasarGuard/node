package api

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/pasarguard/node/common"
	"github.com/xtls/xray-core/proxy/masque"
	"google.golang.org/protobuf/proto"
)

func TestMasqueAccountEncoding(t *testing.T) {
	user := &common.User{
		Email:    "alice@example.com",
		Proxies:  &common.Proxy{Masque: &common.Masque{Pass: "p:q"}},
		Inbounds: []string{"masque"},
	}
	// Both node transports receive this protobuf user message.
	data, err := proto.Marshal(user)
	if err != nil {
		t.Fatal(err)
	}
	decoded := new(common.User)
	if err := proto.Unmarshal(data, decoded); err != nil {
		t.Fatal(err)
	}
	account := NewMasqueAccount(decoded)
	if account.GetEmail() != user.Email || account.GetLevel() != 0 || account.Pass != "p:q" {
		t.Fatalf("unexpected account: %+v", account)
	}
	message, err := account.Message()
	if err != nil {
		t.Fatal(err)
	}
	// From Xray proxy/masque/config.proto: Account { string password = 1; }.
	if message.Type != "xray.proxy.masque.Account" || !bytes.Equal(message.Value, []byte{0x0a, 3, 'p', ':', 'q'}) {
		t.Fatalf("unexpected Xray account message: %v", message)
	}
	xrayAccount := new(masque.Account)
	if err := proto.Unmarshal(message.Value, xrayAccount); err != nil {
		t.Fatal(err)
	}
	if xrayAccount.Password != account.Pass {
		t.Fatalf("Xray decoded password = %q, want %q", xrayAccount.Password, account.Pass)
	}
	data, err = json.Marshal(account)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"email":"alice@example.com","level":0,"pass":"p:q"}` {
		t.Fatalf("unexpected Xray client JSON: %s", data)
	}
}
