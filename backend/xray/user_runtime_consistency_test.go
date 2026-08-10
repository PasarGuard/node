package xray

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/pasarguard/node/backend/xray/api"
	"github.com/pasarguard/node/common"
	"github.com/xtls/xray-core/infra/conf"
)

type scriptedInboundUserHandler struct {
	runtime        map[string]api.Account
	removeCalls    int
	addCalls       int
	removeFailures map[int]error
	addFailures    map[int]error
}

func (h *scriptedInboundUserHandler) RemoveInboundUser(_ context.Context, tag, email string) error {
	h.removeCalls++
	if err := h.removeFailures[h.removeCalls]; err != nil {
		return err
	}
	delete(h.runtime, tag+"\x00"+email)
	return nil
}

func (h *scriptedInboundUserHandler) AddInboundUser(_ context.Context, tag string, account api.Account) error {
	h.addCalls++
	if err := h.addFailures[h.addCalls]; err != nil {
		return err
	}
	h.runtime[tag+"\x00"+account.GetEmail()] = account
	return nil
}

func trojanAccount(email, password string) *api.TrojanAccount {
	return &api.TrojanAccount{
		BaseAccount: api.BaseAccount{Email: email},
		Password:    password,
	}
}

func trojanUser(email, password string, inbounds ...string) *common.User {
	return &common.User{
		Email:    email,
		Inbounds: inbounds,
		Proxies: &common.Proxy{
			Trojan: &common.Trojan{Password: password},
		},
	}
}

func newRuntimeConsistencyXray(accounts ...*api.TrojanAccount) (*Xray, *Inbound, *scriptedInboundUserHandler) {
	const tag = "trojan-in"
	clients := make(map[string]api.Account, len(accounts))
	runtime := make(map[string]api.Account, len(accounts))
	for _, account := range accounts {
		clients[account.GetEmail()] = account
		runtime[tag+"\x00"+account.GetEmail()] = account
	}
	inbound := &Inbound{
		Tag:      tag,
		Protocol: Trojan,
		Settings: make(map[string]any),
		clients:  clients,
	}
	handler := &scriptedInboundUserHandler{
		runtime:        runtime,
		removeFailures: make(map[int]error),
		addFailures:    make(map[int]error),
	}
	x := &Xray{
		config: &Config{
			LogConfig:      &conf.LogConfig{},
			InboundConfigs: []*Inbound{inbound},
		},
		userHandler: handler,
	}
	return x, inbound, handler
}

func accountPassword(t *testing.T, accounts map[string]api.Account, email string) (string, bool) {
	t.Helper()
	account, ok := accounts[email]
	if !ok {
		return "", false
	}
	trojan, ok := account.(*api.TrojanAccount)
	if !ok {
		t.Fatalf("unexpected account type for %q: %T", email, account)
	}
	return trojan.Password, true
}

func runtimePassword(t *testing.T, handler *scriptedInboundUserHandler, email string) (string, bool) {
	t.Helper()
	return accountPassword(t, handler.runtime, "trojan-in\x00"+email)
}

func restartSnapshotPasswords(t *testing.T, config *Config) map[string]string {
	t.Helper()
	payload, err := config.ToBytes()
	if err != nil {
		t.Fatal(err)
	}
	var snapshot struct {
		Inbounds []struct {
			Settings struct {
				Clients []struct {
					Email    string `json:"email"`
					Password string `json:"password"`
				} `json:"clients"`
			} `json:"settings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		t.Fatal(err)
	}
	passwords := make(map[string]string)
	for _, inbound := range snapshot.Inbounds {
		for _, client := range inbound.Settings.Clients {
			passwords[client.Email] = client.Password
		}
	}
	return passwords
}

func TestUpdateUsersPartialAddFailureKeepsRuntimeAndRestartSnapshotAligned(t *testing.T) {
	oldA := trojanAccount("a@example.com", "old-a")
	oldB := trojanAccount("b@example.com", "old-b")
	x, inbound, handler := newRuntimeConsistencyXray(oldA, oldB)
	handler.addFailures[2] = errors.New("second add failed")

	err := x.UpdateUsers(context.Background(), []*common.User{
		trojanUser("a@example.com", "new-a", inbound.Tag),
		trojanUser("b@example.com", "new-b", inbound.Tag),
	})
	if err == nil {
		t.Fatal("expected partial add failure")
	}

	if password, ok := accountPassword(t, inbound.clients, "a@example.com"); !ok || password != "new-a" {
		t.Fatalf("cached successful replacement = %q, %v; want new-a, true", password, ok)
	}
	if _, ok := accountPassword(t, inbound.clients, "b@example.com"); ok {
		t.Fatal("failed replacement retained the old cached credential")
	}
	if password, ok := runtimePassword(t, handler, "a@example.com"); !ok || password != "new-a" {
		t.Fatalf("runtime successful replacement = %q, %v; want new-a, true", password, ok)
	}
	if _, ok := runtimePassword(t, handler, "b@example.com"); ok {
		t.Fatal("failed replacement remained in runtime")
	}

	snapshot := restartSnapshotPasswords(t, x.config)
	if snapshot["a@example.com"] != "new-a" {
		t.Fatalf("restart snapshot lost successful replacement: %#v", snapshot)
	}
	if _, ok := snapshot["b@example.com"]; ok {
		t.Fatalf("restart snapshot would resurrect failed replacement: %#v", snapshot)
	}
}

func TestUpdateUsersPartialRemoveFailureKeepsConfirmedRemovalInSnapshot(t *testing.T) {
	oldA := trojanAccount("a@example.com", "old-a")
	oldB := trojanAccount("b@example.com", "old-b")
	x, inbound, handler := newRuntimeConsistencyXray(oldA, oldB)
	handler.removeFailures[2] = errors.New("second remove failed")

	err := x.UpdateUsers(context.Background(), []*common.User{
		trojanUser("a@example.com", "unused"),
		trojanUser("b@example.com", "unused"),
	})
	if err == nil {
		t.Fatal("expected partial remove failure")
	}

	if _, ok := accountPassword(t, inbound.clients, "a@example.com"); ok {
		t.Fatal("confirmed removal remained in cache")
	}
	if password, ok := accountPassword(t, inbound.clients, "b@example.com"); !ok || password != "old-b" {
		t.Fatalf("failed removal changed cached credential = %q, %v", password, ok)
	}
	if _, ok := runtimePassword(t, handler, "a@example.com"); ok {
		t.Fatal("confirmed removal remained in runtime")
	}
	if password, ok := runtimePassword(t, handler, "b@example.com"); !ok || password != "old-b" {
		t.Fatalf("failed removal changed runtime credential = %q, %v", password, ok)
	}

	snapshot := restartSnapshotPasswords(t, x.config)
	if _, ok := snapshot["a@example.com"]; ok {
		t.Fatalf("restart snapshot would resurrect confirmed removal: %#v", snapshot)
	}
	if snapshot["b@example.com"] != "old-b" {
		t.Fatalf("restart snapshot lost failed removal credential: %#v", snapshot)
	}
}

func TestUpdateUsersContinuesAfterAddFailureAndCommitsLaterSuccess(t *testing.T) {
	oldA := trojanAccount("a@example.com", "old-a")
	oldB := trojanAccount("b@example.com", "old-b")
	x, inbound, handler := newRuntimeConsistencyXray(oldA, oldB)
	handler.addFailures[1] = errors.New("first add failed")

	err := x.UpdateUsers(context.Background(), []*common.User{
		trojanUser("a@example.com", "new-a", inbound.Tag),
		trojanUser("b@example.com", "new-b", inbound.Tag),
	})
	if err == nil {
		t.Fatal("expected partial add failure")
	}

	if _, ok := accountPassword(t, inbound.clients, "a@example.com"); ok {
		t.Fatal("failed replacement retained the old cached credential")
	}
	if password, ok := accountPassword(t, inbound.clients, "b@example.com"); !ok || password != "new-b" {
		t.Fatalf("later successful replacement = %q, %v; want new-b, true", password, ok)
	}
	if _, ok := runtimePassword(t, handler, "a@example.com"); ok {
		t.Fatal("failed replacement remained in runtime")
	}
	if password, ok := runtimePassword(t, handler, "b@example.com"); !ok || password != "new-b" {
		t.Fatalf("later successful runtime replacement = %q, %v; want new-b, true", password, ok)
	}

	snapshot := restartSnapshotPasswords(t, x.config)
	if _, ok := snapshot["a@example.com"]; ok {
		t.Fatalf("restart snapshot would resurrect failed replacement: %#v", snapshot)
	}
	if snapshot["b@example.com"] != "new-b" {
		t.Fatalf("restart snapshot lost later successful replacement: %#v", snapshot)
	}
}

func TestSyncUserAddFailureDoesNotResurrectRemovedCredential(t *testing.T) {
	old := trojanAccount("user@example.com", "old")
	x, inbound, handler := newRuntimeConsistencyXray(old)
	handler.addFailures[1] = errors.New("add failed")

	err := x.SyncUser(context.Background(), trojanUser("user@example.com", "new", inbound.Tag))
	if err == nil {
		t.Fatal("expected add failure")
	}
	if _, ok := accountPassword(t, inbound.clients, "user@example.com"); ok {
		t.Fatal("failed replacement retained the old cached credential")
	}
	if _, ok := runtimePassword(t, handler, "user@example.com"); ok {
		t.Fatal("failed replacement remained in runtime")
	}
	if snapshot := restartSnapshotPasswords(t, x.config); len(snapshot) != 0 {
		t.Fatalf("restart snapshot would resurrect removed credential: %#v", snapshot)
	}
}
