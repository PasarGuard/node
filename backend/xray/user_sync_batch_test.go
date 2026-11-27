package xray

import (
	"slices"
	"testing"

	"github.com/pasarguard/node/common"
)

func inboundEmails(cfg *Config, tag string) []string {
	for _, inbound := range cfg.InboundConfigs {
		if inbound.Tag != tag {
			continue
		}
		inbound.mu.RLock()
		emails := make([]string, 0, len(inbound.clients))
		for email := range inbound.clients {
			emails = append(emails, email)
		}
		inbound.mu.RUnlock()
		slices.Sort(emails)
		return emails
	}
	return nil
}

func TestUpdateUsersLetsTheLastEntryForAUserWin(t *testing.T) {
	x, service := newRecordingXray(t)
	ctx := syncContext(t)
	others := []string{"vless", "vmess", "ss", "ss2022", "hysteria"}

	alice := recordingUser("1.alice", "trojan")
	rotated := recordingUser("1.alice", "trojan")
	rotated.Proxies.Trojan.Password = "rotated trojan secret"

	if err := x.UpdateUsers(ctx, []*common.User{alice}); err != nil {
		t.Fatal(err)
	}
	service.take()

	if err := x.UpdateUsers(ctx, []*common.User{rotated, alice}); err != nil {
		t.Fatal(err)
	}
	assertOperations(t, service.take(), operations(removed(others...)...))

	if err := x.UpdateUsers(ctx, []*common.User{recordingUser("1.alice"), alice}); err != nil {
		t.Fatal(err)
	}
	assertOperations(t, service.take(), operations(removed(others...)...))
	if emails := inboundEmails(x.config, "trojan"); !slices.Equal(emails, []string{"1.alice"}) {
		t.Fatalf("the user whose last entry keeps them on trojan was dropped: trojan holds %v", emails)
	}
}

func TestUpdateUsersAndSyncUsersLetTheLastEntryForAUserWinInTheConfig(t *testing.T) {
	enabled := recordingUser("1.alice", "trojan")
	disabled := recordingUser("1.alice")

	for name, apply := range map[string]func(*Config, []*common.User){
		"updateUsers": (*Config).updateUsers,
		"syncUsers":   (*Config).syncUsers,
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := NewConfig(recordingInbounds, nil)
			if err != nil {
				t.Fatal(err)
			}

			apply(cfg, []*common.User{enabled, disabled})
			if emails := inboundEmails(cfg, "trojan"); len(emails) != 0 {
				t.Fatalf("a user whose last entry removes them is on trojan: %v", emails)
			}

			apply(cfg, []*common.User{disabled, enabled})
			if emails := inboundEmails(cfg, "trojan"); len(emails) != 1 {
				t.Fatalf("a user whose last entry adds them is not on trojan: %v", emails)
			}
		})
	}
}
