package singbox

import (
	"encoding/json"
	"testing"

	"github.com/pasarguard/node/common"
)

func failClosedConfig(t *testing.T, users []*common.User) *Config {
	t.Helper()

	const cfg = `{
  "log": {"level": "error"},
  "inbounds": [
    {"type":"vless","tag":"vless-in","listen":"127.0.0.1","listen_port":4444,
     "users":[{"name":"alice","uuid":"11111111-2222-3333-4444-555555555555"}]}
  ],
  "outbounds": [{"type":"direct","tag":"direct"}]
}`
	parsed, err := NewConfig(cfg, nil)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if err := parsed.ApplyAPI(62051); err != nil {
		t.Fatalf("ApplyAPI: %v", err)
	}
	parsed.syncUsers(users)
	return parsed
}

func readQuotaBudgets(t *testing.T, parsed *Config) (map[string]int64, bool) {
	t.Helper()
	raw, err := parsed.ToBytes()
	if err != nil {
		t.Fatalf("ToBytes: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	experimental, _ := out["experimental"].(map[string]any)
	if experimental == nil {
		return nil, false
	}
	v2api, _ := experimental["v2ray_api"].(map[string]any)
	if v2api == nil {
		return nil, false
	}
	stats, _ := v2api["stats"].(map[string]any)
	if stats == nil {
		return nil, false
	}
	quota, _ := stats["quota"].(map[string]any)
	if quota == nil {
		return nil, false
	}
	entries, _ := quota["users"].(map[string]any)
	if entries == nil {
		return nil, false
	}
	budgets := make(map[string]int64, len(entries))
	for user, value := range entries {
		budgets[user] = int64(value.(float64))
	}
	return budgets, true
}

func TestSyncWritesTheRealBudget(t *testing.T) {
	parsed := failClosedConfig(t, []*common.User{
		{Email: "alice", Quota: 5_000_000, Inbounds: []string{"vless-in"},
			Proxies: &common.Proxy{Vless: &common.Vless{Id: "11111111-2222-3333-4444-555555555555"}}},
	})
	budgets, ok := readQuotaBudgets(t, parsed)
	if !ok {
		t.Fatal("no quota block after a sync that carried a budget")
	}
	if budgets["alice"] != 5_000_000 {
		t.Fatalf("budget = %d, want 5000000", budgets["alice"])
	}
}

func TestFailClosedZeroesEveryBudget(t *testing.T) {
	parsed := failClosedConfig(t, []*common.User{
		{Email: "alice", Quota: 5_000_000, Inbounds: []string{"vless-in"},
			Proxies: &common.Proxy{Vless: &common.Vless{Id: "11111111-2222-3333-4444-555555555555"}}},
	})

	reset := parsed.resetQuotas()
	if reset != 1 {
		t.Fatalf("resetQuotas touched %d budgets, want 1", reset)
	}

	budgets, ok := readQuotaBudgets(t, parsed)
	if !ok {
		t.Fatal("quota block disappeared: the core would fall back to unlimited")
	}
	// Zero, not absent: the core reads "spend nothing" rather than
	// "unlimited", which is the whole point of failing closed.
	if got, present := budgets["alice"]; !present || got != 0 {
		t.Fatalf("alice = %d (present=%v), want 0 present in the map", got, present)
	}
}

func TestFailClosedCoversUsersThePanelHadNoBudgetFor(t *testing.T) {
	// An unlimited user has no entry in the config at all. If the revived core
	// only zeroed tracked budgets, that user would move unlimited bytes in the
	// window before the panel re-syncs.
	parsed := failClosedConfig(t, []*common.User{
		{Email: "alice", Quota: 0, Inbounds: []string{"vless-in"},
			Proxies: &common.Proxy{Vless: &common.Vless{Id: "11111111-2222-3333-4444-555555555555"}}},
	})

	parsed.resetQuotas()

	budgets, ok := readQuotaBudgets(t, parsed)
	if !ok {
		t.Fatal("fail-closed must create a quota block even when the panel had none")
	}
	if got, present := budgets["alice"]; !present || got != 0 {
		t.Fatalf("alice = %d (present=%v), want 0", got, present)
	}
}

func TestFailClosedKeepsEverythingElseIntact(t *testing.T) {
	// It zeroes budgets; it must not disturb the rest of the config.
	parsed := failClosedConfig(t, []*common.User{
		{Email: "alice", Quota: 5_000_000, Inbounds: []string{"vless-in"},
			Proxies: &common.Proxy{Vless: &common.Vless{Id: "11111111-2222-3333-4444-555555555555"}}},
	})
	before, err := parsed.ToBytes()
	if err != nil {
		t.Fatalf("ToBytes: %v", err)
	}

	parsed.resetQuotas()
	after, err := parsed.ToBytes()
	if err != nil {
		t.Fatalf("ToBytes: %v", err)
	}

	var a, b map[string]any
	_ = json.Unmarshal(before, &a)
	_ = json.Unmarshal(after, &b)
	for _, section := range []string{"inbounds", "outbounds", "route"} {
		ja, _ := json.Marshal(a[section])
		jb, _ := json.Marshal(b[section])
		if string(ja) != string(jb) {
			t.Fatalf("%s changed across resetQuotas:\n  before %s\n  after  %s", section, ja, jb)
		}
	}
}
