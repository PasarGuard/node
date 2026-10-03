package singbox

import (
	"encoding/json"
	"testing"

	"github.com/pasarguard/node/common"
)

// quotaConfig renders what the core would actually be started with, which is
// what matters: the budget has to be in the file the binary reads, not in
// something the node pushes afterwards.
func quotaConfig(t *testing.T, users []*common.User) map[string]any {
	t.Helper()

	const cfg = `{
  "log": {"level": "error"},
  "inbounds": [
    {"type":"vless","tag":"vless-in","listen":"127.0.0.1","listen_port":4444,
     "users":[]}
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

	raw, err := parsed.ToBytes()
	if err != nil {
		t.Fatalf("ToBytes: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

func quotaUsers(t *testing.T, out map[string]any) map[string]int64 {
	t.Helper()
	experimental, _ := out["experimental"].(map[string]any)
	if experimental == nil {
		return nil
	}
	v2api, _ := experimental["v2ray_api"].(map[string]any)
	if v2api == nil {
		return nil
	}
	stats, _ := v2api["stats"].(map[string]any)
	if stats == nil {
		return nil
	}
	quota, _ := stats["quota"].(map[string]any)
	if quota == nil {
		return nil
	}
	raw, _ := quota["users"].(map[string]any)
	if raw == nil {
		return nil
	}
	budgets := make(map[string]int64, len(raw))
	for user, value := range raw {
		budgets[user] = int64(value.(float64))
	}
	return budgets
}

func TestQuotaWrittenIntoConfigBeforeStart(t *testing.T) {
	out := quotaConfig(t, []*common.User{
		{Email: "limited", Quota: 5_000_000},
		{Email: "free"},
	})

	budgets := quotaUsers(t, out)
	if budgets == nil {
		t.Fatal("no quota block in the config: the core would start with no budget at all")
	}
	if budgets["limited"] != 5_000_000 {
		t.Fatalf("limited user budget = %d, want 5000000", budgets["limited"])
	}
	if _, present := budgets["free"]; present {
		t.Fatal("unlimited user must be absent from the map, not present with 0")
	}
}

func TestQuotaOmittedWhenNobodyHasABudget(t *testing.T) {
	out := quotaConfig(t, []*common.User{
		{Email: "free"},
		{Email: "alsofree", Quota: 0},
	})

	if budgets := quotaUsers(t, out); budgets != nil {
		t.Fatalf("expected no quota block, got %v", budgets)
	}
}

func TestQuotaReplacedNotAccumulatedOnSync(t *testing.T) {
	// A user whose limit is raised or reset must end up with the new budget on
	// the *same* config — a stale entry left by an earlier sync would keep
	// capping them at the old value.
	const cfg = `{
  "log": {"level": "error"},
  "inbounds": [
    {"type":"vless","tag":"vless-in","listen":"127.0.0.1","listen_port":4444,
     "users":[]}
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

	render := func() map[string]int64 {
		t.Helper()
		raw, err := parsed.ToBytes()
		if err != nil {
			t.Fatalf("ToBytes: %v", err)
		}
		var out map[string]any
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return quotaUsers(t, out)
	}

	parsed.syncUsers([]*common.User{{Email: "u1", Quota: 1_000}})
	if got := render()["u1"]; got != 1_000 {
		t.Fatalf("initial budget = %d, want 1000", got)
	}

	parsed.syncUsers([]*common.User{{Email: "u1", Quota: 9_000}})
	if got := render()["u1"]; got != 9_000 {
		t.Fatalf("budget after raise = %d, want 9000", got)
	}

	parsed.syncUsers([]*common.User{{Email: "u1", Quota: 0}})
	if budgets := render(); budgets != nil {
		t.Fatalf("reset to unlimited must remove the entry, got %v", budgets)
	}
}
