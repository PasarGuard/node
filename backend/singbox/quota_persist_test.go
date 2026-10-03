package singbox

import (
	"testing"

	"github.com/pasarguard/node/common"
)

// Audit: every code path that touches the core config must leave the quota
// block intact.
//
// This exists because ApplyAPI once rebuilt the stats block and dropped
// quota.listen with it. The core then ran with budgets but no way to update
// them, which looks exactly like "enforcement works" right up until a limit
// change has no effect. Each writer below is exercised separately, and a
// failure names the path that lost the budget.

// quotaConfigWithEndpoint builds a config carrying budgets and a control
// endpoint, the shape the panel actually produces.
func quotaConfigWithEndpoint(t *testing.T) *Config {
	t.Helper()
	parsed, err := NewConfig(`{
  "log": {"level": "error"},
  "inbounds": [
    {"type":"vless","tag":"vless-in","listen":"127.0.0.1","listen_port":4444,"users":[]}
  ],
  "outbounds": [{"type":"direct","tag":"direct"}]
}`, nil)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if err := parsed.ApplyAPI(62051); err != nil {
		t.Fatalf("ApplyAPI: %v", err)
	}
	parsed.enableQuotaEndpoint(9999, "")
	parsed.syncUsers(quotaTestUsers())
	return parsed
}

func quotaTestUsers() []*common.User {
	return []*common.User{
		{Email: "alice", Quota: 5_000_000, Inbounds: []string{"vless-in"},
			Proxies: &common.Proxy{Vless: &common.Vless{Id: "11111111-2222-3333-4444-555555555555"}}},
	}
}

func assertQuotaIntact(t *testing.T, parsed *Config, path string) {
	t.Helper()
	if endpoint := parsed.quotaEndpoint(); endpoint == "" {
		t.Fatalf("%s dropped quota.listen — the core would run with budgets but no way to update them", path)
	}
	budgets := parsed.quotaBudgets()
	if len(budgets) == 0 {
		t.Fatalf("%s dropped the budgets entirely", path)
	}
	if got := budgets["alice"]; got != 5_000_000 {
		t.Fatalf("%s changed the budget: alice = %d, want 5000000", path, got)
	}
}

// TestEveryConfigWriterPreservesTheQuotaBlock is the audit. Each subtest is
// one production write path.
func TestEveryConfigWriterPreservesTheQuotaBlock(t *testing.T) {
	// Writers that must leave the budgets exactly as they found them.
	preserving := map[string]func(*Config){
		"ApplyAPI":     func(c *Config) { _ = c.ApplyAPI(62051) },
		"syncUsers":    func(c *Config) { c.syncUsers(quotaTestUsers()) },
		"refreshStats": func(c *Config) { c.refreshStatsUsers() },
		"Clone":        func(c *Config) { _ = c.Clone() },
	}

	for name, write := range preserving {
		t.Run(name, func(t *testing.T) {
			parsed := quotaConfigWithEndpoint(t)
			write(parsed)
			assertQuotaIntact(t, parsed, name)
		})
	}

	// resetQuotas is the one writer that changes budgets on purpose: it zeroes
	// them to fail closed. Its invariant is different — the endpoint must
	// survive, and every budget must still be present so the core reads
	// "spend nothing" rather than "unlimited".
	t.Run("resetQuotas", func(t *testing.T) {
		parsed := quotaConfigWithEndpoint(t)
		parsed.resetQuotas()

		if parsed.quotaEndpoint() == "" {
			t.Fatal("resetQuotas dropped quota.listen")
		}
		budgets := parsed.quotaBudgets()
		if len(budgets) == 0 {
			t.Fatal("resetQuotas removed the budgets; absent means unlimited, not zero")
		}
		for user, budget := range budgets {
			if budget != 0 {
				t.Fatalf("resetQuotas left user %s with a budget of %d", user, budget)
			}
		}
	})
}

// TestQuotaSurvivesRepeatedApplies covers the order that actually bit us: the
// panel sets up the endpoint, then the node calls ApplyAPI during construction.
func TestQuotaSurvivesRepeatedApplies(t *testing.T) {
	parsed := quotaConfigWithEndpoint(t)

	for i := 0; i < 5; i++ {
		_ = parsed.ApplyAPI(62051 + i)
		parsed.syncUsers(quotaTestUsers())
		assertQuotaIntact(t, parsed, "repeated apply")
	}
}

// TestEndpointAndBudgetsAreIndependent makes the two failure modes distinct:
// fail-closed zeroes budgets on purpose, and must never touch the endpoint.
func TestEndpointAndBudgetsAreIndependent(t *testing.T) {
	parsed := quotaConfigWithEndpoint(t)

	before := parsed.quotaEndpoint()
	if reset := parsed.resetQuotas(); reset == 0 {
		t.Fatal("resetQuotas found nobody to zero; the audit would prove nothing")
	}

	if after := parsed.quotaEndpoint(); after != before {
		t.Fatalf("fail-closed changed the endpoint: %q -> %q", before, after)
	}
	for user, budget := range parsed.quotaBudgets() {
		if budget != 0 {
			t.Fatalf("user %s kept a budget of %d after fail-closed", user, budget)
		}
	}
}

// TestCloneKeepsTheQuotaBlock: a clone is what a restart actually starts from,
// so a clone that lost the budget would silently reopen the limit.
func TestCloneKeepsTheQuotaBlock(t *testing.T) {
	parsed := quotaConfigWithEndpoint(t)
	assertQuotaIntact(t, parsed.Clone(), "Clone")
}
