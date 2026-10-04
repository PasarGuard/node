package singbox

import (
	"context"
	"testing"
	"time"

	"github.com/pasarguard/node/common"
)

// The byte-accounting guarantee across a restart: whatever the panel's
// GetStats(UsersStat) reports must be at least the bytes the user actually
// moved through the tunnel — before AND after the restart, and including the
// window the pre-restart flush parks in pendingStats.
//
// This exists because a suspected loss ("bytes drained with reset=true before
// the planned restart, then dropped") turned out to be a different bug
// entirely (sing-box ignoring the pattern field, which reset every counter on
// every outbound-stats poll). The guarantee is still worth pinning on its own:
// it is the property the panel bills against, and no test asserted it in the
// case where the restart's new config does NOT contain the user.

// pollUsers reads the panel-facing per-user total, the way record_usages does.
func pollUsers(t *testing.T, sb *SingBox, ctx context.Context) int64 {
	t.Helper()
	stats, err := sb.GetStats(ctx, &common.StatRequest{Type: common.StatType_UsersStat, Reset_: true})
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	var total int64
	for _, s := range stats.GetStats() {
		if s.GetName() == "a-user" {
			total += s.GetValue()
		}
	}
	return total
}

// TestRestartToAConfigWithoutTheUserStillBillsTheirBytes: the user's counters
// are parked in pendingStats by the pre-restart flush, and the new config has
// no such user. The next poll must still return those bytes, and the total
// across both polls must cover everything the client received.
func TestRestartToAConfigWithoutTheUserStillBillsTheirBytes(t *testing.T) {
	const window = 500 * time.Millisecond
	h := newDebounceHarness(t, window)

	// Bytes #1: consumed by a poll, so the harness proves the accounting works
	// at all before testing the awkward case.
	first := h.tunneled()
	if first == 0 {
		t.Fatal("no bytes moved through the tunnel at all")
	}
	poll1 := pollUsers(t, h.sb, h.ctx)
	if poll1 == 0 {
		t.Fatal("first poll reported no usage for a user that just transferred bytes")
	}

	// Bytes #2: after the poll, so they can only come from pendingStats.
	second := h.tunneled()

	// A restart whose new config does NOT contain the user — the case the
	// pendingStats path exists for.
	if err := h.sb.SyncUsers(h.ctx, nil); err != nil {
		t.Fatalf("SyncUsers(nil) — restart to a config without the user: %v", err)
	}
	deadline := time.Now().Add(5 * window)
	for h.sb.RestartCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if h.sb.RestartCount() != 1 {
		t.Fatalf("expected exactly 1 restart, got %d", h.sb.RestartCount())
	}

	poll2 := pollUsers(t, h.sb, h.ctx)
	if poll2 == 0 {
		t.Fatal("usage was LOST: the pre-restart bytes never reached the panel " +
			"(pendingStats flush did not deliver for a user absent from the new config)")
	}

	// The guarantee: billed >= delivered. Uplink+downlink combined is what
	// used_traffic sums, and it includes wire overhead, so it can exceed the
	// payload the client read — never fall short of it.
	delivered := int64(first + second)
	billed := poll1 + poll2
	if billed < delivered {
		t.Fatalf("panel-visible usage %d is below what the client received %d "+
			"(first_poll=%d second_poll=%d first_fetch=%d second_fetch=%d)",
			billed, delivered, poll1, poll2, first, second)
	}
	t.Logf("accounted across a restart that drops the user: delivered=%d billed=%d "+
		"(poll1=%d poll2=%d)", delivered, billed, poll1, poll2)
}

// TestPendingUserStatsSurviveANonUserPoll: only a user-facing read may consume
// pendingStats. The node-stats job polls Outbounds with reset=true 15s after
// scheduler start — before the usage job's first tick at 30s — so a consuming
// Outbounds poll handed the panel a response whose user rows the panel then
// discarded, and the pre-restart user bytes were gone. The result was a run
// that billed 0 bytes for a user the core had already spent 20 MB on.
func TestPendingUserStatsSurviveANonUserPoll(t *testing.T) {
	const window = 500 * time.Millisecond
	h := newDebounceHarness(t, window)

	h.tunneled() // bytes after the last poll; they can only live in pendingStats

	// Queue the restart, which drains the counters into pendingStats.
	if err := h.sb.SyncUser(h.ctx, &common.User{
		Email:    "a-user",
		Proxies:  &common.Proxy{Vless: &common.Vless{Id: h.userID}},
		Inbounds: []string{"vless-in"},
	}); err != nil {
		t.Fatalf("SyncUser: %v", err)
	}
	deadline := time.Now().Add(5 * window)
	for h.sb.RestartCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if h.sb.RestartCount() != 1 {
		t.Fatalf("expected exactly 1 restart, got %d", h.sb.RestartCount())
	}

	// The node-stats job's poll, verbatim: Outbounds with reset=true.
	if _, err := h.sb.GetStats(h.ctx, &common.StatRequest{Type: common.StatType_Outbounds, Reset_: true}); err != nil {
		t.Fatalf("Outbounds poll: %v", err)
	}

	// The usage job's poll must still see the bytes.
	got := pollUsers(t, h.sb, h.ctx)
	if got == 0 {
		t.Fatal("an Outbounds poll consumed the pending user bytes; the panel would " +
			"bill this user 0 for traffic the core already counted")
	}
	t.Logf("pending user bytes survived a node-stats poll: %d", got)
}
