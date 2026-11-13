package xray

import (
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/pasarguard/node/common"
)

func coreHoldsAfter(start bool, ordered []string, tag string) bool {
	present := start
	for _, operation := range ordered {
		switch operation {
		case tag + ":add":
			present = true
		case tag + ":remove":
			present = false
		}
	}
	return present
}

func TestConcurrentSyncUserAndUpdateUsersKeepCoreAndConfigInAgreement(t *testing.T) {
	x, service := newRecordingXray(t)

	on := recordingUser("1.alice", "trojan")
	off := recordingUser("1.alice")

	if err := x.UpdateUsers(syncContext(t), []*common.User{on}); err != nil {
		t.Fatal(err)
	}
	service.takeOrdered()
	present := true

	for round := 0; round < 200; round++ {
		ctx := syncContext(t)
		single, batch := on, []*common.User{on, off}
		if round%2 == 1 {
			single, batch = off, []*common.User{off, on}
		}

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = x.SyncUser(ctx, single)
		}()
		go func() {
			defer wg.Done()
			_ = x.UpdateUsers(ctx, batch)
		}()
		wg.Wait()

		ordered := service.takeOrdered()
		present = coreHoldsAfter(present, ordered, "trojan")
		inConfig := slices.Contains(inboundEmails(x.config, "trojan"), "1.alice")
		if present != inConfig {
			t.Fatalf("round %d: core holds alice on trojan = %v, config holds her = %v, operations %s", round, present, inConfig, strings.Join(ordered, " "))
		}

		if err := x.UpdateUsers(ctx, batch); err != nil {
			t.Fatal(err)
		}
		present = coreHoldsAfter(present, service.takeOrdered(), "trojan")
		want := slices.Contains(batch[len(batch)-1].GetInbounds(), "trojan")
		if present != want || slices.Contains(inboundEmails(x.config, "trojan"), "1.alice") != want {
			t.Fatalf("round %d: after a lone batch whose last entry wants alice on trojan = %v, core = %v", round, want, present)
		}
	}
}
