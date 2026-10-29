package xray

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pasarguard/node/common"
)

func TestSyncCallsAbandonedWhileQueuedReturnTheContextError(t *testing.T) {
	x := &Xray{}
	ctx, cancel := context.WithCancel(context.Background())

	x.syncMu.Lock()
	errs := make(chan error, 4)
	go func() { errs <- x.SyncUser(ctx, &common.User{}) }()
	go func() { errs <- x.SyncUsers(ctx, nil) }()
	go func() { errs <- x.UpdateUsers(ctx, nil) }()
	go func() { errs <- x.UpdateUsersAndRestart(ctx, nil) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	x.syncMu.Unlock()

	for range 4 {
		select {
		case err := <-errs:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("got %v, want context.Canceled", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a queued sync call did not return after its context was cancelled")
		}
	}
}
