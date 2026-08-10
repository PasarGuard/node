package controller

import (
	"errors"
	"reflect"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
)

func newEpochTestController(t *testing.T) *Controller {
	t.Helper()
	return New(config.NewTestConfig(t.TempDir(), uuid.New()))
}

func TestUserSyncEpochZeroAllowedUntilEpochAwareMutation(t *testing.T) {
	c := newEpochTestController(t)
	mutations := 0
	mutate := func() error {
		mutations++
		return nil
	}

	if err := c.ApplyUserSyncEpoch(0, mutate); err != nil {
		t.Fatalf("legacy mutation before epoch rollout failed: %v", err)
	}
	if err := c.ApplyUserSyncEpoch(7, mutate); err != nil {
		t.Fatalf("epoch-aware mutation failed: %v", err)
	}
	if err := c.ApplyUserSyncEpoch(0, mutate); err == nil {
		t.Fatal("legacy mutation was accepted after epoch rollout")
	} else {
		var epochErr *UserSyncEpochError
		if !errors.As(err, &epochErr) || epochErr.Current != 7 {
			t.Fatalf("expected current epoch 7, got %v", err)
		}
	}
	if mutations != 2 {
		t.Fatalf("rejected mutation ran; got %d calls", mutations)
	}
}

func TestFailedHigherUserSyncEpochIsConsumed(t *testing.T) {
	c := newEpochTestController(t)
	wantErr := errors.New("backend failed")
	if err := c.ApplyUserSyncEpoch(12, func() error { return wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("expected backend failure, got %v", err)
	}

	ran := false
	err := c.ApplyUserSyncEpoch(11, func() error {
		ran = true
		return nil
	})
	if err == nil {
		t.Fatal("older mutation was accepted after failed higher epoch")
	}
	if ran {
		t.Fatal("older backend mutation ran")
	}
}

func TestStaleLatePartialCannotOverwriteAuthoritativeSnapshot(t *testing.T) {
	c := newEpochTestController(t)
	state := []string{"initial"}

	if err := c.ApplyUserSyncEpoch(20, func() error {
		state = []string{"authoritative"}
		return nil
	}); err != nil {
		t.Fatalf("authoritative mutation failed: %v", err)
	}

	err := c.ApplyUserSyncEpoch(19, func() error {
		state = append(state, "stale-partial")
		return nil
	})
	if err == nil {
		t.Fatal("stale late partial mutation was accepted")
	}
	if !reflect.DeepEqual(state, []string{"authoritative"}) {
		t.Fatalf("stale mutation changed state: %v", state)
	}
}

func TestUserSyncEpochSerializesReservationAndMutation(t *testing.T) {
	c := newEpochTestController(t)
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondDone := make(chan struct{})
	secondAttempted := make(chan struct{})
	var orderMu sync.Mutex
	order := make([]uint64, 0, 2)

	go func() {
		_ = c.ApplyUserSyncEpoch(30, func() error {
			close(firstStarted)
			<-releaseFirst
			orderMu.Lock()
			order = append(order, 30)
			orderMu.Unlock()
			return nil
		})
	}()
	<-firstStarted

	go func() {
		close(secondAttempted)
		_ = c.ApplyUserSyncEpoch(31, func() error {
			orderMu.Lock()
			order = append(order, 31)
			orderMu.Unlock()
			return nil
		})
		close(secondDone)
	}()
	<-secondAttempted

	select {
	case <-secondDone:
		t.Fatal("higher epoch mutated while the older mutation was still running")
	default:
	}
	close(releaseFirst)
	<-secondDone

	orderMu.Lock()
	defer orderMu.Unlock()
	if !reflect.DeepEqual(order, []uint64{30, 31}) {
		t.Fatalf("mutations ran out of order: %v", order)
	}
}

func TestUserSyncEpochBatchRejectsMixedEpochs(t *testing.T) {
	var batch UserSyncEpochBatch
	if err := batch.Add(40); err != nil {
		t.Fatalf("first epoch failed: %v", err)
	}
	if err := batch.Add(40); err != nil {
		t.Fatalf("matching epoch failed: %v", err)
	}
	if err := batch.Add(41); err == nil {
		t.Fatal("mixed epoch was accepted")
	}
	if batch.Epoch() != 40 {
		t.Fatalf("mixed item changed batch epoch to %d", batch.Epoch())
	}
}

func TestBaseInfoAdvertisesUserSyncEpochSupport(t *testing.T) {
	c := newEpochTestController(t)
	if !c.BaseInfoResponse().GetUserSyncEpochSupported() {
		t.Fatal("base info did not advertise user sync epoch support")
	}
}

func TestBaseInfoReportsCurrentUserSyncEpochAfterSuccess(t *testing.T) {
	c := newEpochTestController(t)
	if err := c.ApplyUserSyncEpoch(60, func() error { return nil }); err != nil {
		t.Fatalf("epoch mutation failed: %v", err)
	}
	if got := c.BaseInfoResponse().GetUserSyncEpoch(); got != 60 {
		t.Fatalf("base info epoch = %d, want 60", got)
	}
}

func TestBaseInfoReportsConsumedUserSyncEpochAfterFailure(t *testing.T) {
	c := newEpochTestController(t)
	if err := c.ApplyUserSyncEpoch(61, func() error { return errors.New("backend failed") }); err == nil {
		t.Fatal("expected backend failure")
	}
	if got := c.BaseInfoResponse().GetUserSyncEpoch(); got != 61 {
		t.Fatalf("base info epoch = %d, want consumed epoch 61", got)
	}
}

func TestStaleStartIsRejectedBeforeDisconnect(t *testing.T) {
	c := newEpochTestController(t)
	shutdownStarted := make(chan struct{})
	allowShutdown := make(chan struct{})
	close(allowShutdown)
	oldBackend := &blockingBackend{shutdownStarted: shutdownStarted, allowShutdown: allowShutdown}
	c.backend = oldBackend

	if err := c.ApplyUserSyncEpoch(50, func() error { return nil }); err != nil {
		t.Fatalf("failed to establish current epoch: %v", err)
	}
	err := c.StartBackendControlled(t.Context(), &common.Backend{UserSyncEpoch: 49}, "127.0.0.1")
	if err == nil {
		t.Fatal("stale start was accepted")
	}
	select {
	case <-shutdownStarted:
		t.Fatal("stale start disconnected the current backend")
	default:
	}
	if c.Backend() != oldBackend {
		t.Fatal("stale start replaced the current backend")
	}
}
