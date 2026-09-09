package controller

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/pasarguard/node/backend"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
)

type blockingBackend struct {
	shutdownStarted chan struct{}
	allowShutdown   chan struct{}
	shutdownCalls   int
	syncUsersCalls  int
	users           []*common.User
	syncUsersErr    error
}

func (b *blockingBackend) Started() bool       { return true }
func (b *blockingBackend) Version() string     { return "test" }
func (b *blockingBackend) Logs() <-chan string { return nil }
func (b *blockingBackend) Restart() error      { return nil }
func (b *blockingBackend) Shutdown() {
	b.shutdownCalls++
	if b.shutdownStarted != nil {
		close(b.shutdownStarted)
	}
	if b.allowShutdown != nil {
		<-b.allowShutdown
	}
}
func (b *blockingBackend) SyncUser(context.Context, *common.User) error { return nil }
func (b *blockingBackend) SyncUsers(_ context.Context, users []*common.User) error {
	b.syncUsersCalls++
	b.users = append([]*common.User(nil), users...)
	return b.syncUsersErr
}
func (b *blockingBackend) UpdateUsers(context.Context, []*common.User) error           { return nil }
func (b *blockingBackend) UpdateUsersAndRestart(context.Context, []*common.User) error { return nil }
func (b *blockingBackend) GetSysStats(context.Context) (*common.BackendStatsResponse, error) {
	return nil, nil
}
func (b *blockingBackend) GetStats(context.Context, *common.StatRequest) (*common.StatResponse, error) {
	return nil, nil
}
func (b *blockingBackend) GetOutboundsLatency(context.Context, *common.LatencyRequest) (*common.LatencyResponse, error) {
	return nil, nil
}
func (b *blockingBackend) GetUserOnlineStats(context.Context, string) (*common.OnlineStatResponse, error) {
	return nil, nil
}
func (b *blockingBackend) GetUserOnlineIpListStats(context.Context, string) (*common.StatsOnlineIpListResponse, error) {
	return nil, nil
}

var _ backend.Backend = (*blockingBackend)(nil)

func TestDisconnectSerializesBackendReplacement(t *testing.T) {
	c := New(config.NewTestConfig(t.TempDir(), uuid.New()))
	oldBackend := &blockingBackend{shutdownStarted: make(chan struct{}), allowShutdown: make(chan struct{})}
	newBackend := &blockingBackend{shutdownStarted: make(chan struct{}), allowShutdown: make(chan struct{})}
	c.backend = oldBackend

	disconnected := make(chan struct{})
	go func() {
		c.Disconnect()
		close(disconnected)
	}()

	select {
	case <-oldBackend.shutdownStarted:
	case <-time.After(time.Second):
		t.Fatal("Disconnect did not begin shutting down the old backend")
	}

	replacementStarted := make(chan struct{})
	replacementDone := make(chan struct{})
	go func() {
		c.LockControl()
		close(replacementStarted)
		c.backend = newBackend
		c.UnlockControl()
		close(replacementDone)
	}()

	select {
	case <-replacementStarted:
		t.Fatal("replacement acquired control while Disconnect was still stopping the old backend")
	case <-time.After(50 * time.Millisecond):
	}

	close(oldBackend.allowShutdown)
	<-disconnected
	<-replacementStarted
	<-replacementDone

	if c.Backend() != newBackend {
		t.Fatal("stale Disconnect erased the replacement backend")
	}
}
