package mtproto

import (
	"context"
	"sync"
)

// syncLock is a mutex whose waiters can give up when their context ends,
// and whose holder may hand it to another goroutine to release. The zero
// value is unlocked.
type syncLock struct {
	once sync.Once
	ch   chan struct{}
}

func (l *syncLock) sem() chan struct{} {
	l.once.Do(func() { l.ch = make(chan struct{}, 1) })
	return l.ch
}

func (l *syncLock) Lock() {
	l.sem() <- struct{}{}
}

func (l *syncLock) Unlock() {
	select {
	case <-l.sem():
	default:
		panic("mtproto: unlock of an unlocked syncLock")
	}
}

// LockContext takes the lock. It gives up with ctx's error when ctx ends,
// and with errClosed when closed is closed, whichever comes first.
func (l *syncLock) LockContext(ctx context.Context, closed <-chan struct{}) error {
	select {
	case l.sem() <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-closed:
		return errClosed
	}
}
