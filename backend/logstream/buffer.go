package logstream

import (
	"context"
	"sync"
)

type Buffer struct {
	mu          sync.Mutex
	lines       []string
	next        int
	count       int
	subscribers map[chan string]struct{}
	done        chan struct{}
	closed      bool
}

func NewBuffer(size int) *Buffer {
	if size <= 0 {
		size = 1
	}

	return &Buffer{
		lines:       make([]string, size),
		subscribers: make(map[chan string]struct{}),
		done:        make(chan struct{}),
	}
}

func (b *Buffer) Publish(line string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return
	}

	b.lines[b.next] = line
	b.next = (b.next + 1) % len(b.lines)
	if b.count < len(b.lines) {
		b.count++
	}

	for subscriber := range b.subscribers {
		select {
		case subscriber <- line:
		default:
		}
	}
}

func (b *Buffer) Subscribe(ctx context.Context) <-chan string {
	if ctx == nil {
		ctx = context.Background()
	}

	ch := make(chan string, b.capacity())

	b.mu.Lock()
	if b.closed {
		close(ch)
		b.mu.Unlock()
		return ch
	}

	for _, line := range b.snapshotLocked() {
		ch <- line
	}
	b.subscribers[ch] = struct{}{}
	b.mu.Unlock()

	done := b.done
	go func() {
		select {
		case <-ctx.Done():
			b.unsubscribe(ch)
		case <-done:
		}
	}()

	return ch
}

func (b *Buffer) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return
	}

	b.closed = true
	close(b.done)
	for subscriber := range b.subscribers {
		close(subscriber)
		delete(b.subscribers, subscriber)
	}
}

func (b *Buffer) capacity() int {
	if b == nil || len(b.lines) == 0 {
		return 1
	}
	return len(b.lines)
}

func (b *Buffer) snapshotLocked() []string {
	snapshot := make([]string, 0, b.count)
	if b.count == 0 {
		return snapshot
	}

	start := 0
	if b.count == len(b.lines) {
		start = b.next
	}

	for i := 0; i < b.count; i++ {
		snapshot = append(snapshot, b.lines[(start+i)%len(b.lines)])
	}

	return snapshot
}

func (b *Buffer) unsubscribe(ch chan string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, ok := b.subscribers[ch]; !ok {
		return
	}

	delete(b.subscribers, ch)
	close(ch)
}
