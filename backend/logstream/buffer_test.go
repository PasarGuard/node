package logstream

import (
	"context"
	"testing"
	"time"
)

func TestBufferReplaysTailAndFansOut(t *testing.T) {
	buffer := NewBuffer(3)
	buffer.Publish("one")
	buffer.Publish("two")
	buffer.Publish("three")
	buffer.Publish("four")

	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	subA := buffer.Subscribe(ctxA)

	for _, want := range []string{"two", "three", "four"} {
		if got := receiveLog(t, subA); got != want {
			t.Fatalf("expected replayed log %q, got %q", want, got)
		}
	}

	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()
	subB := buffer.Subscribe(ctxB)

	for _, want := range []string{"two", "three", "four"} {
		if got := receiveLog(t, subB); got != want {
			t.Fatalf("expected second subscriber replayed log %q, got %q", want, got)
		}
	}

	buffer.Publish("five")

	if got := receiveLog(t, subA); got != "five" {
		t.Fatalf("expected first subscriber live log, got %q", got)
	}
	if got := receiveLog(t, subB); got != "five" {
		t.Fatalf("expected second subscriber live log, got %q", got)
	}

	cancelA()
	assertClosed(t, subA)

	buffer.Publish("six")
	if got := receiveLog(t, subB); got != "six" {
		t.Fatalf("expected remaining subscriber live log, got %q", got)
	}
}

func TestBufferDoesNotBlockOnSlowSubscribers(t *testing.T) {
	buffer := NewBuffer(1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sub := buffer.Subscribe(ctx)

	buffer.Publish("one")
	buffer.Publish("two")

	if got := receiveLog(t, sub); got != "one" {
		t.Fatalf("expected slow subscriber to keep first queued log, got %q", got)
	}

	freshCtx, freshCancel := context.WithCancel(context.Background())
	defer freshCancel()
	freshSub := buffer.Subscribe(freshCtx)
	if got := receiveLog(t, freshSub); got != "two" {
		t.Fatalf("expected fresh subscriber to receive latest buffered log, got %q", got)
	}
}

func TestBufferCloseClosesSubscribers(t *testing.T) {
	buffer := NewBuffer(2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sub := buffer.Subscribe(ctx)

	buffer.Publish("line")
	buffer.Close()

	if got := receiveLog(t, sub); got != "line" {
		t.Fatalf("expected buffered line before close, got %q", got)
	}
	assertClosed(t, sub)

	closedSub := buffer.Subscribe(context.Background())
	assertClosed(t, closedSub)
}

func receiveLog(t *testing.T, ch <-chan string) string {
	t.Helper()

	select {
	case got, ok := <-ch:
		if !ok {
			t.Fatal("expected log channel to be open")
		}
		return got
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for log")
		return ""
	}
}

func assertClosed(t *testing.T, ch <-chan string) {
	t.Helper()

	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("expected log channel to be closed")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for log channel to close")
	}
}
