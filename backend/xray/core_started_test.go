package xray

import (
	"io"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"testing"
	"time"
)

// Run the test binary as a child that stays alive until its stdin is closed.
// This exercises exec.Cmd.Wait without requiring an installed Xray binary.
func TestCoreStartedHelperProcess(t *testing.T) {
	if os.Getenv("PG_NODE_STARTED_TEST_HELPER") != "1" {
		return
	}
	_, _ = os.Stdout.Write([]byte{1})
	_, _ = io.Copy(io.Discard, os.Stdin)
	os.Exit(0)
}

func startCoreTestProcess(t *testing.T, core *Core) (io.WriteCloser, <-chan struct{}) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestCoreStartedHelperProcess$")
	cmd.Env = append(os.Environ(), "PG_NODE_STARTED_TEST_HELPER=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		t.Fatal(err)
	}

	waitDone := make(chan struct{})
	core.mu.Lock()
	core.process = cmd
	core.waitDone = waitDone
	core.mu.Unlock()
	go func() {
		_ = cmd.Wait()
		close(waitDone)
	}()
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		waitForCoreTestProcess(t, waitDone)
	})

	if _, err := io.ReadFull(stdout, make([]byte, 1)); err != nil {
		t.Fatalf("child did not become ready: %v", err)
	}
	return stdin, waitDone
}

func waitForCoreTestProcess(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for child process")
	}
}

func pollCoreStarted(core *Core) func() {
	done := make(chan struct{})
	var ready, workers sync.WaitGroup
	for range 4 {
		ready.Add(1)
		workers.Add(1)
		go func() {
			defer workers.Done()
			core.Started()
			ready.Done()
			for {
				select {
				case <-done:
					return
				default:
					core.Started()
					runtime.Gosched()
				}
			}
		}()
	}
	ready.Wait()
	return func() {
		close(done)
		workers.Wait()
	}
}

func TestCoreStartedProcessExit(t *testing.T) {
	core := &Core{}
	if core.Started() {
		t.Fatal("new core reports running")
	}
	stdin, waitDone := startCoreTestProcess(t, core)
	if !core.Started() {
		t.Fatal("live child reports stopped")
	}
	stopPolling := pollCoreStarted(core)
	defer stopPolling()

	// Process exit must be observable without the exit handler acquiring mu.
	// Stop also holds mu while waiting for the process watcher to reap the child.
	core.mu.Lock()
	_ = stdin.Close()
	select {
	case <-waitDone:
	case <-time.After(5 * time.Second):
		core.mu.Unlock()
		t.Fatal("process watcher blocked while core mutex was held")
	}
	started := core.startedLocked()
	core.mu.Unlock()
	if started || core.Started() {
		t.Fatal("exited child reports running")
	}
}

func TestCoreStartedConcurrentStopAndReplacement(t *testing.T) {
	core := &Core{}
	stopPolling := pollCoreStarted(core)
	defer stopPolling()

	for range 8 {
		_, waitDone := startCoreTestProcess(t, core)
		if !core.Started() {
			t.Fatal("replacement child reports stopped")
		}
		// Start already owns mu here: calling the locking Started method from
		// this path would deadlock instead of rejecting the duplicate start.
		if err := core.Start(&Config{}, false); err == nil {
			t.Fatal("duplicate start succeeded")
		}
		core.Stop()
		waitForCoreTestProcess(t, waitDone)
		if core.Started() {
			t.Fatal("stopped child reports running")
		}
	}
}
