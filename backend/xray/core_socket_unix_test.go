//go:build !windows

package xray

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestRemoveUnixSocketFilesOnlyRemovesSockets(t *testing.T) {
	dir := t.TempDir()

	socketPath := filepath.Join(dir, "xray.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatalf("failed to create unix socket: %v", err)
	}
	listener.SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatalf("failed to close unix socket listener: %v", err)
	}

	filePath := filepath.Join(dir, "regular.txt")
	if err := os.WriteFile(filePath, []byte("keep me"), 0644); err != nil {
		t.Fatalf("failed to write regular file: %v", err)
	}

	removeUnixSocketFiles([]string{
		socketPath,
		filePath,
		filepath.Join(dir, "missing.sock"),
	})

	if _, err := os.Lstat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("expected socket path to be removed, got err=%v", err)
	}

	if _, err := os.Lstat(filePath); err != nil {
		t.Fatalf("expected regular file to remain, got err=%v", err)
	}
}

func TestStopRemovesTrackedUnixSocketsAfterProcessExit(t *testing.T) {
	dir := t.TempDir()

	socketPath := filepath.Join(dir, "xray.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatalf("failed to create unix socket: %v", err)
	}
	listener.SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatalf("failed to close unix socket listener: %v", err)
	}

	cancelled := false
	core := &Core{
		unixSocketPaths: []string{socketPath},
		cancelFunc: func() {
			cancelled = true
		},
	}

	core.Stop()

	if _, err := os.Lstat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("expected socket path to be removed, got err=%v", err)
	}
	if !cancelled {
		t.Fatal("expected cancel function to be called")
	}
	if core.cancelFunc != nil {
		t.Fatal("expected cancel function to be cleared")
	}
	if len(core.unixSocketPaths) != 0 {
		t.Fatalf("expected tracked socket paths to be cleared, got %v", core.unixSocketPaths)
	}
}
