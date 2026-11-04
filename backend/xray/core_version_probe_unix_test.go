//go:build !windows

package xray

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeVersionStub(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "xray")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func newCoreWithin(t *testing.T, path string, limit time.Duration) error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := NewXRayCore(path, t.TempDir(), t.TempDir(), 16, 16)
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(limit):
		t.Fatalf("NewXRayCore did not return within %s while the version probe hung", limit)
		return nil
	}
}

func TestVersionProbeOfAHungBinaryIsBounded(t *testing.T) {
	previous := versionProbeTimeout
	versionProbeTimeout = 500 * time.Millisecond
	t.Cleanup(func() { versionProbeTimeout = previous })

	err := newCoreWithin(t, writeVersionStub(t, "exec sleep 30"), 5*time.Second)
	if err == nil {
		t.Fatal("expected an error from a version probe that never answered")
	}
}

func TestVersionProbeSurvivesABinaryThatForksAndHoldsStdout(t *testing.T) {
	err := newCoreWithin(t, writeVersionStub(t, "echo 'Xray 26.10.31 (Xray, Penetrates Everything.)'\nsleep 30 &\nexit 0"), 15*time.Second)
	if err != nil {
		t.Fatalf("expected the printed version to be accepted, got %v", err)
	}
}

func TestVersionProbeOfAWorkingBinaryStillParses(t *testing.T) {
	path := writeVersionStub(t, "echo 'Xray 26.10.31 (Xray, Penetrates Everything.)'")
	core, err := NewXRayCore(path, t.TempDir(), t.TempDir(), 16, 16)
	if err != nil {
		t.Fatal(err)
	}
	if core.Version() != "26.10.31" {
		t.Fatalf("version = %q", core.Version())
	}
}
