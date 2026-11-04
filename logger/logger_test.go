package logger

import (
	"os"
	"testing"
)

func TestSetLogFileTreatsNoneAsDisabled(t *testing.T) {
	t.Chdir(t.TempDir())

	l := New(false)
	if err := l.SetLogFile(DisabledLog, DisabledLog); err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	l.Log(LogInfo, "from 203.0.113.7:51000 accepted tcp:example.com:443 [in >> direct] email: user1")
	l.Log(LogError, "[Warning] core: Xray started")

	if _, err := os.Stat(DisabledLog); !os.IsNotExist(err) {
		t.Fatalf("SetLogFile(%q, %q) created a file named %q (stat error: %v)", DisabledLog, DisabledLog, DisabledLog, err)
	}
}
