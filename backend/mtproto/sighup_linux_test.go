//go:build linux

package mtproto

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pasarguard/node/common"
)

func TestParseSIGHUPCaught(t *testing.T) {
	status := func(sigCgt string) string {
		return "Name:\ttelemt\nState:\tS (sleeping)\nPid:\t4242\n" +
			"SigQ:\t0/63414\nSigPnd:\t0000000000000000\nShdPnd:\t0000000000000000\n" +
			"SigBlk:\t0000000000000000\nSigIgn:\t0000000000001000\n" +
			"SigCgt:\t" + sigCgt + "\nCapInh:\t0000000000000000\n"
	}
	for name, test := range map[string]struct {
		status string
		caught bool
		fails  bool
	}{
		// telemt 3.5.14 right after exec: SIGBUS and SIGSEGV only.
		"without SIGHUP":      {status: status("0000000000000440")},
		"with SIGHUP":         {status: status("0000000000004e47"), caught: true},
		"every other signal":  {status: status("fffffffffffffffe")},
		"upper-case hex":      {status: status("FFFFFFFD7FC1FEFF"), caught: true},
		"128-bit mask":        {status: status("00000000000000000000000000000441"), caught: true},
		"no SigCgt line":      {status: "Name:\ttelemt\nSigIgn:\t0000000000000000\n", fails: true},
		"empty mask":          {status: status(""), fails: true},
		"not a hex mask":      {status: status("00000000000004g1"), fails: true},
		"SigCgt in the value": {status: "Name:\tSigCgt:\t1\n", fails: true},
	} {
		t.Run(name, func(t *testing.T) {
			caught, err := parseSIGHUPCaught(test.status)
			if test.fails {
				if err == nil {
					t.Fatalf("parseSIGHUPCaught = %v, want an error", caught)
				}
				return
			}
			if err != nil || caught != test.caught {
				t.Fatalf("parseSIGHUPCaught = %v, %v; want %v", caught, err, test.caught)
			}
		})
	}
}

func TestSIGHUPCaughtWithoutProcess(t *testing.T) {
	if _, err := sighupCaught(0); err == nil {
		t.Error("sighupCaught(0) succeeded")
	}
}

// TestRenderMissedByWatcherGetsSIGHUPOnceHandled: on Linux the node sends
// the SIGHUP for a render telemt's config watcher missed once telemt's
// SigCgt mask shows the handler, not on a clock. telemtSignalGrace is out
// of reach here, so only the mask can let the signal through; one sent
// before the handler would end the fake (a restart), and none would leave
// the render unloaded.
func TestRenderMissedByWatcherGetsSIGHUPOnceHandled(t *testing.T) {
	lowerSignalGrace(t, time.Hour)
	lowerMarkerConfirmTimeout(t, 10*time.Second)
	signals := filepath.Join(t.TempDir(), "signals")
	exe := writeFakeTelemt(t, fakeTelemt{
		ServeUsers:  true,
		WatchConfig: true,
		WatchSetup:  2 * time.Second,
		SignalDelay: 700 * time.Millisecond,
		SignalFile:  signals,
	})
	mt := newTestBackend(t, testNodeConfig(t, exe), []*common.User{mtUser("alice", "mtproto", testSecret)})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := mt.SyncUsers(ctx, []*common.User{mtUser("bob", "mtproto", testSecret)}); err != nil {
		t.Fatalf("SyncUsers: %v", err)
	}
	if !mt.Started() || mt.process.Generation() != 1 {
		t.Errorf("telemt was restarted (started %v, generation %d)", mt.Started(), mt.process.Generation())
	}
	if data, _ := os.ReadFile(signals); strings.Count(string(data), "SIGHUP") != 1 {
		t.Errorf("signal log %q, want one SIGHUP", data)
	}
	if got := desiredNames(mt); !slices.Equal(got, []string{"bob"}) {
		t.Errorf("desired = %q, want bob", got)
	}
}
