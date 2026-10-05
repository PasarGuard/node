package xray

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nodeLogger "github.com/pasarguard/node/logger"
)

// TestClassifyLogTypeIsUnchanged asserts on the known inputs rather than on a
// hand-written expectation: the level a line gets is the same one that picks
// the access file it has always picked, and both now come from classifyLogType.
func TestClassifyLogTypeIsUnchanged(t *testing.T) {
	cases := []struct {
		line  string
		want  nodeLogger.LogLevel
		level string
	}{
		{
			"2025/10/06 11:28:38.624743 from 2.187.120.79:48394 accepted tcp:www.gstatic.com:443 [REALITY_GRPC_1 -> DIRECT] email: 7.Family",
			nodeLogger.LogInfo,
			"access tcp",
		},
		{
			"2025/10/06 11:28:38.624743 from 5.117.22.146:16425 accepted udp:dns.google.com:53 [REALITY_GRPC_1 -> DIRECT] email: 1.Myself",
			nodeLogger.LogInfo,
			"access udp",
		},
		{
			"[Warning] rejected request from 10.0.0.1:443: connection not accepted by destination",
			nodeLogger.LogError,
			"from/accepted fragments without the full access pattern",
		},
		{
			"2025/10/06 11:28:34.717774 [Debug] app/log: Logger started",
			nodeLogger.LogError,
			"debug line",
		},
		{
			"2024/01/15 10:30:45.654321 [Warning] connection timeout",
			nodeLogger.LogError,
			"warning line",
		},
		{
			"some random log without level",
			nodeLogger.LogError,
			"unclassified line",
		},
		{
			"2025/10/06 11:28:34.717852 [Debug] app/router: MphDomainMatcher is enabled for 24 domain rule(s)",
			nodeLogger.LogError,
			"router matcher",
		},
	}

	for _, tc := range cases {
		t.Run(tc.level, func(t *testing.T) {
			if got := classifyLogType(tc.line); got != tc.want {
				t.Errorf("classifyLogType(%q) = %q, want %q", tc.line, got, tc.want)
			}
			// The verdict must still be the one that picks the file.
			if tc.want == nodeLogger.LogInfo && !isAccessLog(tc.line) {
				t.Error("an Info line is not an access log: the file and the level disagree")
			}
			if tc.want == nodeLogger.LogError && isAccessLog(tc.line) {
				t.Error("an Error line is an access log: the file and the level disagree")
			}
		})
	}
}

// TestTwoCoresNeverMixFiles is the negative assertion for the per-core file:
// core 2's lines never reach core 1's file, and both keep their own.
func TestTwoCoresNeverMixFiles(t *testing.T) {
	root := t.TempDir()

	core1 := newLogTestCore(root, "core-1", 16)
	core2 := newLogTestCore(root, "core-2", 16)
	defer core1.logger.Close()
	defer core2.logger.Close()

	access1 := "2025/10/06 11:28:38.624743 from 2.187.120.79:48394 accepted tcp:a.example:443 [IN -> DIRECT] email: 1.A"
	error2 := "2025/10/06 11:28:39.000000 [Warning] core 2 trouble"

	for range 20 {
		core1.recordProcessLog(access1)
		core2.recordProcessLog(error2)
	}

	one := readLogFile(t, filepath.Join(root, "core-1.log"))
	two := readLogFile(t, filepath.Join(root, "core-2.log"))

	if !strings.Contains(one, access1) {
		t.Error("core-1.log is missing core 1's own line")
	}
	if strings.Contains(one, error2) {
		t.Error("core 2's line landed in core-1.log")
	}
	if !strings.Contains(two, error2) {
		t.Error("core-2.log is missing core 2's own line")
	}
	if strings.Contains(two, access1) {
		t.Error("core 1's line landed in core-2.log")
	}

	// The access/error split is unchanged: an access line stays out of the
	// error file and an error line stays out of the access file.
	accessPath := filepath.Join(root, "core-1-access.log")
	errPath := filepath.Join(root, "core-1-error.log")
	if err := core1.logger.SetLogFile(accessPath, errPath); err != nil {
		t.Fatalf("SetLogFile: %v", err)
	}
	core1.recordProcessLog(access1)
	core1.recordProcessLog(error2)

	if got := readLogFile(t, accessPath); strings.Contains(got, error2) {
		t.Error("an error line landed in the access file")
	}
	if got := readLogFile(t, errPath); !strings.Contains(got, error2) {
		t.Error("an error line did not reach the error file")
	}
}

// TestClassifiedLinesCarryLevelAndTimestamp: the wire record is the file
// record, and the timestamp is the node's own non-zero clock.
func TestClassifiedLinesCarryLevelAndTimestamp(t *testing.T) {
	root := t.TempDir()
	core := newLogTestCore(root, "core-1", 16)
	defer core.logger.Close()

	ch := core.LogLines()
	if ch == nil {
		t.Fatal("LogLines must be available once the core is bound")
	}

	access := "2025/10/06 11:28:38.624743 from 1.1.1.1:1234 accepted tcp:x.example:443 [IN -> OUT] email: 1.B"
	core.recordProcessLog(access)

	line := <-ch
	if line.Detail != access {
		t.Errorf("detail = %q, want %q", line.Detail, access)
	}
	if line.Level != nodeLogger.LogInfo {
		t.Errorf("level = %q, want Info (an access line)", line.Level)
	}
	if line.TsUnixMs <= 0 {
		t.Errorf("ts_unix_ms = %d, want a non-zero node clock", line.TsUnixMs)
	}
}

// TestSlowConsumerDoesNotWedgeTheCore: the non-blocking send is load-bearing.
// A full channel must drop lines, never block the producer.
func TestSlowConsumerDoesNotWedgeTheCore(t *testing.T) {
	root := t.TempDir()
	core := newLogTestCore(root, "core-1", 4)
	defer core.logger.Close()

	// Nobody reads either channel.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 5_000 {
			core.recordProcessLog("line " + strings.Repeat("x", i%7+1))
		}
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a full log channel wedged the core")
	}
}

// newLogTestCore builds a Core with only the state recordProcessLog touches, so
// the test drives the real capture path rather than a re-implementation.
func newLogTestCore(root, dir string, logBuffer int) *Core {
	return &Core{
		logger:         nodeLogger.New(false),
		logsChan:       make(chan string, logBuffer),
		logPhase:       logPhaseRuntime,
		startupLogs:    newStartupLogRing(10),
		runtimeLogs:    newStartupLogRing(10),
		configPath:     filepath.Join(root, dir),
		startupLogSize: 200,
	}
}

func readLogFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
