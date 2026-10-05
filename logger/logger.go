package logger

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type LogLevel string

const (
	LogDebug    LogLevel = "Debug"
	LogInfo     LogLevel = "Info"
	LogWarning  LogLevel = "Warning"
	LogError    LogLevel = "Error"
	LogCritical LogLevel = "Critical"
)

// LogLine is one log record on the wire: the level the core's own detector
// decided for the line, plus the node's clock (CONTRACT §3.1).
type LogLine struct {
	Detail   string
	Level    LogLevel
	TsUnixMs int64
}

// LogLiner is the optional richer log source. A core that classifies its own
// lines (xray, sing-box) implements this and the GetLogs handlers prefer it;
// Backend.Logs() is unchanged, so a core with nothing to add — or a consumer
// that only wants plain strings — costs nothing.
type LogLiner interface {
	LogLines() <-chan LogLine
}

// DefaultLogBuffer is the classified channel's capacity. It matches the node's
// own LOG_BUFFER_SIZE default, so the classified stream and the legacy string
// stream fill at the same rate.
const DefaultLogBuffer = 10000

// Logger is one core's log sink: the access and error files it has always
// written, plus the classified line channel and the per-core file the
// multilevel view needs. One Logger per core, so nothing here is shared.
type Logger struct {
	outputLogs    bool
	accessLogFile *os.File
	errorLogFile  *os.File
	accessLogger  *log.Logger
	errorLogger   *log.Logger
	mu            sync.RWMutex

	bind      sync.Once
	coreID    uint64
	logLines  chan LogLine
	coreFiles *PerCoreFiles
	// backfill holds the lines published before the Logger was bound to a core,
	// so binding can replay them into the channel that did not exist yet. It is
	// the same DefaultLogBuffer bound as the live channel and is dropped at
	// bind time; a Logger that never binds never keeps more than that either.
	backfill []LogLine
}

func New(outputLogs bool) *Logger {
	return &Logger{
		outputLogs: outputLogs,
	}
}

// CoreLogLocation maps a core's own generated-config directory to the per-core
// log identity: the id it was created under and the directory that holds its
// siblings' files (CONTRACT §3.1, per-core files).
//
// config.CoreConfigPath builds "<GeneratedConfigPath>/core-<id>" for every core
// (node/config/config.go:148-150), so the directory a core is handed already
// names it. Reading it back is what lets every core write its own file without
// its constructor — which does not know it is being built for core 2 — having to
// say so.
func CoreLogLocation(configDir string) (coreID uint64, logDir string, ok bool) {
	base := filepath.Base(configDir)
	if !strings.HasPrefix(base, "core-") {
		return 0, "", false
	}
	id, err := strconv.ParseUint(strings.TrimPrefix(base, "core-"), 10, 64)
	if err != nil || id == 0 {
		return 0, "", false
	}
	return id, filepath.Dir(configDir), true
}

// BindOnce attaches this Logger to the core that owns configDir, at most once.
// It is idempotent and safe to call from every captured line, so a core needs no
// init hook: the first line it produces binds it.
//
// Binding a core also backfills: every line the core published before anyone
// attached to its channel is replayed into that channel. That is what makes a
// serving core's records exist from the moment it starts rather than from the
// moment the panel's stream opens — the defect a live three-core gate found
// (a core that logged nothing while actively serving traffic, because
// GetLogs snapshots its sources once and a Logger that binds on its first line
// has no channel yet).
//
// ponytail: the backfill ring is per-Logger and fixed at DefaultLogBuffer, the
// same bound the live channel already has. A core that produced more lines than
// that before anyone attached keeps its most recent ones — the same lines a
// slow consumer would keep getting from the live channel today. Raise the
// bound, or make it per-core configurable, if a real node's startup volume
// exceeds it.
func (l *Logger) BindOnce(configDir string) {
	id, dir, ok := CoreLogLocation(configDir)
	if !ok {
		return
	}
	l.bind.Do(func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.coreID = id
		l.coreFiles = NewPerCoreFiles(dir)
		l.logLines = make(chan LogLine, DefaultLogBuffer)
		// Drain the ring into the channel now that one exists, oldest first, so
		// a consumer that attaches later still sees what it missed in order.
		if len(l.backfill) == 0 {
			return
		}
		for _, line := range l.backfill {
			select {
			case l.logLines <- line:
			default:
			}
		}
		l.backfill = nil
	})
}

// LogLines is the classified stream: every line passed to Log, with the level
// that was just decided for it. It is nil until the Logger is bound to a core.
//
// Attaching does not start the stream: reading a channel never consumes the
// lines another reader put there, so the panel's GetLogs, a second subscriber
// and a test can all read the same records. That is the same property the
// legacy Logs() string channel has always had.
func (l *Logger) LogLines() <-chan LogLine {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.logLines
}

func openLogFile(path string) (*os.File, error) {
	if path == "" {
		return nil, nil
	}

	// Ensure the directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	// Try to open the file, create if not exists, and append to it
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (l *Logger) SetLogFile(accessPath, errorPath string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	var err error

	if l.accessLogFile, err = openLogFile(accessPath); err != nil {
		return fmt.Errorf("failed to open access log: %w", err)
	}
	if l.accessLogFile != nil {
		l.accessLogger = log.New(l.accessLogFile, "", 0)
	}

	if l.errorLogFile, err = openLogFile(errorPath); err != nil {
		return fmt.Errorf("failed to open error log: %w", err)
	}
	if l.errorLogFile != nil {
		l.errorLogger = log.New(l.errorLogFile, "", 0)
	}

	return nil
}

// Log is the one place a core's level verdict is consumed. It picks the access
// or error file exactly as it always has, and additionally publishes the record
// to the classified channel and this core's own file (CONTRACT §3.1).
//
// Publishing here rather than at each call site is what makes the level on the
// wire the same verdict the files got: there is one decision and one consumer.
func (l *Logger) Log(level LogLevel, message string) {
	l.mu.RLock()
	switch level {
	case LogError, LogCritical:
		if l.errorLogger != nil {
			l.errorLogger.Println(message)
		}
	default:
		if l.accessLogger != nil {
			l.accessLogger.Println(message)
		}
	}
	l.mu.RUnlock()

	if l.outputLogs {
		fmt.Println(message)
	}

	l.Publish(LogLine{Detail: message, Level: level, TsUnixMs: time.Now().UnixMilli()})
}

// Publish fans one classified line out to the channel and this core's own file.
// Both sends are non-blocking for the same reason the legacy ones are: a slow
// consumer or an unwritable file must never wedge the core that produced it.
//
// An unbound Logger has no channel yet, so the line goes into the bounded
// backfill ring instead of being dropped. BindOnce replays that ring once the
// channel exists. This is what makes a core's records exist from the moment it
// starts instead of from the moment a stream first attaches — without buffering
// unboundedly, because the ring keeps only the most recent DefaultLogBuffer
// lines, exactly as the live channel does.
func (l *Logger) Publish(line LogLine) {
	l.mu.Lock()
	ch, files, id := l.logLines, l.coreFiles, l.coreID
	if ch == nil && files == nil {
		l.backfill = append(l.backfill, line)
		if len(l.backfill) > DefaultLogBuffer {
			l.backfill = l.backfill[len(l.backfill)-DefaultLogBuffer:]
		}
	}
	l.mu.Unlock()

	if ch != nil {
		select {
		case ch <- line:
		default:
		}
	}
	if files != nil {
		files.Write(id, line)
	}
}

func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.accessLogFile != nil {
		l.accessLogFile.Close()
		l.accessLogFile = nil
	}
	if l.errorLogFile != nil {
		l.errorLogFile.Close()
		l.errorLogFile = nil
	}
	// The per-core file is opened lazily and would otherwise stay open for the
	// life of the process: a core that restarts would leak one handle each time,
	// and on Windows the file could not be removed or rotated underneath it.
	if l.coreFiles != nil {
		l.coreFiles.Close()
		l.coreFiles = nil
	}
}
