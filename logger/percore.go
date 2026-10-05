package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CoreLogFileName is the per-core file name (CONTRACT §3.1, per-core files).
// core_id 0 is the node's own logs and keeps the legacy node.log name, so a
// single-core node is byte-identical to a pre-multi-core one.
func CoreLogFileName(coreID uint64) string {
	if coreID == 0 {
		return "node.log"
	}
	return fmt.Sprintf("core-%d.log", coreID)
}

// logRootEnv is the same variable config.Load() reads for the node's generated
// config root (node/config/config.go:89).
//
// It is NOT where per-core files are actually written. That path is DERIVED, not
// configured: CoreLogLocation reads it back from the core's own generated-config
// directory, so <generated>/core-3/ yields <generated> as the log directory and
// the file is <generated>/core-3.log. Use CoreLogDir for that.
//
// This exists only so DefaultLogRoot below can read it, and DefaultLogRoot has
// no callers. The node has exactly one root for both the generated configs and
// the per-core logs; there is no LOG_DIR setting, and a gate test asserting
// against one was looking for a directory the node never writes to.
//
// ponytail: an env var read per process rather than injected through
// config.Config, whose default string would then be duplicated. Nothing reads
// it; delete both with the last caller, or thread cfg in when the node grows a
// second log root.
const logRootEnv = "GENERATED_CONFIG_PATH"

// DefaultLogRoot is where per-core files live when nothing else says.
func DefaultLogRoot() string {
	return os.Getenv(logRootEnv)
}

// CoreLogDir returns the directory a core's per-core log file is written to,
// derived exactly as the writer derives it. Exposed so a caller asserts against
// the writer's own answer instead of guessing at a setting that does not exist.
func CoreLogDir(configDir string) (string, bool) {
	_, dir, ok := CoreLogLocation(configDir)
	return dir, ok
}

// PerCoreFiles is the node's per-core audit trail: one append-only file per
// core, as a sibling of that core's generated config directory.
//
// A core writes only its own file, which is the property that matters. The
// writer is keyed by core id and the id is re-checked at the sink, so there is
// no path by which one core's line can land in another's file.
//
// ponytail: no rotation and no size cap. node/logger's access and error files
// do not rotate either (logger.go openLogFile is a plain O_APPEND open), so
// core-<id>.log inherits that exact behaviour rather than introducing a library
// the rest of the node does not use. CONTRACT §3.1 was corrected to match
// (orchestrator commit 0c55554, with docs/multi/agents/logs.md): there is no
// rotation here to reuse. Add rotation for the node-wide files first, and it
// applies to these for free.
type PerCoreFiles struct {
	dir     string
	now     func() time.Time
	mu      sync.Mutex
	writers map[uint64]*perCoreFile
}

type perCoreFile struct {
	file *os.File
}

// NewPerCoreFiles returns a writer rooted at dir, opened lazily per core.
func NewPerCoreFiles(dir string) *PerCoreFiles {
	return &PerCoreFiles{
		dir:     dir,
		now:     time.Now,
		writers: map[uint64]*perCoreFile{},
	}
}

// SetClock replaces the timestamp source, so a test can assert on exact file
// contents instead of on a wall clock.
func (p *PerCoreFiles) SetClock(now func() time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.now = now
}

// Write appends one line to coreID's own file. A line whose file cannot be
// opened is dropped rather than retried: the audit trail is best-effort and
// must never block or fail the core that produced it.
func (p *PerCoreFiles) Write(coreID uint64, line LogLine) {
	p.mu.Lock()
	w, ok := p.writers[coreID]
	if !ok {
		w = p.openLocked(coreID)
	}
	now := p.now
	p.mu.Unlock()

	if w == nil {
		return
	}
	fmt.Fprintf(w.file, "%d %s %s\n", now().UnixMilli(), line.Level, line.Detail)
}

// WriteString appends a bare line at Info, for a core that has no level.
func (p *PerCoreFiles) WriteString(coreID uint64, detail string) {
	p.Write(coreID, LogLine{Detail: detail, Level: LogInfo})
}

func (p *PerCoreFiles) openLocked(coreID uint64) *perCoreFile {
	if p.dir == "" {
		return nil
	}
	if err := os.MkdirAll(p.dir, 0755); err != nil {
		return nil
	}
	f, err := os.OpenFile(filepath.Join(p.dir, CoreLogFileName(coreID)), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return nil
	}
	w := &perCoreFile{file: f}
	p.writers[coreID] = w
	return w
}

// Close releases every per-core file.
func (p *PerCoreFiles) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, w := range p.writers {
		if w.file != nil {
			w.file.Close()
		}
		delete(p.writers, id)
	}
}
