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
// config root (node/config/config.go:89). Reading it here keeps the per-core
// log directory a property of the node's existing configuration rather than a
// new setting.
//
// ponytail: the env var is read per process rather than injected through
// config.Config, so the default string is duplicated. Thread cfg into
// logger.NewForCore if the node ever grows a second log root.
const logRootEnv = "GENERATED_CONFIG_PATH"

// DefaultLogRoot is where per-core files live when nothing else says.
func DefaultLogRoot() string {
	return os.Getenv(logRootEnv)
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
// the rest of the node does not use. Change request CR-1 filed to the
// orchestrator: the CONTRACT's "reuse the rotation that file already has" names
// a rotation that does not exist.
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
