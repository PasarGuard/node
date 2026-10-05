package singbox

import (
	"strings"

	nodeLogger "github.com/pasarguard/node/logger"
)

// classifyLogType is sing-box's ERR[/FATAL substring heuristic, exactly as
// recordProcessLog has always applied it (core.go:527-532). The verdict now
// travels on the record instead of being discarded; the heuristic itself is
// deliberately not touched (CONTRACT §3.1: classification is unchanged, only
// carried).
func classifyLogType(line string) nodeLogger.LogLevel {
	if strings.Contains(line, "ERR[") || strings.Contains(line, "FATAL") {
		return nodeLogger.LogError
	}
	return nodeLogger.LogInfo
}

// bindLogCore attaches this core's Logger to its own per-core file. It is safe
// to call on every read of LogLines and is a no-op after the first call.
func (c *Core) bindLogCore() {
	if c.logger != nil {
		c.logger.BindOnce(c.configDir)
	}
}

// LogLines is the classified stream, alongside the unchanged Logs() string
// channel: a consumer of the legacy channel sees exactly what it always did.
func (c *Core) LogLines() <-chan nodeLogger.LogLine {
	c.bindLogCore()
	if c.logger == nil {
		return nil
	}
	return c.logger.LogLines()
}

// LogLines is how the controller reaches a core's classified lines: it holds the
// backend.Backend (the outer SingBox), not the inner Core.
func (s *SingBox) LogLines() <-chan nodeLogger.LogLine {
	if s == nil || s.core == nil {
		return nil
	}
	return s.core.LogLines()
}
