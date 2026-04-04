package wireguard

import (
	"fmt"
	"time"
)

type logSeverity string

const (
	wireGuardLogTimestampFormat = "2006/01/02 15:04:05.000000"

	logSeverityInfo    logSeverity = "Info"
	logSeverityWarning logSeverity = "Warning"
	logSeverityError   logSeverity = "Error"
)

func formatWireGuardLogLine(severity logSeverity, message string) string {
	timestamp := time.Now().Format(wireGuardLogTimestampFormat)
	return fmt.Sprintf("%s [%s] %s", timestamp, severity, message)
}

func (wg *WireGuard) emitInfoLogf(format string, args ...any) {
	wg.emitLogf(logSeverityInfo, format, args...)
}

func (wg *WireGuard) emitWarningLogf(format string, args ...any) {
	wg.emitLogf(logSeverityWarning, format, args...)
}

func (wg *WireGuard) emitErrorLogf(format string, args ...any) {
	wg.emitLogf(logSeverityError, format, args...)
}

func (wg *WireGuard) emitLogf(severity logSeverity, format string, args ...any) {
	wg.emitLog(severity, fmt.Sprintf(format, args...))
}

func (wg *WireGuard) emitLog(severity logSeverity, message string) {
	wg.mu.RLock()
	defer wg.mu.RUnlock()

	wg.emitLogLocked(severity, message)
}

// emitLogLocked sends to the backend log channel while the caller already holds wg.mu.
func (wg *WireGuard) emitLogLocked(severity logSeverity, message string) {
	if wg.logChan == nil {
		return
	}

	select {
	case wg.logChan <- formatWireGuardLogLine(severity, message):
	default:
	}
}
