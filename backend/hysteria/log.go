package hysteria

import nodeLogger "github.com/pasarguard/node/logger"

// LogLines is the classified stream, alongside the unchanged Logs() string
// channel: a consumer of the legacy channel sees exactly what it always did.
//
// The classification itself is not new — recordProcessLog has always called
// levelForLine to pick which file the line went to (core.go:431-433). This only
// puts the verdict it already computed on the record as well (CONTRACT §3.1).
// Without it, GetLogs falls back to the legacy string channel and every hysteria
// line arrives with an empty level, so the panel's level filter can never
// match one.
//
// It binds the Logger to this core on the way past, so a consumer that attaches
// before the first line arrives still gets a live channel rather than nil.
func (c *Core) LogLines() <-chan nodeLogger.LogLine {
	if c.logger == nil {
		return nil
	}
	c.logger.BindOnce(c.configDir)
	return c.logger.LogLines()
}

// LogLines is how the controller reaches a core's classified lines: it holds
// the backend.Backend (the outer Hysteria), not the inner Core.
func (h *Hysteria) LogLines() <-chan nodeLogger.LogLine {
	if h == nil || h.core == nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.core.LogLines()
}
