package rest

import (
	"fmt"
	"net/http"
	"strconv"

	nodeLogger "github.com/pasarguard/node/logger"
)

// GetLogs multiplexes every running core's log channel; each line is prefixed
// with its core id, level and timestamp so a REST client can tell them apart
// (CONTRACT §3.1). The prefix is additive: a single-core node emits the same
// lines it always did, with the same leading core id.
//
// The wire form is one line per record:
//
//	<core_id> <ts_unix_ms> <level> <detail>
//
// core_id and ts_unix_ms are numeric so a client can filter on them without
// parsing prose. level is one of the node's own vocabulary words, empty for a
// core that does not classify its lines.
func (s *Service) GetLogs(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	sources := s.LogSources()
	if len(sources) == 0 {
		http.Error(w, "backend not initialized", http.StatusServiceUnavailable)
		return
	}

	type tagged struct {
		coreID uint64
		line   nodeLogger.LogLine
	}
	merged := make(chan tagged, len(sources))

	for _, src := range sources {
		// coreID is captured per source and stamped onto every record that core
		// sends, so a line can only ever be attributed to the core that produced
		// it. Nothing downstream can reassign it.
		if liner, ok := src.Backend.(nodeLogger.LogLiner); ok {
			go func(coreID uint64, ch <-chan nodeLogger.LogLine) {
				for line := range ch {
					select {
					case merged <- tagged{coreID: coreID, line: line}:
					case <-r.Context().Done():
						return
					}
				}
			}(src.ID, liner.LogLines())
			continue
		}

		go func(coreID uint64, ch <-chan string) {
			for line := range ch {
				select {
				case merged <- tagged{coreID: coreID, line: nodeLogger.LogLine{Detail: line}}:
				case <-r.Context().Done():
					return
				}
			}
		}(src.ID, src.Backend.Logs())
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	for {
		select {
		case msg := <-merged:
			if msg.line.Detail == "" {
				continue
			}
			_, err := fmt.Fprintf(w, "%d %s %s %s\n",
				msg.coreID,
				strconv.FormatInt(msg.line.TsUnixMs, 10),
				msg.line.Level,
				msg.line.Detail,
			)
			if err != nil {
				return
			}
			flusher.Flush()

		case <-r.Context().Done():
			return
		}
	}
}
