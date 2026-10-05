package rpc

import (
	"fmt"

	"github.com/pasarguard/node/common"
	nodeLogger "github.com/pasarguard/node/logger"
)

// GetLogs multiplexes every running core's log channel onto one stream; each
// record carries its core_id, level and timestamp (CONTRACT §3.1). Signature is
// unchanged, so an old panel still sees one core's lines, now with fields it
// ignores.
//
// A core that classifies its own lines (LogLiner) supplies the level and
// timestamp. One that does not is read through the legacy string channel and
// gets the node's clock and an empty level — the panel's level filter treats an
// empty level as "any", so nothing is hidden that used to be shown.
func (s *Service) GetLogs(_ *common.Empty, stream common.NodeService_GetLogsServer) error {
	sources := s.LogSources()
	if len(sources) == 0 {
		return s.backendNotInitialized()
	}

	type tagged struct {
		coreID uint64
		line   nodeLogger.LogLine
	}
	merged := make(chan tagged, len(sources))
	ctx := stream.Context()

	for _, src := range sources {
		// coreID is captured per source and stamped onto every record that core
		// sends, so a line can only ever be attributed to the core that produced
		// it. Nothing downstream can reassign it.
		if liner, ok := src.Backend.(nodeLogger.LogLiner); ok {
			go func(coreID uint64, ch <-chan nodeLogger.LogLine) {
				for line := range ch {
					select {
					case merged <- tagged{coreID: coreID, line: line}:
					case <-ctx.Done():
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
				case <-ctx.Done():
					return
				}
			}
		}(src.ID, src.Backend.Logs())
	}

	for {
		select {
		case msg := <-merged:
			if msg.line.Detail == "" {
				continue
			}
			if err := stream.Send(&common.Log{
				Detail:   msg.line.Detail,
				CoreId:   msg.coreID,
				Level:    string(msg.line.Level),
				TsUnixMs: msg.line.TsUnixMs,
			}); err != nil {
				return fmt.Errorf("failed to send log: %w", err)
			}

		case <-ctx.Done():
			// Client has disconnected or cancelled the request.
			return nil
		}
	}
}

func (s *Service) backendNotInitialized() error {
	if _, err := s.backend(); err != nil {
		return err
	}
	return nil
}
