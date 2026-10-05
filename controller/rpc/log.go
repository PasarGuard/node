package rpc

import (
	"fmt"

	"github.com/pasarguard/node/common"
)

// GetLogs multiplexes every running core's log channel onto one stream; each
// record carries its core_id so the panel can filter client-side. Signature is
// unchanged (CONTRACT §3.1), so an old panel still sees one core's lines.
func (s *Service) GetLogs(_ *common.Empty, stream common.NodeService_GetLogsServer) error {
	sources := s.LogSources()
	if len(sources) == 0 {
		return s.backendNotInitialized()
	}

	type tagged struct {
		coreID uint64
		line   string
	}
	merged := make(chan tagged, len(sources))
	ctx := stream.Context()

	for _, src := range sources {
		go func(coreID uint64, ch <-chan string) {
			for line := range ch {
				select {
				case merged <- tagged{coreID: coreID, line: line}:
				case <-ctx.Done():
					return
				}
			}
			// A closed core channel must not close the multiplexed stream.
			select {
			case merged <- tagged{coreID: coreID}:
			case <-ctx.Done():
			}
		}(src.ID, src.Backend.Logs())
	}

	for {
		select {
		case msg := <-merged:
			// coreID 0 with an empty line is the end-of-core marker.
			if msg.line == "" {
				continue
			}
			if err := stream.Send(&common.Log{Detail: msg.line, CoreId: msg.coreID}); err != nil {
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
