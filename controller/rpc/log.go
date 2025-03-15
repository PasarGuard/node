package rpc

import (
	"errors"
	"fmt"

	"github.com/m03ed/gozargah-node/common"
)

func (s *Service) GetLogs(_ *common.Empty, stream common.NodeService_GetLogsServer) error {
	logChan := s.GetBackend().GetLogs()

	for {
		select {
		case log, ok := <-logChan:
			if !ok {
				return errors.New("log channel closed")
			}

			if err := stream.Send(&common.Log{Detail: log}); err != nil {
				return fmt.Errorf("failed to send log: %w", err)
			}

		case <-stream.Context().Done():
			// Client has disconnected or cancelled the request
			return nil
		}
	}
}
