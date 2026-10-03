package rpc

// SubscribeEvents streams node events to the panel.
//
// Mirrors GetLogs: a long-lived server stream the panel opens and re-opens. The
// panel is responsible for re-opening with backoff and for re-deriving state
// after a reconnect — a stream is a notification, not the source of truth. That
// split is deliberate: losing a stream must not lose a limit, and the panel
// already re-reads usage from the node on its own schedule.

import (
	"fmt"

	"github.com/pasarguard/node/backend/singbox"
	"github.com/pasarguard/node/common"
)

func (s *Service) SubscribeEvents(_ *common.Empty, stream common.NodeService_SubscribeEventsServer) error {
	backend, err := s.backend()
	if err != nil {
		return err
	}

	// Only the sing-box backend reports quota events; an xray node has no
	// in-core budget to exhaust. The stream stays open and simply quiet, so the
	// panel's reconnect logic needs no per-core special case.
	quotaCh, ok := backend.(interface {
		QuotaEventCh() <-chan singbox.QuotaEvent
	})
	if !ok {
		<-stream.Context().Done()
		return nil
	}

	events := quotaCh.QuotaEventCh()
	for {
		select {
		case ev := <-events:
			if err := stream.Send(&common.NodeEvent{
				UserId:    ev.UserID,
				Type:      ev.EventType,
				Remaining: ev.Remaining,
			}); err != nil {
				return fmt.Errorf("failed to send node event: %w", err)
			}

		case <-stream.Context().Done():
			// Client disconnected or cancelled the request.
			return nil
		}
	}
}
