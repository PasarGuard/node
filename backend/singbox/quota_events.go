package singbox

// Quota-exhaustion events, for the panel to consume.
//
// The core knows the instant a user's budget runs out — `settle()` closes their
// connections at that moment. The panel does not: it learns about usage from a
// poll, so without this the user keeps spending until the next tick even though
// the core has already stopped them. The gap is one usage interval (10s by
// default), which is most of the overshoot Mode B is meant to remove.
//
// Detection is a poll of the core's own /quota endpoint rather than a hook
// through the patch. That keeps the patch free of any callback plumbing (it has
// no way to reach the node process) at the cost of a small, bounded delay:
//
//	fast : 250ms while any user has a non-zero remaining budget
//	slow : the normal interval once nothing is near a limit
//
// The cost is one loopback GET, and the fast tier only runs when a user is
// actually spending, so a quiet node costs one request per slow tick.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pasarguard/node/common"
)

var errQuotaStatus = errors.New("quota status endpoint returned a non-200")

const (
	quotaPollFast = 250 * time.Millisecond
	quotaPollSlow = 5 * time.Second

	// A user is "near" their limit when what remains is a small slice of what
	// they have already spent. Below this the fast poll buys nothing.
	quotaNearRatio = 0.02
	quotaNearFloor = 64 * 1024
)

// quotaEvent is what the detector emits; it is already in proto shape so the
// RPC layer can forward it without a conversion and without exposing an
// unexported type across packages.
type quotaEvent = common.NodeEvent

// quotaStatusResponse mirrors what the patched core's GET /quota returns. Only
// the fields this file needs are declared; the endpoint sends more.
type quotaStatusResponse struct {
	Users    map[string]int64 `json:"users"`
	Consumed map[string]int64 `json:"consumed"`
}

// QuotaEventCh returns the channel on which quota-exhaustion events appear.
// Buffered so a slow panel cannot block the detector, which must keep polling
// regardless of whether anyone is listening.
func (s *SingBox) QuotaEventCh() <-chan common.NodeEvent {
	s.eventOnce.Do(func() {
		s.quotaEvents = make(chan common.NodeEvent, 256)
	})
	return s.quotaEvents
}

// emitQuotaEvent publishes an event, dropping it if nobody is keeping up. A
// dropped event is recoverable — the panel re-derives the state from usage on
// its next poll — whereas blocking the detector would not be.
func (s *SingBox) emitQuotaEvent(ev common.NodeEvent) {
	s.eventOnce.Do(func() {
		s.quotaEvents = make(chan common.NodeEvent, 256)
	})
	select {
	case s.quotaEvents <- ev:
	default:
		log.Printf("quota event for user %s dropped: nobody is consuming events", ev.UserId)
	}
}

// startQuotaMonitor watches the core's control endpoint and emits an event the
// moment a user's remaining budget reaches zero. It stops when baseCtx is done.
func (s *SingBox) startQuotaMonitor(baseCtx context.Context, endpoint, secret string) {
	if endpoint == "" || secret == "" {
		// Nothing to watch. Config-carried budgets still enforce; only the
		// immediacy of the panel's reaction is lost.
		return
	}

	// Already announced: a user whose budget is restored must be able to
	// exhaust it again and be reported again.
	announced := map[string]time.Time{}

	client := &http.Client{Timeout: 5 * time.Second}
	go func() {
		interval := quotaPollSlow
		for {
			select {
			case <-baseCtx.Done():
				return
			case <-time.After(interval):
			}

			status, err := fetchQuotaStatus(client, endpoint, secret)
			if err != nil {
				// A core that is restarting answers nothing; back off rather
				// than hammering a port that is not listening yet.
				interval = quotaPollSlow
				continue
			}

			anyNear := false
			for user, remaining := range status.Users {
				consumed := status.Consumed[user]
				if remaining <= 0 {
					if last, ok := announced[user]; !ok || time.Since(last) > time.Minute {
						announced[user] = time.Now()
						s.emitQuotaEvent(common.NodeEvent{
							UserId:    user,
							Type:      common.NodeEventType_NODE_EVENT_QUOTA_EXHAUSTED,
							Remaining: remaining,
						})
						log.Printf("quota exhausted for user %s", user)
					}
					continue
				}
				delete(announced, user)
				// Near the limit when little remains relative to what has been
				// spent; that is when an event is imminent.
				if remaining <= quotaNearFloor ||
					(consumed > 0 && float64(remaining)/float64(consumed) <= quotaNearRatio) {
					anyNear = true
				}
			}

			interval = quotaPollSlow
			if anyNear {
				interval = quotaPollFast
			}
		}
	}()
}

func fetchQuotaStatus(client *http.Client, endpoint, secret string) (quotaStatusResponse, error) {
	var out quotaStatusResponse
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(endpoint, "/")+"/quota", nil)
	if err != nil {
		return out, err
	}
	req.Header.Set("X-Quota-Secret", secret)
	resp, err := client.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, errQuotaStatus
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return out, err
	}
	return out, json.Unmarshal(body, &out)
}

// quotaEvents is created lazily so the zero-value backend is usable in tests
// that never ask for it.
type quotaEventSink struct {
	eventOnce   sync.Once
	quotaEvents chan quotaEvent
}
