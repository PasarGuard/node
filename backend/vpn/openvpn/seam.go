package openvpn

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/pasarguard/node/backend/singbox"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/logger"
)

// The quota seam, in the two halves batch 5a-1 agreed (accounting-quota owns
// nft.go / quota.go / stats.go, this package owns everything else).
//
// This file exists rather than direct calls to NewQuota/PreflightNFT because
// both halves are on separate branches: a direct reference would make this
// package uncompilable until they merge, and the batch's gate is that each
// branch is green on its own. Once quota.go lands it calls RegisterQuotaEngine
// from its init() and every hook below starts returning the real engine; with
// the hook unset the core runs exactly as it does today — serving traffic with
// no accounting, which is what it did before that file existed.

// QuotaSeam is the half accounting-quota consumes. *OpenVPN is one.
//
// TunnelIP is called from their detector goroutine and under their mutex, so
// it only takes a read lock on state this package already holds — it must never
// block on their side or on a management round trip.
type QuotaSeam interface {
	Kill(username string) error
	TunnelIP(username string) (netip.Addr, bool)
}

// QuotaEngine is the half this package consumes: exactly the surface
// accounting-quota's *Quota exposes.
type QuotaEngine interface {
	FailClosed(usernames []string) error
	SyncUsers(ctx context.Context, users []*common.User) error
	GetStats(ctx context.Context, req *common.StatRequest) (*common.StatResponse, error)
	Disable(username string) error
	QuotaEventCh() <-chan singbox.QuotaEvent
	Close() error
}

// quotaHooks are installed by RegisterQuotaEngine. Read under the package
// mutex: the factory runs once per core at construction, the preflight on every
// Start, but a future reload may call either concurrently.
var (
	quotaMu      sync.RWMutex
	quotaFactory func(coreID uint64, seam QuotaSeam) (QuotaEngine, error)
	preflightNFT func() error
)

// RegisterQuotaEngine installs the nftables quota engine. quota.go calls this
// from init(); it is the only coupling the two halves need.
func RegisterQuotaEngine(
	factory func(coreID uint64, seam QuotaSeam) (QuotaEngine, error),
	preflight func() error,
) {
	quotaMu.Lock()
	defer quotaMu.Unlock()
	quotaFactory = factory
	preflightNFT = preflight
}

// Quota returns the engine for this core, or nil when none is installed.
func (o *OpenVPN) Quota() QuotaEngine {
	quotaMu.RLock()
	defer quotaMu.RUnlock()
	return o.quota
}

// Kill ends one user's session on the management interface. This is the call
// the detector goroutine and Disable make, so it is bounded and does not
// depend on the caller's context.
func (o *OpenVPN) Kill(username string) error {
	m := o.Management()
	if m == nil {
		return fmt.Errorf("openvpn: management interface is not up")
	}
	ctx, cancel := context.WithTimeout(context.Background(), mgmtTimeout)
	defer cancel()
	return m.Kill(ctx, username)
}

// TunnelIP is the address the counter and the quota rules bind to: the one the
// CCD file pinned, which is also the one `status 2` reports for the session.
// false means the roster has no entry for that name (not synced, or removed).
func (o *OpenVPN) TunnelIP(username string) (netip.Addr, bool) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	ip, ok := o.ips[username]
	if !ok {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr, true
}

// QuotaEventCh is what controller/rpc/events.go:28 type-asserts. A nil channel
// blocks forever, which is exactly the "stream stays open and quiet" behaviour
// that file documents for a core with no in-core budget.
func (o *OpenVPN) QuotaEventCh() <-chan singbox.QuotaEvent {
	q := o.Quota()
	if q == nil {
		return nil
	}
	return q.QuotaEventCh()
}

// coreIDFor reads the id out of the directory the controller built for this
// core (<gen>/core-<n>, config.CoreConfigPath). 0 when the path is not shaped
// that way — which is only ever a test.
func coreIDFor(dir string) uint64 {
	id, _, ok := logger.CoreLogLocation(dir)
	if !ok {
		return 0
	}
	return id
}

// preflight runs the kernel-feature check before anything is started. It is a
// hook for the same reason the factory is: without quota.go installed there is
// nothing to check and the core serves normally.
func preflight() error {
	quotaMu.RLock()
	fn := preflightNFT
	quotaMu.RUnlock()
	if fn == nil {
		return nil
	}
	if err := fn(); err != nil {
		return fmt.Errorf("openvpn: nftables preflight: %w", err)
	}
	return nil
}

// quotaTimeout bounds one engine round trip made by this package.
const quotaTimeout = 15 * time.Second

// installQuota builds this core's quota engine and arms it fail-closed.
//
// Order is the whole point: the roster is already on disk (so TunnelIP answers
// for every name this core authenticates), and FailClosed(0) lands before the
// child starts, so there is no window in which a client can hold a budget the
// node has not installed (LEGACY-VPN.md 4c).
func (o *OpenVPN) installQuota() error {
	quotaMu.RLock()
	factory := quotaFactory
	quotaMu.RUnlock()
	if factory == nil {
		return nil
	}
	q, err := factory(coreIDFor(o.dir), o)
	if err != nil {
		return fmt.Errorf("openvpn: quota engine: %w", err)
	}
	if err := q.FailClosed(o.ipNames()); err != nil {
		_ = q.Close()
		return fmt.Errorf("openvpn: fail-closed quota: %w", err)
	}
	o.mu.Lock()
	o.quota = q
	o.mu.Unlock()
	logf("openvpn: quota engine armed fail-closed (%d users)", len(o.ipNames()))
	return nil
}

// ipNames is the authenticable set: exactly the names with a CCD file, which is
// the set ccd-exclusive will let connect.
func (o *OpenVPN) ipNames() []string {
	o.mu.RLock()
	defer o.mu.RUnlock()
	out := make([]string, 0, len(o.ips))
	for name := range o.ips {
		out = append(out, name)
	}
	return out
}

// quotaFailClosed re-arms budget 0 for the current roster. Called before the
// child starts from idle, when the engine already exists but has seen no users.
func (o *OpenVPN) quotaFailClosed() error {
	q := o.Quota()
	if q == nil {
		return nil
	}
	return q.FailClosed(o.ipNames())
}

// quotaSync forwards the roster to the engine. Failures are logged, not
// returned: the panel retries the sync, and turning one into a start failure
// would take the core down over a rule update.
//
// Caller holds syncMu and does NOT hold o.mu — their SyncUsers calls back into
// TunnelIP, which takes o.mu.RLock.
func (o *OpenVPN) quotaSync(ctx context.Context) {
	q := o.Quota()
	if q == nil {
		return
	}
	qctx, cancel := context.WithTimeout(ctx, quotaTimeout)
	defer cancel()
	if err := q.SyncUsers(qctx, o.users); err != nil {
		logf("openvpn: quota sync failed: %v", err)
	}
}

// quotaDisable removes one user's rules after killing their session — the
// order accounting-quota asked for (kill, then rules; rules-first would open a
// free-traffic window, and dying after the kill leaves the user blocked).
func (o *OpenVPN) quotaDisable(names []string) bool {
	q := o.Quota()
	if q == nil {
		return false
	}
	for _, name := range names {
		if err := q.Disable(name); err != nil {
			logf("openvpn: quota disable of %q failed: %v", name, err)
		}
	}
	return true
}

// closeQuota stops the detector and deletes the table. Idempotent.
func (o *OpenVPN) closeQuota() {
	q := o.Quota()
	if q == nil {
		return
	}
	o.mu.Lock()
	o.quota = nil
	o.mu.Unlock()
	if err := q.Close(); err != nil {
		logf("openvpn: quota engine close failed: %v", err)
	}
}
