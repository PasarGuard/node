package tunnel

import (
	"sync"

	"github.com/pasarguard/node/pkg/netutil"
)

// Allocator hands out per-tunnel port pairs on top of Phase 1's
// netutil.Allocator (CONTRACT §1.4). The pair rule is the one cores already
// paid for: sing-box derives its quota port as apiPort+1, so an allocation is
// only valid when Listen+1 is free too — and it is reserved with Listen so no
// later tunnel can take it.
//
// One Allocator serves every tunnel on a node; a Manager owns one. Two
// Allocators do not see each other's reservations, so a test that brings its
// own ports must not share the node's.
type Allocator struct {
	mu    sync.Mutex
	under *netutil.Allocator
}

// NewAllocator returns an empty allocator.
func NewAllocator() *Allocator {
	return &Allocator{under: netutil.NewAllocator()}
}

// AllocPair reserves a side's ports: Listen (with Control = Listen+1 free and
// reserved), plus one port per extra name asked for. extra may be empty.
func (a *Allocator) AllocPair(extra ...string) Ports {
	a.mu.Lock()
	defer a.mu.Unlock()

	listen, _ := a.under.FindFreePorts()
	a.under.Reserve(listen, listen+1)
	p := Ports{Listen: listen, Control: listen + 1}

	for _, name := range extra {
		if p.Extra == nil {
			p.Extra = map[string]int{}
		}
		e, _ := a.under.FindFreePorts()
		a.under.Reserve(e, e+1)
		p.Extra[name] = e
	}
	return p
}

// Release hands a side's ports back. Safe to call with ports this allocator
// never issued — netutil's reservation set simply has nothing to delete — so a
// Manager whose caller allocated elsewhere cannot corrupt a real reservation.
func (a *Allocator) Release(p Ports) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if p.Listen != 0 {
		a.under.Release(p.Listen, p.Listen+1)
	}
	for _, e := range p.Extra {
		a.under.Release(e, e+1)
	}
}
