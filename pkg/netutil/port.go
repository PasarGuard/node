package netutil

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
)

func isPortFree(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

func FindFreePort() int {
	var apiPort int
	for apiPort = rand.Intn(50000) + 10000; apiPort < 65536; apiPort++ {
		if isPortFree(apiPort) {
			break
		}
	}
	return apiPort
}

// Allocator hands out ports that stay reserved for the lifetime of a core
// instance.
//
// FindFreePort only bind-tests, so two cores racing it can land on the same
// port and the loser fails at startup instead of starting. An Allocator
// remembers what it has handed out and never repeats it. It also never hands
// out the successor of a reserved port: sing-box derives its quota control port
// as apiPort+1 (backend/singbox/core.go), so a pair is only valid when apiPort+1
// is free too. That is checked at allocation time and again at Reserve time,
// where apiPort+1 goes on the reserved set so no later core can take it either.
type Allocator struct {
	mu    sync.Mutex
	taken map[int]struct{}
}

func NewAllocator() *Allocator {
	return &Allocator{taken: map[int]struct{}{}}
}

// Reserve marks apiPort, apiPort+1 and metricPort as this core's.
func (a *Allocator) Reserve(apiPort, metricPort int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, p := range []int{apiPort, apiPort + 1, metricPort} {
		a.taken[p] = struct{}{}
	}
}

// Release hands a core's ports back. Used when the node tears everything down.
func (a *Allocator) Release(apiPort, metricPort int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, p := range []int{apiPort, apiPort + 1, metricPort} {
		delete(a.taken, p)
	}
}

// FindFreePorts returns an (apiPort, metricPort) pair for one core. apiPort+1
// is verified free alongside apiPort; metricPort is only checked itself.
func (a *Allocator) FindFreePorts() (int, int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.scan(2), a.scan(1)
}

// scan returns the first free port at or after a random start for which the
// next n-1 ports are also free and unreserved.
func (a *Allocator) scan(n int) int {
	for p := rand.Intn(50000) + 10000; p+n <= 65536; p++ {
		free := true
		for i := 0; i < n; i++ {
			if _, taken := a.taken[p+i]; taken || !isPortFree(p+i) {
				free = false
				break
			}
		}
		if free {
			return p
		}
	}
	return 0
}

// Taken reports whether a port is currently reserved. Exported for tests.
func (a *Allocator) Taken(port int) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.taken[port]
	return ok
}
