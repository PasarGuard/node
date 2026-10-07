package tunnel

import (
	"fmt"
	"sort"
	"sync"
)

// The registry mirrors node/backend/registry.go (Phase 1's core seam): one
// map, one Register from each tool's init(), one lookup. A new tunnel tool is
// one package + one init() and touches nothing outside its own directory.
var (
	registryMu sync.RWMutex
	registry   = map[string]Adapter{}
)

// Register installs the Adapter for a tool name ("gost", "backhaul", "plain",
// …). Called from the tool package's init(); re-registering replaces the
// previous Adapter, which is what a test needs to install a fake.
func Register(tool string, a Adapter) {
	if tool == "" {
		panic("tunnel: Register called with an empty tool name")
	}
	if a == nil {
		panic("tunnel: Register called with a nil Adapter for " + tool)
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[tool] = a
}

// For returns the Adapter registered for a tool.
func For(tool string) (Adapter, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	a, ok := registry[tool]
	return a, ok
}

// Tools lists every registered tool name, sorted. For status output and tests.
func Tools() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]string, 0, len(registry))
	for t := range registry {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Require is For with an error, for callers that have no fallback.
func Require(tool string) (Adapter, error) {
	a, ok := For(tool)
	if !ok {
		return nil, fmt.Errorf("%w: %q (registered: %v)", ErrUnknownTool, tool, Tools())
	}
	return a, nil
}
