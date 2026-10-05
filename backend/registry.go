package backend

import (
	"context"
	"sync"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
)

// Ports are the ports one core instance owns. They are handed out per core and
// held for that core's lifetime: a second core never sees them and a core's
// successor on restart keeps them.
type Ports struct {
	ApiPort    int
	MetricPort int
}

// Factory builds one core instance.
//
// A Factory must never read a process-global: the ports it is handed are the
// only ports that core may bind, and cfg is a per-core copy of the node config
// whose GeneratedConfigPath already points at <GeneratedConfigPath>/core-<id>/.
// A new core is one package with one init() calling Register; nothing outside
// that package changes.
type Factory func(ctx context.Context, in *common.Backend, ports Ports, cfg *config.Config) (Backend, error)

var (
	registryMu sync.RWMutex
	registry   = map[common.BackendType]Factory{}
)

// Register installs a Factory for a backend type. Called from a core package's
// init(); re-registering a type replaces the previous Factory, which is what a
// test needs to install a fake.
func Register(t common.BackendType, f Factory) {
	if f == nil {
		panic("backend: Register called with a nil Factory")
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[t] = f
}

// For returns the Factory registered for a backend type.
func For(t common.BackendType) (Factory, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	f, ok := registry[t]
	return f, ok
}
