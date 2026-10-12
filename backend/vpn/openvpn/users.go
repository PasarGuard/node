package openvpn

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/pasarguard/node/common"
)

// ccdDir is the client-config-dir, relative to `openvpn --cd`.
const ccdDir = "ccd"

// ipamFile persists username -> tunnel IP so a user keeps the same address
// across restarts, reboots and roster churn. The accounting rules bind to that
// address (LEGACY-VPN.md section 4b), so churning it under a live session would
// move a user's counters without moving their traffic.
const ipamFile = "ipam.json"

// ccdFileName turns a username into a CCD file name that is guaranteed safe on
// every filesystem: plain hex of the bytes.
//
// The alternative (the username itself) is a path traversal surface on a value
// that arrives from the wire. hex is injective, so it has no collisions either.
func ccdFileName(username string) string {
	return hex.EncodeToString([]byte(username))
}

// credentialFor maps a panel user onto the OpenVPN login pair.
//
// Identity rule (CONTRACT 6.1, LEGACY-VPN.md 4a): the login name is
// str(user.id), which is exactly what User.email and Stat.name already carry --
// so a session, a CCD file, a stat row and a panel user row are all the same
// key. The wire also has Openvpn.username; when it is set and disagrees with
// that identity, this refuses the user by name instead of authenticating
// someone the panel cannot attribute.
func credentialFor(user *common.User) (credentialPair, error) {
	proxies := user.GetProxies()
	if proxies == nil || proxies.GetOpenvpn() == nil {
		return credentialPair{}, errSkip
	}
	ovpn := proxies.GetOpenvpn()
	identity := user.GetEmail()
	if identity == "" {
		return credentialPair{}, errSkip
	}
	if name := ovpn.GetUsername(); name != "" && name != identity {
		return credentialPair{}, fmt.Errorf(
			"openvpn: user %q has Openvpn.username %q, which is not the panel identity %q",
			identity, name, identity)
	}
	if ovpn.GetPassword() == "" {
		return credentialPair{}, errSkip
	}
	return credentialPair{Username: identity, Password: ovpn.GetPassword()}, nil
}

// errSkip marks a user this core does not serve: no OpenVPN credentials, or no
// password. Skipped, not an error -- the same user may be on a core that does.
var errSkip = fmt.Errorf("openvpn: user has no credentials for this core")

// roster builds the ordered login set for this core and the tunnel IP each user
// keeps. Ordering is by username so two renders of the same roster produce the
// same files byte for byte.
func (o *OpenVPN) roster(users []*common.User) ([]credentialPair, map[string]string, error) {
	var pairs []credentialPair
	seen := map[string]bool{}
	for _, user := range users {
		if !assignedToThisCore(user, o.cfg.excluded) {
			continue
		}
		pair, err := credentialFor(user)
		if err == errSkip {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		if err := validateCredential(pair.Username, pair.Password); err != nil {
			return nil, nil, err
		}
		if seen[pair.Username] {
			continue
		}
		seen[pair.Username] = true
		pairs = append(pairs, pair)
	}
	slices.SortFunc(pairs, func(a, b credentialPair) int {
		return strings.Compare(a.Username, b.Username)
	})
	names := make([]string, 0, len(pairs))
	for _, p := range pairs {
		names = append(names, p.Username)
	}
	ips, err := o.assignIPs(names)
	if err != nil {
		return nil, nil, err
	}
	return pairs, ips, nil
}

// assignIPs loads the persisted table, gives every name a stable address and
// drops the ones no longer on this core.
func (o *OpenVPN) assignIPs(names []string) (map[string]string, error) {
	a, err := loadIPAM(filepath.Join(o.dir, ipamFile))
	if err != nil {
		return nil, err
	}
	if err := a.ensure(names); err != nil {
		return nil, err
	}
	if err := a.save(); err != nil {
		return nil, err
	}
	return a.assigned, nil
}

// ipam is the pool allocator for one core.
type ipam struct {
	path     string
	base     uint32
	ones     int
	assigned map[string]string
}

func loadIPAM(path string) (*ipam, error) {
	a := &ipam{path: path, assigned: map[string]string{}}
	data, err := os.ReadFile(path)
	if err == nil {
		if uerr := json.Unmarshal(data, &a.assigned); uerr != nil {
			// A corrupt table must not brick the core: reallocate. The old
			// addresses are only a stability nicety, never an authorization --
			// nft rules are rewritten from this table on every sync anyway.
			log.Printf("openvpn: %s is unreadable (%v), reassigning tunnel IPs", filepath.Base(path), uerr)
			a.assigned = map[string]string{}
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("openvpn: reading %s: %w", filepath.Base(path), err)
	}
	return a, nil
}

// bindPool tells the allocator which network it works in. Called once from the
// core constructor, after Config has been validated.
func (a *ipam) bindPool(network, netmask string) error {
	ip := net.ParseIP(network).To4()
	mask := net.IPMask(net.ParseIP(netmask).To4())
	if ip == nil || len(mask) != net.IPv4len {
		return fmt.Errorf("openvpn: cannot allocate from %s/%s", network, netmask)
	}
	ones, bits := mask.Size()
	if bits != 32 || ones > 30 {
		return fmt.Errorf("openvpn: pool %s/%s has no client addresses", network, netmask)
	}
	a.base = binaryIP(ip)
	a.ones = ones
	return nil
}

func binaryIP(ip net.IP) uint32 {
	b := ip.To4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func uint32IP(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// hosts enumerates the assignable addresses: everything after the server own
// address (base+1, which the `server` directive takes) and before the broadcast
// address.
func (a *ipam) hosts() []string {
	size := uint32(1) << uint(32-a.ones)
	out := make([]string, 0, int(size)-3)
	for v := a.base + 2; v < a.base+size-1; v++ {
		out = append(out, uint32IP(v))
	}
	return out
}

// ensure gives every name an address, keeps the ones it already has and
// releases the rest. Returns an error only when the pool is genuinely full.
// Fail closed: an unassigned user gets no CCD file, and `ccd-exclusive` then
// refuses the session rather than letting it take a random address the rules
// do not cover.
func (a *ipam) ensure(names []string) error {
	wanted := make(map[string]bool, len(names))
	for _, n := range names {
		wanted[n] = true
	}
	kept := make(map[string]string, len(names))
	taken := map[string]bool{}
	for name, ip := range a.assigned {
		if wanted[name] {
			kept[name] = ip
			taken[ip] = true
		}
	}
	for _, name := range names {
		if _, ok := kept[name]; ok {
			continue
		}
		free := ""
		for _, candidate := range a.hosts() {
			if !taken[candidate] {
				free = candidate
				break
			}
		}
		if free == "" {
			return fmt.Errorf("openvpn: tunnel pool %s/%d is exhausted (%d addresses in use)",
				uint32IP(a.base), a.ones, len(taken))
		}
		kept[name] = free
		taken[free] = true
	}
	a.assigned = kept
	return nil
}

func (a *ipam) save() error {
	data, err := json.MarshalIndent(a.assigned, "", "  ")
	if err != nil {
		return err
	}
	return writeSecret(a.path, data)
}

// syncRoster materialises the desired state on disk: the credential file the
// auth executable reads and one CCD file per user carrying its static IP.
//
// Order matters. The CCD file is written first, so a crash between the two
// leaves a session with an address and no login rather than a login with no
// address -- the second is the one that would authenticate a client the
// accounting rules cannot see.
//
// Nothing here restarts the child: the auth executable re-reads the credential
// file on every login and openvpn re-reads a CCD file on every connect. That is
// the whole reason the seam is a file and not a config block.
func syncRoster(dir string, pairs []credentialPair, ips map[string]string, netmask string) error {
	ccdPath := filepath.Join(dir, ccdDir)
	if err := os.MkdirAll(ccdPath, 0o755); err != nil {
		return fmt.Errorf("openvpn: creating %s: %w", ccdDir, err)
	}

	live := map[string]bool{}
	for _, p := range pairs {
		ip, ok := ips[p.Username]
		if !ok {
			return fmt.Errorf("openvpn: no tunnel IP assigned for user %q", p.Username)
		}
		live[ccdFileName(p.Username)] = true
		body := "# PasarGuard: static tunnel IP for this session owner\nifconfig-push " + ip + " " + netmask + "\n"
		path := filepath.Join(ccdPath, ccdFileName(p.Username))
		if err := writeSecret(path, []byte(body)); err != nil {
			return fmt.Errorf("openvpn: writing CCD for %q: %w", p.Username, err)
		}
	}
	// Prune: a CCD file left behind by a removed user would still hand that
	// common name an address. Auth would stop it, but the file is the
	// fail-closed half of ccd-exclusive and must not outlive the roster.
	entries, err := os.ReadDir(ccdPath)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || live[e.Name()] {
			continue
		}
		if err := os.Remove(filepath.Join(ccdPath, e.Name())); err != nil {
			return fmt.Errorf("openvpn: pruning stale CCD %s: %w", e.Name(), err)
		}
	}

	return writeCredentials(dir, pairs)
}

// removedNames returns who was authenticated and is not any more.
func removedNames(before []string, pairs []credentialPair) []string {
	now := map[string]bool{}
	for _, p := range pairs {
		now[p.Username] = true
	}
	var gone []string
	for _, name := range before {
		if !now[name] {
			gone = append(gone, name)
		}
	}
	slices.Sort(gone)
	return gone
}

// applyUsers installs the snapshot as the desired state and makes the running
// core match it. replace=true is SyncUsers (the whole roster), false is an
// upsert of the given users.
func (o *OpenVPN) applyUsers(ctx context.Context, users []*common.User, replace bool) error {
	o.syncMu.Lock()
	defer o.syncMu.Unlock()

	previous := o.users
	if replace {
		o.users = users
	} else {
		o.users = upsertUsers(o.users, users)
	}

	pairs, ips, err := o.roster(o.users)
	if err != nil {
		o.users = previous
		return err
	}

	// Removed users: kill their sessions FIRST, before anything else could
	// drop the rules that bound them. LEGACY-VPN.md 4d -- removing rules while
	// a tunnel is live leaves that tunnel unrestricted; killing first leaves a
	// dead session on a still-blocked address, which is the safe direction.
	if removed := removedNames(credentialNames(previous), pairs); len(removed) > 0 {
		o.killSessions(ctx, removed)
	}

	if err := syncRoster(o.dir, pairs, ips, o.cfg.Netmask); err != nil {
		o.users = previous
		return err
	}
	o.mu.Lock()
	o.ips = ips
	o.mu.Unlock()

	// Idle-when-no-users, the hysteria rule (backend/hysteria/hysteria.go:137):
	// no eligible users means no child, and Started() still answers true so the
	// panel health check stays green instead of arming a Start-retry loop.
	if len(pairs) == 0 {
		if !o.isIdle() {
			o.core.Stop()
			o.setIdle(true)
			log.Printf("openvpn core idle: no eligible users remain")
		}
		return nil
	}
	if o.isIdle() {
		return o.startFromIdle(ctx)
	}
	log.Printf("openvpn: applied user change (%d users)", len(pairs))
	return nil
}

// credentialNames is the identity set a roster authenticates.
func credentialNames(users []*common.User) []string {
	var out []string
	for _, u := range users {
		if p, err := credentialFor(u); err == nil {
			out = append(out, p.Username)
		}
	}
	return out
}

// upsertUsers merges incoming users into the current snapshot by email.
func upsertUsers(current, incoming []*common.User) []*common.User {
	next := slices.Clone(current)
	for _, in := range incoming {
		idx := slices.IndexFunc(next, func(u *common.User) bool {
			return u.GetEmail() == in.GetEmail()
		})
		if idx >= 0 {
			next[idx] = in
		} else {
			next = append(next, in)
		}
	}
	return next
}
