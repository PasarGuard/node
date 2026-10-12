package openvpn

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pasarguard/node/common"
)

func openvpnUser(id, password string) *common.User {
	return &common.User{
		Email: id,
		Proxies: &common.Proxy{
			Openvpn: &common.Openvpn{Username: id, Password: password},
		},
	}
}

func rosterCore(t *testing.T, configJSON string) *OpenVPN {
	t.Helper()
	cfg, err := NewConfig(configJSON, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &OpenVPN{cfg: cfg, dir: t.TempDir()}
}

// The whole on-disk contract of a roster: one static address per user, a CCD
// file naming it, addresses that survive a re-sync, and files for users who
// went away removed.
//
// The live test found the bug this guards — assignIPs never bound the pool, so
// the allocator walked a range it had been told nothing about and panicked.
func TestRosterWritesCCDAndKeepsAddressesStable(t *testing.T) {
	o := rosterCore(t, `{"port":1194,"server":"10.9.0.0/24"}`)

	users := []*common.User{openvpnUser("1001", "pw1"), openvpnUser("1002", "pw2")}
	pairs, ips, err := o.roster(users)
	if err != nil {
		t.Fatalf("roster: %v", err)
	}
	if len(pairs) != 2 {
		t.Fatalf("got %d pairs, want 2", len(pairs))
	}
	// The `server` directive takes base+1; clients start at base+2.
	if ips["1001"] != "10.9.0.2" || ips["1002"] != "10.9.0.3" {
		t.Errorf("addresses = %v, want 1001->10.9.0.2 and 1002->10.9.0.3", ips)
	}
	if err := syncRoster(o.dir, pairs, ips, o.cfg.Netmask()); err != nil {
		t.Fatalf("syncRoster: %v", err)
	}

	ccd := filepath.Join(o.dir, ccdDir)
	for name, want := range map[string]string{"1001": "10.9.0.2", "1002": "10.9.0.3"} {
		body, err := os.ReadFile(filepath.Join(ccd, ccdName(t, name)))
		if err != nil {
			t.Fatalf("CCD for %s: %v", name, err)
		}
		if !strings.Contains(string(body), "ifconfig-push "+want+" 255.255.255.0") {
			t.Errorf("CCD for %s does not pin %s:\n%s", name, want, body)
		}
	}

	// Stability: the same roster re-renders to the same addresses, and a new
	// user does not shuffle the existing ones (the accounting rules bind to
	// these numbers).
	grown := append(users, openvpnUser("1003", "pw3"))
	_, ips2, err := o.roster(grown)
	if err != nil {
		t.Fatal(err)
	}
	if ips2["1001"] != "10.9.0.2" || ips2["1002"] != "10.9.0.3" {
		t.Errorf("addresses moved on a roster grow: %v", ips2)
	}
	if ips2["1003"] != "10.9.0.4" {
		t.Errorf("new user got %q, want 10.9.0.4", ips2["1003"])
	}

	// Shrinking: the removed user's CCD file must go with them, or
	// ccd-exclusive would still hand that common name an address.
	pairs3, ips3, err := o.roster(users)
	if err != nil {
		t.Fatal(err)
	}
	if err := syncRoster(o.dir, pairs3, ips3, o.cfg.Netmask()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(ccd, ccdName(t, "1003"))); !os.IsNotExist(err) {
		t.Errorf("stale CCD for the removed user survived the prune: %v", err)
	}
	if _, err := os.Stat(filepath.Join(ccd, ccdName(t, "1001"))); err != nil {
		t.Errorf("CCD for a live user was pruned: %v", err)
	}
}

// A common name arrives from the wire, so the CCD file it maps to must be a
// name no filesystem can be escaped with — and openvpn looks the file up by the
// common name itself, so it cannot be encoded either. Refusal is the only
// answer that satisfies both.
func TestCCDFilenamesCannotEscapeTheDirectory(t *testing.T) {
	for _, n := range []string{"../../etc/passwd", "..", "/etc/shadow", "a/b", ".", "", `c:\evil`} {
		if name, err := ccdFileName(n); err == nil {
			t.Errorf("ccdFileName(%q) = %q, nil; want an error", n, name)
		}
	}
	// The mapping itself: openvpn reads ccd/<common name>.
	for _, n := range []string{"1001", "4242", "user@host"} {
		name, err := ccdFileName(n)
		if err != nil {
			t.Errorf("ccdFileName(%q): %v", n, err)
			continue
		}
		if name != n {
			t.Errorf("ccdFileName(%q) = %q; openvpn looks for ccd/%s", n, name, n)
		}
	}

	// Refusal happens before anything is written: a hostile common name leaves
	// the directory untouched rather than a file somewhere above it.
	o := rosterCore(t, `{"port":1194}`)
	pairs, ips, err := o.roster([]*common.User{openvpnUser("../../etc/passwd", "pw")})
	if err == nil {
		err = syncRoster(o.dir, pairs, ips, o.cfg.Netmask())
	}
	if err == nil {
		t.Fatal("a path-traversal common name was accepted")
	}
	if entries, readErr := os.ReadDir(filepath.Join(o.dir, ccdDir)); readErr == nil && len(entries) > 0 {
		t.Errorf("refused user still produced %d CCD file(s)", len(entries))
	}
}

// ccdName is ccdFileName with the test failing instead of the caller.
func ccdName(t *testing.T, user string) string {
	t.Helper()
	name, err := ccdFileName(user)
	if err != nil {
		t.Fatalf("ccdFileName(%q): %v", user, err)
	}
	return name
}

// Pool exhaustion is an error, not an address outside the pool: a user with no
// CCD file is refused by ccd-exclusive, which is the safe direction.
func TestPoolExhaustionFailsClosed(t *testing.T) {
	o := rosterCore(t, `{"port":1194,"server":"10.0.0.0/30"}`)
	var users []*common.User
	// /30 leaves exactly one assignable host (base+2).
	for i := 0; i < 2; i++ {
		users = append(users, openvpnUser(string(rune('a'+i)), "pw"))
	}
	if _, _, err := o.roster(users); err == nil {
		t.Fatal("roster with two users in a one-address pool succeeded, want exhaustion")
	}
}
