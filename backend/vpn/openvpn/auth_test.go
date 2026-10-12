package openvpn

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

var (
	authExeOnce sync.Once
	authExePath string
	authExeErr  error
)

// mustAuthExe builds the real auth executable once for the package, so these
// tests run the same program openvpn will execve — not a stand-in.
func mustAuthExe(t *testing.T) string {
	t.Helper()
	authExeOnce.Do(func() {
		// An operator — or this test running against a prebuilt binary inside a
		// container — may point at the executable directly instead of asking for
		// a Go toolchain at test time.
		if prebuilt := os.Getenv(authExecutableEnv); prebuilt != "" {
			authExePath = prebuilt
			return
		}
		dir, err := os.MkdirTemp("", "pg-ovpn-auth-build-")
		if err != nil {
			authExeErr = err
			return
		}
		out := filepath.Join(dir, "pg-ovpn-auth")
		if runtime.GOOS == "windows" {
			out += ".exe"
		}
		cmd := exec.Command("go", "build", "-o", out, "./authcmd")
		if body, err := cmd.CombinedOutput(); err != nil {
			authExeErr = &buildError{err: err, body: string(body)}
			return
		}
		authExePath = out
	})
	if authExeErr != nil {
		t.Fatalf("building the auth executable: %v", authExeErr)
	}
	return authExePath
}

type buildError struct {
	err  error
	body string
}

func (b *buildError) Error() string { return b.err.Error() + ": " + b.body }

func writeRoster(t *testing.T, pairs ...credentialPair) string {
	t.Helper()
	dir := t.TempDir()
	if err := writeCredentials(dir, pairs); err != nil {
		t.Fatalf("writeCredentials: %v", err)
	}
	return dir
}

func check(t *testing.T, dir, exe string, attempt credentialPair, wantAccept bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), authTimeout)
	defer cancel()
	err := verifyWithAuthExecutable(ctx, exe, dir, attempt)
	if wantAccept && err != nil {
		t.Errorf("username %q: rejected, want accepted: %v", attempt.Username, err)
	}
	if !wantAccept && err == nil {
		t.Errorf("username %q: accepted, want rejected", attempt.Username)
	}
}

// Positive and negative controls in one roster: the accepted case proves the
// comparison works at all, which is what makes the rejections meaningful.
func TestAuthAcceptsValidAndRejectsEverythingElse(t *testing.T) {
	exe := mustAuthExe(t)
	dir := writeRoster(t,
		credentialPair{Username: "1001", Password: "correct horse"},
		credentialPair{Username: "1002", Password: "second"},
	)

	check(t, dir, exe, credentialPair{Username: "1001", Password: "correct horse"}, true)
	check(t, dir, exe, credentialPair{Username: "1001", Password: "Correct horse"}, false) // wrong password
	check(t, dir, exe, credentialPair{Username: "1001", Password: ""}, false)              // empty password
	check(t, dir, exe, credentialPair{Username: "9999", Password: "correct horse"}, false) // unknown user
	check(t, dir, exe, credentialPair{Username: "1002", Password: "correct horse"}, false) // right password, wrong user
	check(t, dir, exe, credentialPair{Username: "1001", Password: "correct horse\n"}, false)

	// An empty roster authenticates nobody, not everyone. The failure mode of
	// a naive split is the opposite, and it is a total authentication bypass.
	empty := t.TempDir()
	if err := writeCredentials(empty, nil); err != nil {
		t.Fatal(err)
	}
	check(t, empty, exe, credentialPair{Username: "1001", Password: "correct horse"}, false)
}

// The usernames that would be an RCE if any shell ever saw them. The marker
// file is the negative control: it is what `$(touch …)` would create if the
// value were ever expanded anywhere.
func TestHostileUsernamesNeverReachAShell(t *testing.T) {
	exe := mustAuthExe(t)
	marker := filepath.Join(t.TempDir(), "pwned")

	payloads := []string{
		"$ (touch " + marker + ")",
		"$(touch " + marker + ")",
		";touch " + marker + ";",
		"||touch " + marker,
		"`touch " + marker + "`",
		"'\"; touch " + marker + "; #",
		"../../etc/passwd",
		"*",
	}
	for _, name := range payloads {
		dir := writeRoster(t, credentialPair{Username: name, Password: "pw-" + name})
		// Accepted under its own password: the comparison is byte-exact and
		// the hostile bytes are data, never syntax.
		check(t, dir, exe, credentialPair{Username: name, Password: "pw-" + name}, true)
		// Rejected under anything else, including a password that would be
		// interesting if it were ever evaluated.
		check(t, dir, exe, credentialPair{Username: name, Password: "$(id)"}, false)
	}

	if _, err := os.Stat(marker); err == nil {
		t.Fatalf("%s exists — a username reached a shell", marker)
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

// A username containing a newline or a NUL cannot be represented in the
// credential file at all, so the node refuses it at sync time rather than
// writing an entry that would authenticate somebody else.
func TestCredentialsWithNewlineOrNULAreRefused(t *testing.T) {
	dir := t.TempDir()
	bad := []credentialPair{
		{Username: "1001\n1002", Password: "x"},
		{Username: "1001", Password: "x\ny"},
		{Username: "1001", Password: "x\x00y"},
		{Username: "", Password: "x"},
		{Username: "1001", Password: ""},
	}
	for _, pair := range bad {
		if err := writeCredentials(dir, []credentialPair{pair}); err == nil {
			t.Errorf("writeCredentials accepted %+v, want it refused", pair)
		}
	}
	// And the node-side runner refuses before it ever spawns anything.
	exe := mustAuthExe(t)
	ctx, cancel := context.WithTimeout(context.Background(), authTimeout)
	defer cancel()
	attempt := credentialPair{Username: "1001\n1002", Password: "x"}
	if err := verifyWithAuthExecutable(ctx, exe, dir, attempt); err == nil {
		t.Error("verifyWithAuthExecutable accepted a username containing a newline")
	}
	if _, err := os.Stat(filepath.Join(dir, credentialsFile)); err == nil {
		t.Error("a refused credential left a credentials file behind")
	}
}

// A hanging auth executable must not wedge the node: the bound is the context,
// and there is nothing else in the path that could wait forever.
//
// The hang is this test binary re-exec'd with PG_OVPN_HANG set; TestMain in
// main_test_hook_test.go never returns in that case. That is exactly the
// failure mode of a script that blocks on a network read.
func TestHangingAuthExecutableIsBounded(t *testing.T) {
	dir := writeRoster(t, credentialPair{Username: "1001", Password: "pw"})

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	err := verifyWithAuthExecutable(ctx, os.Args[0], dir,
		credentialPair{Username: "1001", Password: "pw"}, "PG_OVPN_HANG=1")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("hanging auth executable returned success")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("hanging auth executable blocked for %s, want the context bound (~300ms)", elapsed)
	}
	t.Logf("bounded in %s: %v", elapsed, err)
}

// A missing or malformed credential file fails closed.
func TestAuthFailsClosedWhenTheRosterIsUnreadable(t *testing.T) {
	exe := mustAuthExe(t)
	missing := t.TempDir() // no users.cred at all
	check(t, missing, exe, credentialPair{Username: "1001", Password: "pw"}, false)

	truncated := t.TempDir()
	body := "only-a-username\n"
	if err := os.WriteFile(filepath.Join(truncated, credentialsFile), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	check(t, truncated, exe, credentialPair{Username: "only-a-username", Password: "x"}, false)
}
