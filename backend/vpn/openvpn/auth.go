package openvpn

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/pasarguard/node/config"
)

// The auth executable is a separate program, not a shell script. That is the
// whole point of the seam: `auth-user-pass-verify <path> via-file` execve()s
// whatever is at <path> with the temp credential file as argv[1], so with an
// ELF/PE binary at the end of it there is no shell anywhere on the path a
// username travels — `$(reboot)` and `;rm -rf` are just bytes to compare.
//
// openvpn inherits this process's environment and passes it to the executable,
// so the credential file path travels as an env var rather than as an argument
// openvpn would have to parse (it passes exactly one: the temp file).
const (
	authExecutableEnv = "OPENVPN_AUTH_EXECUTABLE_PATH"
	defaultAuthExe    = "/usr/local/bin/pg-ovpn-auth"
	credentialsEnv    = "PG_OVPN_CREDENTIALS"
	credentialsFile   = "users.cred"
)

// authTimeout bounds every node-side run of the auth executable: the start-up
// self-check and the tests. openvpn itself runs the executable per login and
// has no timeout of its own, which is exactly why it is a binary that does one
// bounded read-and-compare and exits.
const authTimeout = 5 * time.Second

// authExecutable resolves the binary the config points at.
func authExecutable() string {
	if custom := config.GetEnv(authExecutableEnv, ""); custom != "" {
		return custom
	}
	return defaultAuthExe
}

// credentialPair is one synced user: username first, password second, exactly
// the two lines the file is made of.
type credentialPair struct {
	Username string
	Password string
}

// validateCredential rejects what the file format cannot represent.
//
// The file is line-delimited, so a newline or a NUL in either field would let
// one user's entry be read as two — or as somebody else's. This is a trust
// boundary: the values come off the wire from the panel.
func validateCredential(username, password string) error {
	for _, field := range []struct{ name, value string }{
		{"username", username},
		{"password", password},
	} {
		if field.value == "" {
			return fmt.Errorf("openvpn: %s is empty for user %q", field.name, username)
		}
		if strings.ContainsAny(field.value, "\r\n\x00") {
			return fmt.Errorf("openvpn: %s for user %q contains a newline or NUL", field.name, username)
		}
	}
	return nil
}

// writeCredentials writes the roster as alternating username/password lines.
//
// Atomic (temp file + rename) so a login that lands mid-sync reads either the
// old roster or the new one, never a half-written one.
func writeCredentials(dir string, pairs []credentialPair) error {
	var b strings.Builder
	for _, p := range pairs {
		if err := validateCredential(p.Username, p.Password); err != nil {
			return err
		}
		b.WriteString(p.Username)
		b.WriteByte('\n')
		b.WriteString(p.Password)
		b.WriteByte('\n')
	}
	final := filepath.Join(dir, credentialsFile)
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return fmt.Errorf("openvpn: writing %s: %w", credentialsFile, err)
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("openvpn: installing %s: %w", credentialsFile, err)
	}
	return nil
}

// verifyWithAuthExecutable runs the same program openvpn runs, the same way
// openvpn runs it, with the caller's context as the bound.
//
// It exists so the node can prove its own auth path at start (a roster the
// executable cannot read is otherwise discovered at a user's first login) and
// so a test can prove a hung executable cannot hold the node: ctx is the only
// timeout there is.
func verifyWithAuthExecutable(ctx context.Context, exe, dir string, attempt credentialPair, extraEnv ...string) error {
	if err := validateCredential(attempt.Username, attempt.Password); err != nil {
		return err
	}
	tmpDir, err := os.MkdirTemp("", "pg-ovpn-auth-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)
	if err := os.Chmod(tmpDir, 0o700); err != nil {
		return err
	}
	// Same two-line layout openvpn writes for `via-file`.
	userFile := filepath.Join(tmpDir, "creds")
	body := attempt.Username + "\n" + attempt.Password + "\n"
	if err := os.WriteFile(userFile, []byte(body), 0o600); err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, exe, userFile)
	cmd.Env = append(os.Environ(),
		credentialsEnv+"="+filepath.Join(dir, credentialsFile),
	)
	cmd.Env = append(cmd.Env, extraEnv...)
	// stdout/stderr are not connected: the executable must not be able to put a
	// password on the node's own log either.
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("openvpn: auth verification did not finish within %s: %w", authTimeout, ctx.Err())
		}
		return fmt.Errorf("openvpn: credentials rejected by %s", exe)
	}
	return nil
}
