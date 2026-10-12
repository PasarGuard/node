package openvpn

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	nodeLogger "github.com/pasarguard/node/logger"
)

// grepSecrets walks a tree and reports every file (outside the deliberate
// carriers) that contains one of the secrets. It is the whole assertion of
// this test, so it is deliberately dumb: no globs, no ignore lists beyond the
// two files whose job is to hold a secret.
func grepSecrets(t *testing.T, root string, secrets map[string]string, carriers map[string]bool) []string {
	t.Helper()
	var hits []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if carriers[path] {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for label, secret := range secrets {
			if bytes.Contains(body, []byte(secret)) {
				hits = append(hits, path+" -> "+label)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return hits
}

// The management password and a user password must exist nowhere in the
// generated tree except the two 0600 files whose entire purpose is to carry
// them, and nowhere at all in the core's log.
//
// The planted-secret control is what makes this check worth running: the same
// grep has to be able to find the secret when it is there, or "zero hits"
// only proves the walk visited nothing.
func TestSecretHygiene(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "core-1")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	mgmtSecret := "mgmt-" + randomHex(t)
	userSecret := "user-" + randomHex(t)
	t.Setenv(mgmtPasswordEnv, mgmtSecret)

	if err := ensurePKI(dir, &Config{}); err != nil {
		t.Fatal(err)
	}
	mgmtPassword, err := managementPassword(dir)
	if err != nil {
		t.Fatal(err)
	}
	if mgmtPassword != mgmtSecret {
		t.Fatalf("managementPassword = %q, want the pinned %q", mgmtPassword, mgmtSecret)
	}

	cfg, err := NewConfig(`{"port":1194,"dns":["1.1.1.1"]}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	text := cfg.Render(RenderOptions{
		AuthExecutable:         "/usr/local/bin/pg-ovpn-auth",
		ManagementSocket:       filepath.Join(dir, mgmtSocketFile),
		ManagementPasswordFile: filepath.Join(dir, mgmtPasswordFile),
		ClientConfigDir:        ccdDir,
	})
	if err := writeServerConfig(dir, text); err != nil {
		t.Fatal(err)
	}
	pairs := []credentialPair{{Username: "1001", Password: userSecret}}
	if err := syncRoster(dir, pairs, map[string]string{"1001": "10.8.0.2"}, cfg.Netmask()); err != nil {
		t.Fatal(err)
	}

	// A real log, written the way the core writes one: BindOnce(configDir) so
	// core-<id>.log exists. Nothing here is a secret, and that is the point —
	// the log path has no reason to ever see one.
	logger := nodeLogger.New(false)
	logger.BindOnce(dir)
	logger.Log(nodeLogger.LogInfo, "openvpn started, Version: 2.6.19")
	logger.Log(nodeLogger.LogError, "TLS Error: TLS handshake failed")
	logger.Close()
	if _, err := os.Stat(filepath.Join(root, "core-1.log")); err != nil {
		t.Fatalf("core-1.log was not written by logger.BindOnce(configDir): %v", err)
	}

	secrets := map[string]string{
		"management password": mgmtSecret,
		"user password":       userSecret,
	}
	carriers := map[string]bool{
		filepath.Join(dir, mgmtPasswordFile): true,
		filepath.Join(dir, credentialsFile):  true,
	}
	if hits := grepSecrets(t, root, secrets, carriers); len(hits) > 0 {
		t.Errorf("secrets found outside their 0600 carriers:\n  %s", strings.Join(hits, "\n  "))
	}

	// The two carriers are private, and the config that *names* them is too.
	for _, name := range []string{mgmtPasswordFile, credentialsFile, "server.conf", tlsCryptFile, serverKey, caKeyFile} {
		if runtime.GOOS == "windows" {
			break
		}
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("%s mode = %o, want 600", name, mode)
		}
	}

	// Negative control: plant the same secret and prove the walk finds it.
	planted := filepath.Join(dir, "core-1.log.planted")
	if err := os.WriteFile(planted, []byte("accidentally logged: "+mgmtSecret), 0o644); err != nil {
		t.Fatal(err)
	}
	if hits := grepSecrets(t, root, secrets, carriers); len(hits) == 0 {
		t.Fatal("grep found nothing in a file that contains the secret — the check is vacuous")
	} else {
		t.Logf("negative control found: %s", strings.Join(hits, ", "))
	}
	if err := os.Remove(planted); err != nil {
		t.Fatal(err)
	}
	if hits := grepSecrets(t, root, secrets, carriers); len(hits) > 0 {
		t.Errorf("secrets still present after removing the planted file:\n  %s", strings.Join(hits, "\n  "))
	}
}

func randomHex(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(buf)
}
