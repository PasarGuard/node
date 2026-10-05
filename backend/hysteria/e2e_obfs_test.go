package hysteria

import (
	"context"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/pasarguard/node/common"
)

// TestHysteriaObfsRefusesClientWithoutPassword covers scope test 3.
//
// Enabling salamander makes the server incompatible with standard QUIC
// (docs/advanced/Full-Server-Config, "Obfuscation"), so a client without the
// obfs password cannot even complete a handshake. Both halves are asserted
// here: without the password nothing moves, with it the same client config
// otherwise identical moves bytes.
func TestHysteriaObfsRefusesClientWithoutPassword(t *testing.T) {
	exe := requirePinnedBinary(t)

	apiPort := freePort(t)
	serverPort := freeUDPPort(t)
	targetPort := startHTTPOrigin(t, 4096)

	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir)

	const email = "obfs-user"
	const password = "auth-password"
	const obfsPassword = "cry_me_a_r1ver"

	h := newTestBackend(t, exe, serverConfigJSON("127.0.0.1:"+strconv.Itoa(serverPort), certPath, keyPath, map[string]any{
		"obfs": map[string]any{
			"type":       "salamander",
			"salamander": map[string]any{"password": obfsPassword},
		},
	}), []*common.User{
		{
			Email:    email,
			Proxies:  &common.Proxy{Hysteria: &common.Hysteria{Auth: password}},
			Inbounds: []string{},
		},
	}, apiPort)

	// Negative: right auth, no obfs. Must move nothing.
	noObfsPort := freePort(t)
	noObfsCfg := writeClientConfig(t, dir, "client-no-obfs.json", clientConfigJSON(
		"127.0.0.1:"+strconv.Itoa(serverPort), email+":"+password, noObfsPort, nil))
	noObfsLog := hysteriaClient(t, exe, noObfsCfg, noObfsPort, false)

	if got := httpGetViaProxy(noObfsPort, targetPort, 8*time.Second); got != 0 {
		t.Fatalf("a client without the obfs password moved %d bytes; salamander must refuse it\nclient log:\n%s",
			got, tailFile(t, noObfsLog))
	}

	// Positive: same config plus the obfs password.
	withObfsPort := freePort(t)
	withObfsCfg := writeClientConfig(t, dir, "client-obfs.json", clientConfigJSON(
		"127.0.0.1:"+strconv.Itoa(serverPort), email+":"+password, withObfsPort, map[string]any{
			"obfs": map[string]any{
				"type":       "salamander",
				"salamander": map[string]any{"password": obfsPassword},
			},
		}))
	hysteriaClient(t, exe, withObfsCfg, withObfsPort, true)

	got := httpGetViaProxy(withObfsPort, targetPort, 20*time.Second)
	if got == 0 {
		t.Fatalf("a client with the correct obfs password moved no bytes")
	}
	t.Logf("obfs: %d bytes through a salamander-wrapped tunnel", got)

	// Only the obfs client's traffic is billed; the refused one contributes
	// nothing.
	ctx := context.Background()
	deadline := time.Now().Add(15 * time.Second)
	var total int64
	for time.Now().Before(deadline) {
		stats, err := h.GetStats(ctx, &common.StatRequest{Type: common.StatType_UsersStat, Reset_: true})
		if err != nil {
			t.Fatalf("GetStats: %v", err)
		}
		total = 0
		for _, s := range stats.GetStats() {
			if s.GetName() == email {
				total += s.GetValue()
			}
		}
		if total > 0 {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if total == 0 {
		t.Fatalf("no traffic attributed to %q after %d bytes moved through the obfs tunnel", email, got)
	}
	t.Logf("obfs per-user total: %d bytes", total)
}

// TestHysteriaMasqueradeServesProbe covers scope test 4: the masquerade target
// is served for a plain HTTP probe, so a scanner hitting the port sees a web
// site rather than a QUIC listener.
//
// Both listenHTTP and listenHTTPS are configured because hysteria refuses one
// without the other ("having only HTTP server without HTTPS is not supported",
// verified against v2.13.0).
func TestHysteriaMasqueradeServesProbe(t *testing.T) {
	exe := requirePinnedBinary(t)

	apiPort := freePort(t)
	serverPort := freeUDPPort(t)
	masqHTTPPort := freePort(t)
	masqHTTPSPort := freePort(t)

	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir)

	const body = "nothing suspicious here"

	// One user is required: hysteria refuses to start a userpass core with an
	// empty map ("invalid config: auth.userpass: empty auth userpass", verified
	// against v2.13.0), so a userless masquerade probe has to carry a throwaway
	// credential.
	h := newTestBackend(t, exe, serverConfigJSON("127.0.0.1:"+strconv.Itoa(serverPort), certPath, keyPath, map[string]any{
		"masquerade": map[string]any{
			"type": "string",
			"string": map[string]any{
				"content":    body,
				"statusCode": 200,
			},
			"listenHTTP":  "127.0.0.1:" + strconv.Itoa(masqHTTPPort),
			"listenHTTPS": "127.0.0.1:" + strconv.Itoa(masqHTTPSPort),
		},
	}), []*common.User{
		{Email: "masq-user", Proxies: &common.Proxy{Hysteria: &common.Hysteria{Auth: "masq-password"}}},
	}, apiPort)
	_ = h

	// A plain HTTP probe on the masquerade port must get the decoy body, and
	// the Alt-Svc header must point back at the QUIC port — that header is how
	// hysteria tells a real client to upgrade.
	httpBody, altSvc := probeMasquerade(t, "http://127.0.0.1:"+strconv.Itoa(masqHTTPPort))
	if httpBody != body {
		t.Errorf("masquerade HTTP body = %q, want %q", httpBody, body)
	}
	if altSvc == "" {
		t.Error("masquerade response carried no Alt-Svc header")
	} else {
		t.Logf("masquerade HTTP: body=%q Alt-Svc=%s", httpBody, altSvc)
	}

	httpsBody, httpsAltSvc := probeMasquerade(t, "https://127.0.0.1:"+strconv.Itoa(masqHTTPSPort))
	if httpsBody != body {
		t.Errorf("masquerade HTTPS body = %q, want %q", httpsBody, body)
	}
	if httpsAltSvc == "" {
		t.Error("masquerade HTTPS response carried no Alt-Svc header")
	}
}

// TestHysteriaPortHoppingConfigRenders covers scope test 5.
//
// Only the config rendering is asserted, and that is deliberate: hysteria's
// server-side port range needs nftables or iptables plus CAP_NET_ADMIN to
// redirect the range's other ports to the first one, and the docs say
// "Server-side port range listening is only supported on Linux". This host is
// Windows, so a live hop test would be testing the host, not the code. What the
// node owns — passing the range through untouched and giving it a real port —
// is asserted; whether the redirect rules land is hysteria's and the operator's.
func TestHysteriaPortHoppingConfigRenders(t *testing.T) {
	const hopRange = "127.0.0.1:20000-20010"

	cfg, err := NewConfig(`{
      "listen": "`+hopRange+`",
      "auth": {"type": "userpass", "userpass": {}}
    }`, nil)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}

	if got := cfg.Listen(); got != hopRange {
		t.Errorf("Listen() = %q, want %q; a port range must survive rendering verbatim", got, hopRange)
	}

	// The node must not rewrite a range into its first port: doing so would
	// silently disable hopping while looking configured.
	buf, err := cfg.ToBytes()
	if err != nil {
		t.Fatalf("ToBytes: %v", err)
	}
	if !containsAll(string(buf), hopRange, "20000-20010") {
		t.Errorf("rendered config lost the port range:\n%s", buf)
	}

	if runtime.GOOS != "linux" {
		t.Logf("live port-hopping UNVERIFIED: hysteria needs nftables/iptables + CAP_NET_ADMIN for a "+
			"server-side range and supports it on Linux only; this host is %s. Config rendering is asserted "+
			"above; the redirect behaviour is hysteria's, not this package's.", runtime.GOOS)
	}
}
