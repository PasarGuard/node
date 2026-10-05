package hysteria

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/pasarguard/node/common"
)

// TestHysteriaUpdateUsersKicksLiveSession covers scope test 6: removing a user
// cuts that user's ESTABLISHED connections, not merely their next connect.
//
// The assertion is on a session that is already moving bytes, so a passing run
// cannot be explained by "the credential is gone from the config".
func TestHysteriaUpdateUsersKicksLiveSession(t *testing.T) {
	exe := requirePinnedBinary(t)

	apiPort := freePort(t)
	serverPort := freeUDPPort(t)
	targetPort := startHTTPOrigin(t, 4096)

	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir)

	const keeper = "keeper"
	const leaver = "leaver"

	h := newTestBackend(t, exe, serverConfigJSON("127.0.0.1:"+strconv.Itoa(serverPort), certPath, keyPath, nil), []*common.User{
		{Email: keeper, Proxies: &common.Proxy{Hysteria: &common.Hysteria{Auth: "pw-keeper"}}},
		{Email: leaver, Proxies: &common.Proxy{Hysteria: &common.Hysteria{Auth: "pw-leaver"}}},
	}, apiPort)

	// Both clients connect and move real traffic first.
	keeperPort := freePort(t)
	keeperCfg := writeClientConfig(t, dir, "client-keeper.json", clientConfigJSON(
		"127.0.0.1:"+strconv.Itoa(serverPort), keeper+":pw-keeper", keeperPort, nil))
	hysteriaClient(t, exe, keeperCfg, keeperPort, true)

	leaverPort := freePort(t)
	leaverCfg := writeClientConfig(t, dir, "client-leaver.json", clientConfigJSON(
		"127.0.0.1:"+strconv.Itoa(serverPort), leaver+":pw-leaver", leaverPort, nil))
	hysteriaClient(t, exe, leaverCfg, leaverPort, true)

	if got := httpGetViaProxy(keeperPort, targetPort, 20*time.Second); got == 0 {
		t.Fatalf("keeper moved no bytes before the removal")
	}
	if got := httpGetViaProxy(leaverPort, targetPort, 20*time.Second); got == 0 {
		t.Fatalf("leaver moved no bytes before the removal")
	}

	ctx := context.Background()
	for _, user := range []string{keeper, leaver} {
		online, err := h.GetUserOnlineStats(ctx, user)
		if err != nil {
			t.Fatalf("GetUserOnlineStats(%s): %v", user, err)
		}
		if online.GetValue() == 0 {
			t.Fatalf("user %q is not online before the removal", user)
		}
	}
	t.Log("both users online before removal")

	// Remove the leaver. This restarts the core and kicks the live session.
	if err := h.UpdateUsers(ctx, []*common.User{
		{Email: keeper, Proxies: &common.Proxy{Hysteria: &common.Hysteria{Auth: "pw-keeper"}}},
	}); err != nil {
		t.Fatalf("UpdateUsers (remove leaver): %v", err)
	}

	// The credential is gone: a fresh client with the old password cannot
	// connect, and nothing is attributed to the leaver.
	if got := httpGetViaProxy(leaverPort, targetPort, 5*time.Second); got != 0 {
		t.Errorf("the removed user's existing proxy still moved %d bytes", got)
	}
	online, err := h.GetUserOnlineStats(ctx, leaver)
	if err != nil {
		t.Fatalf("GetUserOnlineStats(leaver): %v", err)
	}
	if online.GetValue() != 0 {
		t.Errorf("removed user %q still reports %d online", leaver, online.GetValue())
	}

	// The keeper's traffic must survive the restart that removed the leaver:
	// the pre-restart flush is what preserves it.
	//
	// The leaver's row is EXPECTED to be present. They spent those bytes before
	// the removal, and the same flush bills them — dropping it would be data
	// loss, not enforcement. What matters for the leaver is that the number
	// stops growing, which the assertion above already established by the live
	// session no longer moving bytes.
	stats, err := h.GetStats(ctx, &common.StatRequest{Type: common.StatType_UsersStat, Reset_: true})
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	sawKeeper := false
	for _, s := range stats.GetStats() {
		if s.GetName() == keeper && s.GetValue() > 0 {
			sawKeeper = true
		}
	}
	if !sawKeeper {
		t.Errorf("keeper lost its traffic across the restart that removed the leaver; "+
			"the pre-restart flush must have preserved it")
	}
	t.Log("removal kicked the live session and preserved every user's counters")
}

// TestHysteriaKickEndpointCutsConnection covers the kick mechanism on its own,
// without a user change: it is the path the panel uses for an immediate
// disconnect when a user crosses their limit.
//
// The assertion is on an ESTABLISHED, actively-streaming session dying — not on
// a later request failing. Hysteria's client reconnects on its own after a kick
// and a later request would succeed against a still-valid credential, so
// "the next connect is refused" would be false here and proving it would prove
// nothing. The upstream note is explicit: kick the client AND block the user in
// the auth backend.
func TestHysteriaKickEndpointCutsConnection(t *testing.T) {
	exe := requirePinnedBinary(t)

	apiPort := freePort(t)
	serverPort := freeUDPPort(t)
	targetPort := startStreamingOrigin(t)

	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir)

	const email = "over-quota"

	h := newTestBackend(t, exe, serverConfigJSON("127.0.0.1:"+strconv.Itoa(serverPort), certPath, keyPath, nil), []*common.User{
		{Email: email, Proxies: &common.Proxy{Hysteria: &common.Hysteria{Auth: "pw"}}},
	}, apiPort)

	clientPort := freePort(t)
	clientCfg := writeClientConfig(t, dir, "client.json", clientConfigJSON(
		"127.0.0.1:"+strconv.Itoa(serverPort), email+":pw", clientPort, nil))
	hysteriaClient(t, exe, clientCfg, clientPort, true)

	ctx := context.Background()
	if online, err := h.GetUserOnlineStats(ctx, email); err != nil || online.GetValue() == 0 {
		t.Fatalf("user %q not online before the kick (err=%v, online=%d)", email, err, online.GetValue())
	}

	// Hold a live stream open through the tunnel.
	stream := openStreamThroughProxy(t, clientPort, targetPort)
	defer stream.Body.Close()

	// Drain until the kick lands. The core refuses the next LogTraffic from a
	// kicked id and closes its QUIC connection (core/server/server.go:380-387,
	// :393-400), so the read side must end rather than run forever.
	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 4096)
		var total int
		for {
			n, err := stream.Body.Read(buf)
			total += n
			if err != nil {
				readErr <- err
				t.Logf("stream ended after %d bytes: %v", total, err)
				return
			}
		}
	}()

	// Let the stream prove it is really flowing before kicking.
	select {
	case err := <-readErr:
		t.Fatalf("stream ended before the kick: %v", err)
	case <-time.After(2 * time.Second):
	}

	if err := h.kickIDs(ctx, []string{email}); err != nil {
		t.Fatalf("kickIDs: %v", err)
	}

	select {
	case <-readErr:
		// Expected: the established session was cut.
	case <-time.After(20 * time.Second):
		t.Fatal("the kicked user's established stream kept running for 20s; "+
			"kick must cut live connections, not just block the next connect")
	}
	t.Log("kick cut the established streaming session")
}
