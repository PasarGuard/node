//go:build integration
// +build integration

package wireguard

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	statsGatherWait    = 11 * time.Second
	connectRetryWindow = 8 * time.Second
)

// TestMain enforces required privileges/tools for WireGuard E2E integration tests.
func TestMain(m *testing.M) {
	if os.Geteuid() != 0 {
		fmt.Println("WireGuard E2E integration tests must run as root/sudo")
		fmt.Println("Run with: sudo go test -tags=integration -v ./backend/wireguard")
		os.Exit(1)
	}

	for _, name := range []string{"ip", "wg", "curl"} {
		if _, err := exec.LookPath(name); err != nil {
			fmt.Printf("required command %q not found: %v\n", name, err)
			os.Exit(1)
		}
	}

	os.Exit(m.Run())
}

type namespaceFixture struct {
	name          string
	hostVeth      string
	nsVeth        string
	hostTransitIP string
}

func createTestWireGuardWithUsers(t *testing.T, configJSON string, users []*common.User) *WireGuard {
	t.Helper()

	wgConfig, err := NewConfig(configJSON)
	if err != nil {
		t.Fatalf("Failed to create WireGuard config: %v", err)
	}

	cfg := &config.Config{
		LogBufferSize:               100,
		StatsUpdateIntervalSeconds:  10,
		StatsCleanupIntervalSeconds: 300,
	}

	wg, err := New(cfg, wgConfig, users)
	if err != nil {
		t.Fatalf("Failed to create WireGuard instance: %v", err)
	}

	return wg
}

func createTestWireGuard(t *testing.T, configJSON string) *WireGuard {
	t.Helper()
	return createTestWireGuardWithUsers(t, configJSON, []*common.User{})
}

func mustHaveCommands(t *testing.T, names ...string) {
	t.Helper()
	for _, name := range names {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatalf("required command %q not found: %v", name, err)
		}
	}
}

func runCommand(t *testing.T, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %s %s\nerror: %v\noutput: %s", name, strings.Join(args, " "), err, string(output))
	}
	return string(output)
}

func runCommandNoFail(name string, args ...string) {
	_ = exec.Command(name, args...).Run()
}

func runInNamespace(ns string, args ...string) (string, error) {
	cmdArgs := append([]string{"netns", "exec", ns}, args...)
	cmd := exec.Command("ip", cmdArgs...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func createNamespaceFixture(t *testing.T, id int) *namespaceFixture {
	t.Helper()

	ns := fmt.Sprintf("wg-e2e-%d", id)
	hostVeth := fmt.Sprintf("vethh%d", id)
	nsVeth := fmt.Sprintf("vethn%d", id)
	hostTransitIP := fmt.Sprintf("172.30.%d.1", id)
	nsTransitIP := fmt.Sprintf("172.30.%d.2", id)
	transitCIDRHost := hostTransitIP + "/30"
	transitCIDRNS := nsTransitIP + "/30"

	// Best-effort cleanup in case a previous run left stale resources.
	runCommandNoFail("ip", "netns", "del", ns)
	runCommandNoFail("ip", "link", "del", hostVeth)

	runCommand(t, "ip", "netns", "add", ns)
	runCommand(t, "ip", "link", "add", hostVeth, "type", "veth", "peer", "name", nsVeth)
	runCommand(t, "ip", "link", "set", nsVeth, "netns", ns)
	runCommand(t, "ip", "addr", "add", transitCIDRHost, "dev", hostVeth)
	runCommand(t, "ip", "link", "set", hostVeth, "up")
	runCommand(t, "ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up")
	runCommand(t, "ip", "netns", "exec", ns, "ip", "addr", "add", transitCIDRNS, "dev", nsVeth)
	runCommand(t, "ip", "netns", "exec", ns, "ip", "link", "set", nsVeth, "up")

	t.Cleanup(func() {
		runCommandNoFail("ip", "link", "del", hostVeth)
		runCommandNoFail("ip", "netns", "del", ns)
	})

	return &namespaceFixture{
		name:          ns,
		hostVeth:      hostVeth,
		nsVeth:        nsVeth,
		hostTransitIP: hostTransitIP,
	}
}

func wireGuardServerIPByFamily(t *testing.T, wg *WireGuard, wantIPv6 bool) string {
	t.Helper()
	if len(wg.config.Address) == 0 {
		t.Fatalf("server has no addresses configured")
	}
	for _, addr := range wg.config.Address {
		ip, _, err := net.ParseCIDR(addr)
		if err != nil {
			t.Fatalf("invalid server address %q: %v", addr, err)
		}
		isIPv6 := ip.To4() == nil
		if isIPv6 == wantIPv6 {
			return ip.String()
		}
	}

	family := "IPv4"
	if wantIPv6 {
		family = "IPv6"
	}
	t.Fatalf("server has no %s address in config: %v", family, wg.config.Address)
	return ""
}

func wireGuardServerIP(t *testing.T, wg *WireGuard) string {
	t.Helper()
	return wireGuardServerIPByFamily(t, wg, false)
}

func wireGuardServerPublicKey(t *testing.T, wg *WireGuard) string {
	t.Helper()
	privateKey, err := wgtypes.ParseKey(wg.config.PrivateKey)
	if err != nil {
		t.Fatalf("failed to parse wireguard private key: %v", err)
	}
	return privateKey.PublicKey().String()
}

func startWGHTTPServerAtIP(t *testing.T, serverIP string) string {
	t.Helper()

	listener, err := net.Listen("tcp", net.JoinHostPort(serverIP, "0"))
	if err != nil {
		t.Fatalf("failed to start test webserver on %s: %v", serverIP, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	server := &http.Server{
		Handler: mux,
	}

	go func() {
		_ = server.Serve(listener)
	}()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})

	port := listener.Addr().(*net.TCPAddr).Port
	return fmt.Sprintf("http://%s/health", net.JoinHostPort(serverIP, strconv.Itoa(port)))
}

func startWGHTTPServer(t *testing.T, wg *WireGuard) (url string, serverIP string) {
	t.Helper()

	serverIP = wireGuardServerIP(t, wg)
	url = startWGHTTPServerAtIP(t, serverIP)
	return url, serverIP
}

func mustGeneratePrivateKey(t *testing.T) string {
	t.Helper()
	privateKey, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}
	return privateKey
}

func buildWGUser(email, publicKey, peerIP, iface string, includeInterface bool) *common.User {
	return buildWGUserWithPeerIPs(email, publicKey, []string{peerIP}, iface, includeInterface)
}

func buildWGUserWithPeerIPs(email, publicKey string, peerIPs []string, iface string, includeInterface bool) *common.User {
	inbounds := []string{}
	if includeInterface {
		inbounds = []string{iface}
	}

	return &common.User{
		Email:    email,
		Inbounds: inbounds,
		Proxies: &common.Proxy{
			Wireguard: &common.Wireguard{
				PublicKey: publicKey,
				PeerIps:   append([]string(nil), peerIPs...),
			},
		},
	}
}

func mustUserPeerIPByFamily(t *testing.T, wg *WireGuard, email string, wantIPv6 bool) string {
	t.Helper()
	peer := wg.peerStore.GetByEmail(email)
	if peer == nil {
		t.Fatalf("no peer found for %s", email)
	}
	if len(peer.AllowedIPs) == 0 {
		t.Fatalf("peer %s has no allowed IP", email)
	}
	for _, allowedIP := range peer.AllowedIPs {
		ip, _, err := net.ParseCIDR(allowedIP.String())
		if err != nil {
			t.Fatalf("invalid allowed ip %q for %s: %v", allowedIP, email, err)
		}
		isIPv6 := ip.To4() == nil
		if isIPv6 == wantIPv6 {
			return ip.String()
		}
	}

	family := "IPv4"
	if wantIPv6 {
		family = "IPv6"
	}
	t.Fatalf("peer %s has no %s allowed IP", email, family)
	return ""
}

func mustUserPeerIP(t *testing.T, wg *WireGuard, email string) string {
	t.Helper()
	return mustUserPeerIPByFamily(t, wg, email, false)
}

func configureNamespaceWGClient(
	t *testing.T,
	ns *namespaceFixture,
	iface string,
	clientPrivateKey string,
	clientWGIP string,
	serverPublicKey string,
	serverEndpointPort int,
	serverWGIP string,
) {
	t.Helper()

	keyFile, err := os.CreateTemp("", "wg-client-key-*")
	if err != nil {
		t.Fatalf("failed to create temp key file: %v", err)
	}
	if _, err = keyFile.WriteString(clientPrivateKey + "\n"); err != nil {
		_ = keyFile.Close()
		t.Fatalf("failed to write temp key file: %v", err)
	}
	if err = keyFile.Close(); err != nil {
		t.Fatalf("failed to close temp key file: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Remove(keyFile.Name())
	})

	runCommand(t, "ip", "netns", "exec", ns.name, "ip", "link", "add", "dev", iface, "type", "wireguard")
	runCommand(t, "ip", "netns", "exec", ns.name, "ip", "address", "add", clientWGIP+"/32", "dev", iface)

	endpoint := fmt.Sprintf("%s:%d", ns.hostTransitIP, serverEndpointPort)
	runCommand(
		t,
		"ip", "netns", "exec", ns.name,
		"wg", "set", iface,
		"private-key", keyFile.Name(),
		"peer", serverPublicKey,
		"endpoint", endpoint,
		"allowed-ips", serverWGIP+"/32",
	)

	runCommand(t, "ip", "netns", "exec", ns.name, "ip", "link", "set", "up", "dev", iface)
	runCommand(t, "ip", "netns", "exec", ns.name, "ip", "route", "replace", serverWGIP+"/32", "dev", iface)
}

func configureNamespaceWGClientDualStack(
	t *testing.T,
	ns *namespaceFixture,
	iface string,
	clientPrivateKey string,
	clientWGIPv4 string,
	clientWGIPv6 string,
	serverPublicKey string,
	serverEndpointPort int,
	serverWGIPv4 string,
	serverWGIPv6 string,
) {
	t.Helper()

	keyFile, err := os.CreateTemp("", "wg-client-key-*")
	if err != nil {
		t.Fatalf("failed to create temp key file: %v", err)
	}
	if _, err = keyFile.WriteString(clientPrivateKey + "\n"); err != nil {
		_ = keyFile.Close()
		t.Fatalf("failed to write temp key file: %v", err)
	}
	if err = keyFile.Close(); err != nil {
		t.Fatalf("failed to close temp key file: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Remove(keyFile.Name())
	})

	runCommand(t, "ip", "netns", "exec", ns.name, "ip", "link", "add", "dev", iface, "type", "wireguard")
	runCommand(t, "ip", "netns", "exec", ns.name, "ip", "address", "add", clientWGIPv4+"/32", "dev", iface)
	runCommand(t, "ip", "netns", "exec", ns.name, "ip", "address", "add", clientWGIPv6+"/128", "dev", iface)

	endpoint := fmt.Sprintf("%s:%d", ns.hostTransitIP, serverEndpointPort)
	allowedIPs := fmt.Sprintf("%s/32,%s/128", serverWGIPv4, serverWGIPv6)
	runCommand(
		t,
		"ip", "netns", "exec", ns.name,
		"wg", "set", iface,
		"private-key", keyFile.Name(),
		"peer", serverPublicKey,
		"endpoint", endpoint,
		"allowed-ips", allowedIPs,
	)

	runCommand(t, "ip", "netns", "exec", ns.name, "ip", "link", "set", "up", "dev", iface)
	runCommand(t, "ip", "netns", "exec", ns.name, "ip", "route", "replace", serverWGIPv4+"/32", "dev", iface)
	runCommand(t, "ip", "netns", "exec", ns.name, "ip", "-6", "route", "replace", serverWGIPv6+"/128", "dev", iface)
}

func waitForHTTPReachable(t *testing.T, nsName, url string) {
	t.Helper()
	deadline := time.Now().Add(connectRetryWindow)
	var lastErr error
	var lastOutput string

	for time.Now().Before(deadline) {
		output, err := runInNamespace(nsName, "curl", "-fsS", "--max-time", "2", url)
		if err == nil {
			return
		}
		lastErr = err
		lastOutput = output
		time.Sleep(500 * time.Millisecond)
	}

	t.Fatalf("expected connection success from namespace %s to %s, err=%v output=%s", nsName, url, lastErr, lastOutput)
}

func expectHTTPUnreachable(t *testing.T, nsName, url string) {
	t.Helper()
	for i := 0; i < 3; i++ {
		output, err := runInNamespace(nsName, "curl", "-fsS", "--max-time", "2", url)
		if err == nil {
			t.Fatalf("expected connection failure from namespace %s to %s, got success: %s", nsName, url, output)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func sendHTTPRequests(t *testing.T, nsName, url string, count int) {
	t.Helper()
	for i := 0; i < count; i++ {
		output, err := runInNamespace(nsName, "curl", "-fsS", "--max-time", "2", url)
		if err != nil {
			t.Fatalf("failed to send traffic from namespace %s to %s, err=%v output=%s", nsName, url, err, output)
		}
	}
}

func userTrafficTotal(t *testing.T, wg *WireGuard, email string) int64 {
	t.Helper()
	response, err := wg.GetStats(context.Background(), &common.StatRequest{
		Name:   email,
		Type:   common.StatType_UserStat,
		Reset_: false,
	})
	if err != nil {
		t.Fatalf("failed to get stats for %s: %v", email, err)
	}

	var total int64
	for _, stat := range response.GetStats() {
		total += stat.GetValue()
	}
	return total
}

func userOnline(t *testing.T, wg *WireGuard, email string) int64 {
	t.Helper()
	online, err := wg.GetUserOnlineStats(context.Background(), email)
	if err != nil {
		t.Fatalf("failed to get online stats for %s: %v", email, err)
	}
	return online.GetValue()
}

func runConnectDisconnectAssertions(
	t *testing.T,
	wg *WireGuard,
	allowedEmail string,
	deniedEmail string,
	allowedNS string,
	deniedNS string,
	url string,
) {
	t.Helper()

	beforeAllowed := userTrafficTotal(t, wg, allowedEmail)

	waitForHTTPReachable(t, allowedNS, url)
	sendHTTPRequests(t, allowedNS, url, 4)
	expectHTTPUnreachable(t, deniedNS, url)

	time.Sleep(statsGatherWait)

	afterAllowed := userTrafficTotal(t, wg, allowedEmail)
	if afterAllowed <= beforeAllowed {
		t.Fatalf("expected traffic for %s to increase, before=%d after=%d", allowedEmail, beforeAllowed, afterAllowed)
	}

	if online := userOnline(t, wg, allowedEmail); online != 1 {
		t.Fatalf("expected %s to be online, got %d", allowedEmail, online)
	}

	if online := userOnline(t, wg, deniedEmail); online != 0 {
		t.Fatalf("expected %s to be offline, got %d", deniedEmail, online)
	}
}

func TestIntegrationE2EStartupUsers(t *testing.T) {
	mustHaveCommands(t, "ip", "wg", "curl")

	const (
		iface           = "wg-e2e-su"
		wgPort          = 51931
		configCIDRv4    = "10.210.1.1/24"
		configCIDRv6    = "fd10:210:1::1/64"
		allowedUser     = "allowed-startup@example.com"
		deniedUser      = "denied-startup@example.com"
		allowedPeerIPv4 = "10.210.1.2/32"
		allowedPeerIPv6 = "fd10:210:1::2/128"
	)

	serverPrivateKey := mustGeneratePrivateKey(t)

	allowedPriv, allowedPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate allowed user keys: %v", err)
	}
	deniedPriv, deniedPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate denied user keys: %v", err)
	}

	configJSON := fmt.Sprintf(
		`{"interface_name":"%s","listen_port":%d,"private_key":"%s","address":["%s","%s"],"tag":"test-node"}`,
		iface, wgPort, serverPrivateKey, configCIDRv4, configCIDRv6,
	)
	startupUsers := []*common.User{
		buildWGUserWithPeerIPs(allowedUser, allowedPub, []string{allowedPeerIPv4, allowedPeerIPv6}, iface, true),
		buildWGUser(deniedUser, deniedPub, "10.210.1.3/32", iface, false),
	}

	wg := createTestWireGuardWithUsers(t, configJSON, startupUsers)
	defer wg.Shutdown()

	urlIPv4, serverWGIPv4 := startWGHTTPServer(t, wg)
	serverWGIPv6 := wireGuardServerIPByFamily(t, wg, true)
	urlIPv6 := startWGHTTPServerAtIP(t, serverWGIPv6)
	serverPublicKey := wireGuardServerPublicKey(t, wg)

	allowedNS := createNamespaceFixture(t, 61)
	deniedNS := createNamespaceFixture(t, 62)

	configureNamespaceWGClientDualStack(
		t,
		allowedNS,
		"wgc0",
		allowedPriv,
		mustUserPeerIPByFamily(t, wg, allowedUser, false),
		mustUserPeerIPByFamily(t, wg, allowedUser, true),
		serverPublicKey,
		wgPort,
		serverWGIPv4,
		serverWGIPv6,
	)
	configureNamespaceWGClientDualStack(
		t,
		deniedNS,
		"wgc1",
		deniedPriv,
		"10.210.1.250",
		"fd10:210:1::250",
		serverPublicKey,
		wgPort,
		serverWGIPv4,
		serverWGIPv6,
	)

	runConnectDisconnectAssertions(t, wg, allowedUser, deniedUser, allowedNS.name, deniedNS.name, urlIPv4)
	waitForHTTPReachable(t, allowedNS.name, urlIPv6)
	sendHTTPRequests(t, allowedNS.name, urlIPv6, 2)
	expectHTTPUnreachable(t, deniedNS.name, urlIPv6)
}

func TestIntegrationE2ESyncUser(t *testing.T) {
	mustHaveCommands(t, "ip", "wg", "curl")

	const (
		iface       = "wg-e2e-su2"
		wgPort      = 51932
		configCIDR  = "10.210.2.1/24"
		allowedUser = "allowed-syncuser@example.com"
		deniedUser  = "denied-syncuser@example.com"
	)

	serverPrivateKey := mustGeneratePrivateKey(t)

	allowedPriv, allowedPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate allowed user keys: %v", err)
	}
	deniedPriv, deniedPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate denied user keys: %v", err)
	}

	configJSON := fmt.Sprintf(
		`{"interface_name":"%s","listen_port":%d,"private_key":"%s","address":["%s"],"tag":"test-node"}`,
		iface, wgPort, serverPrivateKey, configCIDR,
	)
	wg := createTestWireGuard(t, configJSON)
	defer wg.Shutdown()

	if err := wg.SyncUser(context.Background(), buildWGUser(allowedUser, allowedPub, "10.210.2.2/32", iface, true)); err != nil {
		t.Fatalf("failed SyncUser for allowed user: %v", err)
	}
	if err := wg.SyncUser(context.Background(), buildWGUser(deniedUser, deniedPub, "10.210.2.3/32", iface, false)); err != nil {
		t.Fatalf("failed SyncUser for denied user: %v", err)
	}

	url, serverWGIP := startWGHTTPServer(t, wg)
	serverPublicKey := wireGuardServerPublicKey(t, wg)

	allowedNS := createNamespaceFixture(t, 63)
	deniedNS := createNamespaceFixture(t, 64)

	configureNamespaceWGClient(t, allowedNS, "wgc0", allowedPriv, mustUserPeerIP(t, wg, allowedUser), serverPublicKey, wgPort, serverWGIP)
	configureNamespaceWGClient(t, deniedNS, "wgc1", deniedPriv, "10.210.2.250", serverPublicKey, wgPort, serverWGIP)

	runConnectDisconnectAssertions(t, wg, allowedUser, deniedUser, allowedNS.name, deniedNS.name, url)
}

func TestIntegrationE2ESyncUsers(t *testing.T) {
	mustHaveCommands(t, "ip", "wg", "curl")

	const (
		iface       = "wg-e2e-sus"
		wgPort      = 51933
		configCIDR  = "10.210.3.1/24"
		allowedUser = "allowed-syncusers@example.com"
		deniedUser  = "denied-syncusers@example.com"
	)

	serverPrivateKey := mustGeneratePrivateKey(t)

	allowedPriv, allowedPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate allowed user keys: %v", err)
	}
	deniedPriv, deniedPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate denied user keys: %v", err)
	}

	configJSON := fmt.Sprintf(
		`{"interface_name":"%s","listen_port":%d,"private_key":"%s","address":["%s"],"tag":"test-node"}`,
		iface, wgPort, serverPrivateKey, configCIDR,
	)
	wg := createTestWireGuard(t, configJSON)
	defer wg.Shutdown()

	users := []*common.User{
		buildWGUser(allowedUser, allowedPub, "10.210.3.2/32", iface, true),
		buildWGUser(deniedUser, deniedPub, "10.210.3.3/32", iface, false),
	}
	if err := wg.SyncUsers(context.Background(), users); err != nil {
		t.Fatalf("failed SyncUsers: %v", err)
	}

	url, serverWGIP := startWGHTTPServer(t, wg)
	serverPublicKey := wireGuardServerPublicKey(t, wg)

	allowedNS := createNamespaceFixture(t, 65)
	deniedNS := createNamespaceFixture(t, 66)

	configureNamespaceWGClient(t, allowedNS, "wgc0", allowedPriv, mustUserPeerIP(t, wg, allowedUser), serverPublicKey, wgPort, serverWGIP)
	configureNamespaceWGClient(t, deniedNS, "wgc1", deniedPriv, "10.210.3.250", serverPublicKey, wgPort, serverWGIP)

	runConnectDisconnectAssertions(t, wg, allowedUser, deniedUser, allowedNS.name, deniedNS.name, url)
}

func TestIntegrationE2EUpdateUsers(t *testing.T) {
	mustHaveCommands(t, "ip", "wg", "curl")

	const (
		iface       = "wg-e2e-upd"
		wgPort      = 51934
		configCIDR  = "10.210.4.1/24"
		allowedUser = "allowed-update@example.com"
		deniedUser  = "denied-update@example.com"
	)

	serverPrivateKey := mustGeneratePrivateKey(t)

	allowedPriv, allowedPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate allowed user keys: %v", err)
	}
	deniedPriv, deniedPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate denied user keys: %v", err)
	}

	configJSON := fmt.Sprintf(
		`{"interface_name":"%s","listen_port":%d,"private_key":"%s","address":["%s"],"tag":"test-node"}`,
		iface, wgPort, serverPrivateKey, configCIDR,
	)
	wg := createTestWireGuard(t, configJSON)
	defer wg.Shutdown()

	seedUsers := []*common.User{
		buildWGUser(allowedUser, allowedPub, "10.210.4.2/32", iface, true),
		buildWGUser(deniedUser, deniedPub, "10.210.4.3/32", iface, true),
	}
	if err := wg.SyncUsers(context.Background(), seedUsers); err != nil {
		t.Fatalf("failed initial SyncUsers seed: %v", err)
	}

	deniedOldIP := mustUserPeerIP(t, wg, deniedUser)

	updateUsers := []*common.User{
		buildWGUser(allowedUser, allowedPub, "10.210.4.2/32", iface, true),
		buildWGUser(deniedUser, deniedPub, "10.210.4.3/32", iface, false),
	}
	if err := wg.UpdateUsers(context.Background(), updateUsers); err != nil {
		t.Fatalf("failed UpdateUsers: %v", err)
	}

	if peer := wg.peerStore.GetByEmail(deniedUser); peer != nil {
		t.Fatalf("expected denied user peers removed after UpdateUsers, got peer with key %s", peer.PublicKey)
	}

	url, serverWGIP := startWGHTTPServer(t, wg)
	serverPublicKey := wireGuardServerPublicKey(t, wg)

	allowedNS := createNamespaceFixture(t, 67)
	deniedNS := createNamespaceFixture(t, 68)

	configureNamespaceWGClient(t, allowedNS, "wgc0", allowedPriv, mustUserPeerIP(t, wg, allowedUser), serverPublicKey, wgPort, serverWGIP)
	configureNamespaceWGClient(t, deniedNS, "wgc1", deniedPriv, deniedOldIP, serverPublicKey, wgPort, serverWGIP)

	runConnectDisconnectAssertions(t, wg, allowedUser, deniedUser, allowedNS.name, deniedNS.name, url)
}
