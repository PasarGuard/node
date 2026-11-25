package wireguard

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestAmneziaLocalTunnel(t *testing.T) {
	if os.Getenv("PG_NODE_TEST_AMNEZIAWG") != "1" {
		t.Skip("requires /dev/net/tun and CAP_NET_ADMIN in an isolated network namespace")
	}
	serverKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	headerKey, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	addr := netip.MustParseAddr("10.247.19.1")
	clientAddr := netip.MustParseAddr("10.247.19.2")
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := udp.LocalAddr().String()
	port := udp.LocalAddr().(*net.UDPAddr).Port
	udp.Close()
	serverConfig, err := NewConfig(fmt.Sprintf(`{
		"interface_name":"pgn-awg-test", "private_key":"%s", "listen_port":%d,
		"address":["%s/24"], "mtu":1380,
		"amnezia":{"jc":2,"jmin":30,"jmax":60,"i1":"<r 16>",
		"s1":24,"s2":24,"s3":24,"s4":24,"header_protection_key":"%s",
		"content_padding_addition":"5-12","random_trailers":"on"}
	}`, serverKey, port, addr, headerKey))
	if err != nil {
		t.Fatal(err)
	}
	users := []*common.User{{Email: "test@example.invalid", Inbounds: []string{serverConfig.InterfaceName}, Proxies: &common.Proxy{
		Wireguard: &common.Wireguard{PublicKey: clientKey.PublicKey().String(), PeerIps: []string{clientAddr.String() + "/32"}},
	}}}
	server, err := New(&config.Config{LogBufferSize: 10, StatsUpdateIntervalSeconds: 10, StatsCleanupIntervalSeconds: 60}, serverConfig, users)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		server.Shutdown()
		if _, err := netlink.LinkByName(serverConfig.InterfaceName); err == nil {
			t.Error("AmneziaWG TUN remained after shutdown")
		}
	})

	clientTUN := tuntest.NewChannelTUN()
	client := device.NewDevice(clientTUN.TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(client.Close)
	obfuscation, err := serverConfig.Amnezia.uapi()
	if err != nil {
		t.Fatal(err)
	}
	serverPublicKey := serverKey.PublicKey()
	if err := client.IpcSet(fmt.Sprintf("%sprivate_key=%x\npublic_key=%x\nendpoint=%s\nallowed_ip=%s/32\n", obfuscation, clientKey[:], serverPublicKey[:], endpoint, addr)); err != nil {
		t.Fatal(err)
	}
	if err := client.Up(); err != nil {
		t.Fatal(err)
	}
	request := tuntest.Ping(addr, clientAddr)
	// The upstream test helper bypasses kernel checksum validation.
	setAmneziaTestChecksum(request[:20], 10)
	setAmneziaTestChecksum(request[20:], 2)
	select {
	case clientTUN.Outbound <- request:
	case <-time.After(5 * time.Second):
		t.Fatal("client did not read the ICMP request")
	}
	select {
	case reply := <-clientTUN.Inbound:
		if len(reply) < 28 || reply[20] != 0 || netip.AddrFrom4([4]byte(reply[12:16])) != addr {
			t.Fatal("expected ICMP echo reply from server tunnel address")
		}
	case <-time.After(5 * time.Second):
		state, _ := server.manager.GetDevice()
		if state != nil {
			for _, peer := range state.Peers {
				t.Logf("server peer: received %d bytes, sent %d bytes, handshake %v", peer.ReceiveBytes, peer.TransmitBytes, peer.LastHandshakeTime)
			}
		}
		t.Fatal("no echo reply through the AmneziaWG tunnel")
	}
	stats, err := server.manager.GetDevice()
	if err != nil {
		t.Fatal(err)
	}
	if len(stats.Peers) != 1 {
		t.Fatalf("got %d peers, want 1", len(stats.Peers))
	}
	peer := stats.Peers[0]
	if peer.PublicKey != clientKey.PublicKey() || peer.ReceiveBytes == 0 || peer.TransmitBytes == 0 || peer.LastHandshakeTime.IsZero() || peer.Endpoint == nil {
		t.Fatal("AmneziaWG peer counters or handshake data are missing")
	}
}

func setAmneziaTestChecksum(packet []byte, offset int) {
	binary.BigEndian.PutUint16(packet[offset:], 0)
	var sum uint32
	for i := 0; i < len(packet); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[i:]))
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	binary.BigEndian.PutUint16(packet[offset:], ^uint16(sum))
}
