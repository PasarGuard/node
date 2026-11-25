package wireguard

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type amneziaClient struct {
	device *device.Device
}

func newAmneziaManager(name string, cfg AmneziaConfig) (*Manager, error) {
	settings, err := cfg.uapi()
	if err != nil {
		return nil, err
	}
	client := &amneziaClient{}
	return &Manager{
		client:    client,
		iFaceName: name,
		createLink: func() error {
			if _, err := netlink.LinkByName(name); err == nil {
				return fmt.Errorf("AmneziaWG interface %q already exists", name)
			} else if !errors.As(err, new(netlink.LinkNotFoundError)) {
				return fmt.Errorf("checking AmneziaWG interface: %w", err)
			}
			iface, err := tun.CreateTUN(name, device.DefaultMTU)
			if err != nil {
				return fmt.Errorf("creating AmneziaWG TUN (requires /dev/net/tun and CAP_NET_ADMIN): %w", err)
			}
			client.device = device.NewDevice(iface, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
			if err := client.device.IpcSet(settings); err != nil {
				client.Close()
				return fmt.Errorf("configuring AmneziaWG settings: %w", err)
			}
			return nil
		},
		startLink: func() error { return client.device.Up() },
	}, nil
}

func (c *amneziaClient) Close() error {
	if c.device != nil {
		c.device.Close()
		c.device = nil
	}
	return nil
}

func (c *amneziaClient) ConfigureDevice(_ string, cfg wgtypes.Config) error {
	var settings strings.Builder
	if cfg.PrivateKey != nil {
		fmt.Fprintf(&settings, "private_key=%x\n", cfg.PrivateKey[:])
	}
	if cfg.ListenPort != nil {
		fmt.Fprintf(&settings, "listen_port=%d\n", *cfg.ListenPort)
	}
	if cfg.FirewallMark != nil {
		fmt.Fprintf(&settings, "fwmark=%d\n", *cfg.FirewallMark)
	}
	if cfg.ReplacePeers {
		settings.WriteString("replace_peers=true\n")
	}
	for _, peer := range cfg.Peers {
		fmt.Fprintf(&settings, "public_key=%x\n", peer.PublicKey[:])
		if peer.Remove {
			settings.WriteString("remove=true\n")
			continue
		}
		if peer.UpdateOnly {
			settings.WriteString("update_only=true\n")
		}
		if peer.PresharedKey != nil {
			fmt.Fprintf(&settings, "preshared_key=%x\n", peer.PresharedKey[:])
		}
		if peer.Endpoint != nil {
			fmt.Fprintf(&settings, "endpoint=%s\n", peer.Endpoint)
		}
		if peer.PersistentKeepaliveInterval != nil {
			fmt.Fprintf(&settings, "persistent_keepalive_interval=%d\n", *peer.PersistentKeepaliveInterval/time.Second)
		}
		if peer.ReplaceAllowedIPs {
			settings.WriteString("replace_allowed_ips=true\n")
		}
		for _, ip := range peer.AllowedIPs {
			fmt.Fprintf(&settings, "allowed_ip=%s\n", ip.String())
		}
	}
	return c.device.IpcSet(settings.String())
}

func (c *amneziaClient) Device(name string) (*wgtypes.Device, error) {
	state, err := c.device.IpcGet()
	if err != nil {
		return nil, err
	}
	result := &wgtypes.Device{Name: name, Type: wgtypes.Userspace}
	var peer *wgtypes.Peer
	var handshakeSeconds int64
	scanner := bufio.NewScanner(strings.NewReader(state))
	for scanner.Scan() {
		key, value, _ := strings.Cut(scanner.Text(), "=")
		if key == "public_key" {
			var publicKey device.NoisePublicKey
			if err := publicKey.FromHex(value); err != nil {
				return nil, fmt.Errorf("invalid peer key in AmneziaWG statistics: %w", err)
			}
			result.Peers = append(result.Peers, wgtypes.Peer{PublicKey: wgtypes.Key(publicKey)})
			peer = &result.Peers[len(result.Peers)-1]
			handshakeSeconds = 0
			continue
		}
		if peer == nil {
			continue
		}
		switch key {
		case "rx_bytes":
			peer.ReceiveBytes, err = strconv.ParseInt(value, 10, 64)
		case "tx_bytes":
			peer.TransmitBytes, err = strconv.ParseInt(value, 10, 64)
		case "last_handshake_time_sec":
			handshakeSeconds, err = strconv.ParseInt(value, 10, 64)
		case "last_handshake_time_nsec":
			var nanos int64
			nanos, err = strconv.ParseInt(value, 10, 64)
			if handshakeSeconds != 0 || nanos != 0 {
				peer.LastHandshakeTime = time.Unix(handshakeSeconds, nanos)
			}
		case "endpoint":
			var endpoint netip.AddrPort
			endpoint, err = netip.ParseAddrPort(value)
			if err == nil {
				peer.Endpoint = net.UDPAddrFromAddrPort(endpoint)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("invalid %s in AmneziaWG statistics: %w", key, err)
		}
	}
	return result, scanner.Err()
}
