package xray

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
	"github.com/pasarguard/node/pkg/netutil"
)

const sessionTestConfig = `{
	"log": {"loglevel": "warning"},
	"inbounds": [{
		"tag": "VLESS TCP SESSION",
		"listen": "127.0.0.1",
		"port": %d,
		"protocol": "vless",
		"settings": {"clients": [], "decryption": "none"}
	}],
	"outbounds": [{
		"tag": "direct",
		"protocol": "freedom",
		"settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.1"]}]}
	}]
}`

const sessionTestInbound = "VLESS TCP SESSION"

func startByteSource(t *testing.T) *net.TCPAddr {
	t.Helper()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		chunk := make([]byte, 32*1024)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				for {
					if _, err := conn.Write(chunk); err != nil {
						return
					}
				}
			}()
		}
	}()

	return listener.Addr().(*net.TCPAddr)
}

func openVlessStream(t *testing.T, inboundPort int, id uuid.UUID, target *net.TCPAddr) net.Conn {
	t.Helper()

	conn, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(inboundPort)), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	request := []byte{0}
	request = append(request, id[:]...)
	request = append(request, 0, 1)
	request = binary.BigEndian.AppendUint16(request, uint16(target.Port))
	request = append(request, 1)
	request = append(request, target.IP.To4()...)
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	return conn
}

func receive(conn net.Conn, window time.Duration) (int64, error) {
	_ = conn.SetReadDeadline(time.Now().Add(window))
	received, err := io.Copy(io.Discard, conn)
	switch {
	case errors.Is(err, os.ErrDeadlineExceeded):
		return received, nil
	case err == nil:
		return received, io.EOF
	}
	return received, err
}

func requireFlowing(t *testing.T, conn net.Conn, moment string) {
	t.Helper()

	received, err := receive(conn, 500*time.Millisecond)
	if err != nil || received == 0 {
		t.Fatalf("open connection stopped %s: received %d bytes, err %v", moment, received, err)
	}
}

func sessionUser(email string, id uuid.UUID, inbounds ...string) *common.User {
	return &common.User{
		Email:    email,
		Inbounds: inbounds,
		Proxies:  &common.Proxy{Vless: &common.Vless{Id: id.String()}},
	}
}

func TestUserSyncKeepsAnUnchangedUsersOpenConnection(t *testing.T) {
	source := startByteSource(t)
	inboundPort := netutil.FindFreePort()

	xrayConfig, err := NewConfig(fmt.Sprintf(sessionTestConfig, inboundPort), nil)
	if err != nil {
		t.Fatal(err)
	}

	aliceID := uuid.New()
	alice := sessionUser("1.alice", aliceID, sessionTestInbound)

	back, err := New(
		context.Background(),
		xrayConfig,
		[]*common.User{alice},
		netutil.FindFreePort(),
		netutil.FindFreePort(),
		&config.Config{
			XrayExecutablePath:  executablePath,
			XrayAssetsPath:      assetsPath,
			GeneratedConfigPath: configPath,
			LogBufferSize:       1000,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer back.Shutdown()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stream := openVlessStream(t, inboundPort, aliceID, source)
	requireFlowing(t, stream, "before any sync")

	if err := back.SyncUser(ctx, alice); err != nil {
		t.Fatal(err)
	}
	requireFlowing(t, stream, "after SyncUser sent the same user again")

	if err := back.UpdateUsers(ctx, []*common.User{alice}); err != nil {
		t.Fatal(err)
	}
	requireFlowing(t, stream, "after UpdateUsers sent the same user again")

	if err := back.SyncUser(ctx, sessionUser("1.alice", aliceID)); err != nil {
		t.Fatal(err)
	}

	if received, _ := receive(openVlessStream(t, inboundPort, aliceID, source), time.Second); received != 0 {
		t.Fatalf("a removed user opened a new connection and received %d bytes", received)
	}

	received, err := receive(stream, time.Second)
	t.Logf("the connection the removed user had already opened received %d bytes in the next second (err %v)", received, err)
}
