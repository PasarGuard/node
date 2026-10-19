package mtproto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// mtprotoTestDC is the Telegram DC the fake client asks for. Integration
// configs point it at startFakeDC through telemt's dc_overrides.
const mtprotoTestDC = 2

// obfuscated2 initial packets must not look like another protocol, or the
// server would not read them as MTProto.
var reservedInitPrefixes = [][]byte{
	[]byte("HEAD"), []byte("POST"), []byte("GET "), []byte("OPTI"),
	{0x16, 0x03, 0x01, 0x02}, {0xdd, 0xdd, 0xdd, 0xdd}, {0xee, 0xee, 0xee, 0xee},
}

// startFakeDC listens on loopback as a Telegram DC that accepts telemt's
// relay connections and reads them until they close, so a client session
// stays open until telemt itself ends it. A test host cannot reach the real
// DCs, and telemt closes a session at once when its DC refuses.
func startFakeDC(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake DC listen: %v", err)
	}

	var (
		mu    sync.Mutex
		conns []net.Conn
	)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
			go func() {
				_, _ = io.Copy(io.Discard, conn)
				_ = conn.Close()
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range conns {
			_ = conn.Close()
		}
	})
	return listener.Addr().String()
}

// dialMTProto connects to addr as an MTProto client of the user whose secret
// is secretHex: the obfuscated2 handshake keyed with the secret, the padded
// intermediate transport (`dd`), then one framed packet. telemt counts an
// admitted connection in telemt_user_connections_current right away, even
// though it cannot reach Telegram; a handshake with a wrong secret is never
// counted for any user.
func dialMTProto(addr, secretHex string) (net.Conn, error) {
	secret, err := hex.DecodeString(secretHex)
	if err != nil {
		return nil, err
	}

	init := make([]byte, 64)
	for {
		if _, err := rand.Read(init); err != nil {
			return nil, err
		}
		if validInitPacket(init) {
			break
		}
	}
	copy(init[56:60], []byte{0xdd, 0xdd, 0xdd, 0xdd})
	binary.LittleEndian.PutUint16(init[60:62], mtprotoTestDC)

	key := sha256.Sum256(append(append([]byte{}, init[8:40]...), secret...))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, init[40:56])
	encrypted := make([]byte, len(init))
	stream.XORKeyStream(encrypted, init)

	frame := make([]byte, 4+200)
	binary.LittleEndian.PutUint32(frame, 200)
	stream.XORKeyStream(frame, frame)

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	handshake := append(append([]byte{}, init[:56]...), encrypted[56:]...)
	if _, err := conn.Write(append(handshake, frame...)); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func validInitPacket(init []byte) bool {
	if init[0] == 0xef || bytes.Equal(init[4:8], []byte{0, 0, 0, 0}) {
		return false
	}
	for _, prefix := range reservedInitPrefixes {
		if bytes.Equal(init[:4], prefix) {
			return false
		}
	}
	return true
}

// connClosed reports whether the server closed conn, waiting up to wait for
// it. telemt never sends a fake client anything, so a read that times out
// means the connection is still open.
func connClosed(conn net.Conn, wait time.Duration) bool {
	if err := conn.SetReadDeadline(time.Now().Add(wait)); err != nil {
		return true
	}
	buf := make([]byte, 1)
	_, err := conn.Read(buf)
	return err != nil && !errors.Is(err, os.ErrDeadlineExceeded)
}
