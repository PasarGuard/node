package keepalive_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
	"github.com/pasarguard/node/controller/rpc"
	"github.com/pasarguard/node/pkg/tlsutil"
)

func selfSignedPair(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "keepalive-node"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func unusedAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func startNode(t *testing.T) (addr, certPath string, key uuid.UUID) {
	t.Helper()
	certPath, keyPath := selfSignedPair(t)
	tlsConfig, err := tlsutil.LoadTLSCredentials(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	key = uuid.New()
	cfg := config.NewTestConfig(t.TempDir(), key)
	addr = unusedAddr(t)
	shutdown, service, err := rpc.StartGRPCListener(tlsConfig, addr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		service.Disconnect()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shutdown(ctx)
	})
	return addr, certPath, key
}

func dialNode(t *testing.T, addr, certPath string, opts ...grpc.DialOption) *grpc.ClientConn {
	t.Helper()
	pool, err := tlsutil.LoadClientPool(certPath)
	if err != nil {
		t.Fatal(err)
	}
	creds := credentials.NewTLS(&tls.Config{RootCAs: pool, ServerName: "localhost"})
	conn, err := grpc.NewClient(addr, append([]grpc.DialOption{grpc.WithTransportCredentials(creds)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func baseInfo(t *testing.T, conn *grpc.ClientConn, key uuid.UUID) {
	t.Helper()
	ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), metadata.Pairs("x-api-key", key.String())), 5*time.Second)
	defer cancel()
	if _, err := common.NewNodeServiceClient(conn).GetBaseInfo(ctx, &common.Empty{}); err != nil {
		t.Fatalf("GetBaseInfo: %v", err)
	}
}

func TestNodeKeepsAnIdlePanelConnectionThatPingsEveryTenSeconds(t *testing.T) {
	t.Parallel()
	addr, certPath, key := startNode(t)
	conn := dialNode(t, addr, certPath, grpc.WithKeepaliveParams(keepalive.ClientParameters{
		Time:                10 * time.Second,
		Timeout:             5 * time.Second,
		PermitWithoutStream: true,
	}))
	baseInfo(t, conn, key)
	if state := conn.GetState(); state != connectivity.Ready {
		t.Fatalf("connection not ready after the first call: %v", state)
	}

	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if conn.WaitForStateChange(ctx, connectivity.Ready) {
		t.Fatalf("the node dropped an idle panel connection that pings every 10 s after %.0fs; state now %v", time.Since(started).Seconds(), conn.GetState())
	}
}

type freezableProxy struct {
	listener     net.Listener
	target       string
	frozen       atomic.Bool
	serverClosed chan struct{}
	once         sync.Once
}

func startProxy(t *testing.T, target string) *freezableProxy {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &freezableProxy{listener: l, target: target, serverClosed: make(chan struct{})}
	t.Cleanup(func() { l.Close() })
	go p.serve()
	return p
}

func (p *freezableProxy) serve() {
	for {
		client, err := p.listener.Accept()
		if err != nil {
			return
		}
		server, err := net.Dial("tcp", p.target)
		if err != nil {
			client.Close()
			continue
		}
		go func() {
			buf := make([]byte, 32*1024)
			for {
				n, err := client.Read(buf)
				if n > 0 && !p.frozen.Load() {
					if _, werr := server.Write(buf[:n]); werr != nil {
						return
					}
				}
				if err != nil {
					return
				}
			}
		}()
		go func() {
			buf := make([]byte, 32*1024)
			for {
				n, err := server.Read(buf)
				if n > 0 && !p.frozen.Load() {
					_, _ = client.Write(buf[:n])
				}
				if err != nil {
					if err == io.EOF || p.frozen.Load() {
						p.once.Do(func() { close(p.serverClosed) })
					}
					client.Close()
					return
				}
			}
		}()
	}
}

func TestNodeClosesAConnectionWhosePanelStoppedAnswering(t *testing.T) {
	t.Parallel()
	addr, certPath, key := startNode(t)
	proxy := startProxy(t, addr)
	conn := dialNode(t, proxy.listener.Addr().String(), certPath)
	baseInfo(t, conn, key)

	proxy.frozen.Store(true)
	started := time.Now()
	select {
	case <-proxy.serverClosed:
		if elapsed := time.Since(started); elapsed < 30*time.Second {
			t.Fatalf("the node closed a merely idle connection after %.0fs, before its keepalive ping was due", elapsed.Seconds())
		}
	case <-time.After(55 * time.Second):
		t.Fatal("the node kept a connection to a panel that stopped answering for 55 s; it must ping an idle panel and close the connection when the ping is not acknowledged")
	}
}
