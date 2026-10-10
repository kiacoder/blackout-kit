package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"blackout-engine-v2/pkg/ipc"
)

// TestControllerSocksTunnelStartStop drives the controller's tunnel engine
// in-process: start must actually open a working forwarder, stop must close
// it, and a full TLS session must round-trip through it.
func TestControllerSocksTunnelStartStop(t *testing.T) {
	c := newController()

	start, err := c.Start(context.Background(), ipc.StartParams{
		Engine: "socks-tunnel",
		Config: map[string]string{"listen": "127.0.0.1:0"},
	})
	if err != nil {
		t.Fatalf("start socks-tunnel: %v", err)
	}
	listen := start.Listen
	if listen == "" {
		t.Fatal("StartResult.Listen missing for socks-tunnel")
	}

	tlsAddr := echoTLSServer(t, "roundtrip.test")

	// The stop must terminate the listener; verify via a full session first.
	conn := socksHandshake(t, listen, tlsAddr)
	tlsConn := tls.Client(conn, &tls.Config{ServerName: "roundtrip.test", InsecureSkipVerify: true})
	if err := tlsConn.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("handshake through controller tunnel: %v", err)
	}
	if _, err := tlsConn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	_ = tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(tlsConn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("roundtrip got %q", buf)
	}

	if _, err := c.Stop(context.Background()); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if _, err := net.DialTimeout("tcp", listen, 500*time.Millisecond); err == nil {
		t.Fatal("tunnel listener still accepting after Stop")
	}
}

// TestControllerTunnelRejectsNonLoopback keeps the loopback-bind guard
// reachable through IPC: a configured LAN bind must fail the start.
func TestControllerTunnelRejectsNonLoopback(t *testing.T) {
	c := newController()
	if _, err := c.Start(context.Background(), ipc.StartParams{
		Engine: "socks-tunnel",
		Config: map[string]string{"listen": "0.0.0.0:18080"},
	}); err == nil {
		t.Fatal("non-loopback bind accepted")
	}
}

// TestControllerTunnelTelemetry feeds traffic through the tunnel and checks
// that the counters surface in Snapshot.
func TestControllerTunnelTelemetry(t *testing.T) {
	c := newController()
	if _, err := c.Start(context.Background(), ipc.StartParams{
		Engine: "socks-tunnel",
		Config: map[string]string{"listen": "127.0.0.1:0"},
	}); err != nil {
		t.Fatal(err)
	}
	tlsAddr := echoTLSServer(t, "telemetry.test")

	conn := socksHandshake(t, c.tunnelAddr(), tlsAddr)
	tlsConn := tls.Client(conn, &tls.Config{ServerName: "telemetry.test", InsecureSkipVerify: true})
	if err := tlsConn.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	_, _ = tlsConn.Write([]byte("ping"))
	_ = tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(tlsConn, make([]byte, 4)); err != nil {
		t.Fatalf("read: %v", err)
	}

	snap := c.Snapshot()
	if snap.BytesIn == 0 || snap.BytesOut == 0 {
		t.Fatalf("snapshot counters zero: %+v", snap)
	}
}

func socksHandshake(t *testing.T, tunnelAddr, targetAddr string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", tunnelAddr)
	if err != nil {
		t.Fatalf("dial tunnel: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	host, portStr, _ := net.SplitHostPort(targetAddr)
	var p int
	for _, ch := range portStr {
		p = p*10 + int(ch-'0')
	}
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(p>>8), byte(p))
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		t.Fatal(err)
	}
	if head[1] != 0x00 {
		t.Fatalf("CONNECT refused, code %d", head[1])
	}
	if _, err := io.ReadFull(conn, make([]byte, 6)); err != nil {
		t.Fatal(err)
	}
	return conn
}

func echoTLSServer(t *testing.T, host string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				r := bufio.NewReader(conn)
				buf := make([]byte, 512)
				for {
					n, err := r.Read(buf)
					if n > 0 {
						if _, werr := conn.Write([]byte("pong")); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// TestControllerTuneKeepsZeroFields mirrors ipc.MemController semantics: a
// tune call that only sets one field must not reset the others to minimums.
func TestControllerTuneKeepsZeroFields(t *testing.T) {
	c := newController()
	first, err := c.Tune(context.Background(), ipc.TuneParams{
		MinChunk: 16,
		MaxChunk: 48,
		MinDelay: 200,
		MaxDelay: 800,
		FakeSNI:  "first.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.Tune(context.Background(), ipc.TuneParams{FakeSNI: "second.example"})
	if err != nil {
		t.Fatal(err)
	}
	if second.MinChunk != first.MinChunk || second.MaxChunk != first.MaxChunk {
		t.Fatalf("zero tune reset chunks: %+v vs %+v", second, first)
	}
	if second.MinDelay != first.MinDelay || second.MaxDelay != first.MaxDelay {
		t.Fatalf("zero tune reset delays: %+v vs %+v", second, first)
	}
	if second.FakeSNI != "second.example" {
		t.Fatalf("FakeSNI not applied: %q", second.FakeSNI)
	}
}
