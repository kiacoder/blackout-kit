package tunnel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"blackout-engine-v2/pkg/dialer"
)

// socksConnect drives the client half of a minimal SOCKS5 CONNECT handshake.
// It returns the live connection once the tunnel has answered the request.
func socksConnect(t *testing.T, addr, host string, port int) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial tunnel: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("greeting reply: %v", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("unexpected method reply: %v", reply)
	}

	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("connect request: %v", err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		t.Fatalf("connect reply head: %v", err)
	}
	if head[1] != 0x00 {
		t.Fatalf("CONNECT failed, reply code %d", head[1])
	}
	// The tunnel always answers with the fixed IPv4 form: 4 header bytes
	// already read, then 4 address + 2 port bytes.
	rest := make([]byte, 6)
	if _, err := io.ReadFull(conn, rest); err != nil {
		t.Fatalf("connect reply tail: %v", err)
	}
	return conn
}

// recordUpstream is a plain TCP server that accumulates everything the tunnel
// writes until the expected TLS record length is satisfied, then keeps the
// reader available for further assertions.
func recordUpstream(t *testing.T) (addr string, got func() []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	done := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- nil
			return
		}
		defer conn.Close()
		var buf []byte
		chunk := make([]byte, 1024)
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, err := conn.Read(chunk)
			if n > 0 {
				buf = append(buf, chunk[:n]...)
				if len(buf) >= 5 {
					recLen := int(binary.BigEndian.Uint16(buf[3:5]))
					if len(buf) >= 5+recLen {
						done <- append([]byte(nil), buf[:5+recLen]...)
						// Keep reading so the pipe does not block.
						for {
							if _, err := conn.Read(chunk); err != nil {
								return
							}
						}
					}
				}
			}
			if err != nil && !errors.Is(err, net.ErrClosed) && !isTimeout(err) {
				return
			}
		}
		done <- append([]byte(nil), buf...)
	}()

	return ln.Addr().String(), func() []byte {
		select {
		case b := <-done:
			return b
		case <-time.After(6 * time.Second):
			t.Fatal("upstream never recorded the first record")
			return nil
		}
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// buildHelloRecord is the tunnel-test copy of the dialer fixture: a minimal
// ClientHello record carrying an SNI extension, valid for ExtractSNI.
func buildHelloRecord(t *testing.T, sni string) []byte {
	t.Helper()
	host := []byte(sni)
	list := make([]byte, 2+3+len(host))
	binary.BigEndian.PutUint16(list[0:2], uint16(3+len(host)))
	list[2] = 0x00
	binary.BigEndian.PutUint16(list[3:5], uint16(len(host)))
	copy(list[5:], host)

	exts := []byte{0x00, 0x00}
	exts = append(exts, byte(len(list)>>8), byte(len(list)&0xff))
	exts = append(exts, list...)
	exts = append(exts, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04)

	hs := []byte{0x03, 0x03}
	hs = append(hs, make([]byte, 32)...)
	hs = append(hs, 0x00)
	hs = append(hs, 0x00, 0x02, 0x13, 0x01)
	hs = append(hs, 0x01, 0x00)
	hs = append(hs, byte(len(exts)>>8), byte(len(exts)&0xff))
	hs = append(hs, exts...)

	rec := []byte{0x16, 0x03, 0x01, byte((4 + len(hs)) >> 8), byte(4 + len(hs))}
	rec = append(rec, 0x01, byte(len(hs)>>16), byte(len(hs)>>8), byte(len(hs)&0xff))
	rec = append(rec, hs...)
	return rec
}

func newTLSServer(t *testing.T, host string, handler func(io.Reader, io.Writer)) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
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
		t.Fatalf("cert: %v", err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
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
				if handler != nil {
					handler(conn, conn)
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func tlsServerEcho(t *testing.T, host string) string {
	return newTLSServer(t, host, func(r io.Reader, w io.Writer) {
		buf := make([]byte, 512)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				if _, werr := w.Write([]byte("pong")); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	})
}

func startTunnel(t *testing.T, cfg Config) *Server {
	t.Helper()
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for srv.Addr() == nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if srv.Addr() == nil {
		t.Fatal("tunnel never started listening")
	}
	return srv
}

func TestNewRejectsNonLoopbackListen(t *testing.T) {
	for _, listen := range []string{"0.0.0.0:1080", "192.168.1.5:1080", "localhost:1080", ":1080", "1080"} {
		if _, err := New(Config{Listen: listen}); err == nil {
			t.Errorf("New(%q) = nil error, want non-loopback rejection", listen)
		}
	}
	for _, listen := range []string{"127.0.0.1:0", "[::1]:0"} {
		srv, err := New(Config{Listen: listen})
		if err != nil {
			t.Errorf("New(%q): %v", listen, err)
		} else {
			_ = srv.Close()
		}
	}
}

func TestTunnelRelaysTLSSession(t *testing.T) {
	upstream := tlsServerEcho(t, "example.test")
	srv := startTunnel(t, Config{
		Listen: "127.0.0.1:0",
		Dialer: dialer.DefaultConfig(),
	})

	conn := socksConnect(t, srv.Addr().String(), hostOf(upstream), portOf(upstream))
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         "example.test",
		InsecureSkipVerify: true, // test-local self-signed fixture; production path never disables verification
	})
	if err := tlsConn.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("handshake through tunnel: %v", err)
	}
	if _, err := tlsConn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if err := tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(tlsConn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("roundtrip got %q", buf)
	}

	if srv.BytesIn() == 0 || srv.BytesOut() == 0 {
		t.Fatalf("telemetry counters not populated: in=%d out=%d", srv.BytesIn(), srv.BytesOut())
	}
}

func TestTunnelRewritesSNIBeforeUpstreamWrite(t *testing.T) {
	addr, got := recordUpstream(t)
	srv := startTunnel(t, Config{
		Listen: "127.0.0.1:0",
		Dialer: dialer.Config{
			MinChunk:  8,
			MaxChunk:  24,
			MinDelay:  100 * time.Microsecond,
			MaxDelay:  500 * time.Microsecond,
			FakeSNI:   "clean.example.com",
			Fragments: true,
		},
	})

	conn := socksConnect(t, srv.Addr().String(), hostOf(addr), portOf(addr))
	hello := buildHelloRecord(t, "blocked.example.com")
	if _, err := conn.Write(hello); err != nil {
		t.Fatalf("write hello: %v", err)
	}

	up := got()
	if len(up) == 0 {
		t.Fatal("upstream recorded nothing")
	}
	sni, err := dialer.ExtractSNI(up)
	if err != nil {
		t.Fatalf("upstream first record not a parseable hello: %v", err)
	}
	if sni != "clean.example.com" {
		t.Fatalf("upstream SNI = %q, want rewritten %q", sni, "clean.example.com")
	}
	if strings.Contains(string(up), "blocked.example.com") {
		t.Fatal("original SNI leaked to upstream")
	}
}

func TestTunnelPassesNonTLSBytesUnshaped(t *testing.T) {
	addr, got := recordUpstream(t)
	srv := startTunnel(t, Config{
		Listen: "127.0.0.1:0",
		Dialer: dialer.DefaultConfig(),
	})

	conn := socksConnect(t, srv.Addr().String(), hostOf(addr), portOf(addr))
	payload := []byte("GET /plain HTTP/1.1\r\nHost: x\r\n\r\n")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	up := got()
	if string(up) != string(payload) {
		t.Fatalf("non-TLS payload altered: got %q want %q", up, payload)
	}
}

func TestSOCKSRejectsUnsupportedCommand(t *testing.T) {
	srv := startTunnel(t, Config{Listen: "127.0.0.1:0"})
	conn, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte{0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90}); err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		t.Fatal(err)
	}
	if head[1] != 0x07 {
		t.Fatalf("reply code = %d, want 0x07 command not supported", head[1])
	}
}

func TestSOCKSRejectsUnsupportedAddressType(t *testing.T) {
	srv := startTunnel(t, Config{Listen: "127.0.0.1:0"})
	conn, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00, 0x09}); err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		t.Fatal(err)
	}
	if head[1] != 0x08 {
		t.Fatalf("reply code = %d, want 0x08 address type not supported", head[1])
	}
}

func TestSOCKSRejectsMissingNoAuthMethod(t *testing.T) {
	srv := startTunnel(t, Config{Listen: "127.0.0.1:0"})
	conn, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if reply[0] != 0x05 || reply[1] != 0xFF {
		t.Fatalf("method reply = %v, want no-acceptable-method 0xFF", reply)
	}
}

func TestTunnelReportsDialFailure(t *testing.T) {
	srv := startTunnel(t, Config{Listen: "127.0.0.1:0"})
	// Port 1 on loopback is refused; nothing listens there.
	conn, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len("127.0.0.1"))}
	req = append(req, []byte("127.0.0.1")...)
	req = append(req, 0x00, 0x01)
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		t.Fatal(err)
	}
	if head[1] == 0x00 {
		t.Fatal("CONNECT to a refused port unexpectedly succeeded")
	}
	if _, err := conn.Write([]byte("x")); err == nil {
		t.Log("connection still writable after failure reply; server may close lazily")
	}
}

func TestServeStopsOnContextCancel(t *testing.T) {
	srv, err := New(Config{Listen: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ctx) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not stop after context cancel")
	}
}

func TestTunnelHandlesConcurrentSessions(t *testing.T) {
	upstream := tlsServerEcho(t, "concurrent.test")
	srv := startTunnel(t, Config{
		Listen: "127.0.0.1:0",
		Dialer: dialer.DefaultConfig(),
	})

	done := make(chan error, 4)
	for i := 0; i < 4; i++ {
		go func() {
			conn := socksConnect(t, srv.Addr().String(), hostOf(upstream), portOf(upstream))
			tlsConn := tls.Client(conn, &tls.Config{
				ServerName:         "concurrent.test",
				InsecureSkipVerify: true,
			})
			if err := tlsConn.HandshakeContext(context.Background()); err != nil {
				done <- err
				return
			}
			if _, err := tlsConn.Write([]byte("ping")); err != nil {
				done <- err
				return
			}
			buf := make([]byte, 4)
			_ = tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.ReadFull(tlsConn, buf); err != nil {
				done <- err
				return
			}
			done <- nil
		}()
	}
	for i := 0; i < 4; i++ {
		if err := <-done; err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
	}
}

func hostOf(addr string) string { return strings.Split(addr, ":")[0] }

func portOf(addr string) int {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		panic(err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		panic(err)
	}
	return p
}

func TestNonTLSSessionSurvivesHelloTimeout(t *testing.T) {
	old := helloReadTimeout
	helloReadTimeout = 150 * time.Millisecond
	defer func() { helloReadTimeout = old }()

	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upLn.Close()
	seen := make(chan []byte, 1)
	go func() {
		conn, err := upLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var acc []byte
		buf := make([]byte, 256)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				acc = append(acc, buf[:n]...)
				seen <- append([]byte(nil), acc...)
			}
			if err != nil {
				return
			}
		}
	}()

	srv := startTunnel(t, Config{Listen: "127.0.0.1:0", Dialer: dialer.DefaultConfig()})
	conn := socksConnect(t, srv.Addr().String(), hostOf(upLn.Addr().String()), portOf(upLn.Addr().String()))
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\n")); err != nil {
		t.Fatal(err)
	}
	// Cross the hello timeout while the session sits idle, then keep using it.
	time.Sleep(300 * time.Millisecond)
	if _, err := conn.Write([]byte("Host: after-timeout\r\n\r\n")); err != nil {
		t.Fatalf("session died across the hello timeout: %v", err)
	}
	var got []byte
	for got == nil || !strings.Contains(string(got), "Host: after-timeout") {
		select {
		case got = <-seen:
		case <-time.After(3 * time.Second):
			t.Fatalf("bytes sent after the hello timeout never reached upstream; got %q", got)
		}
	}
}

func TestCloseDuringActiveHandshakes(t *testing.T) {
	for i := 0; i < 30; i++ {
		srv, err := New(Config{Listen: "127.0.0.1:0"})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		go func() { _ = srv.Serve(ctx) }()
		time.Sleep(5 * time.Millisecond)

		// A client parked mid-CONNECT: an in-flight session Close must not
		// wait on, and the shutdown must complete promptly regardless of the
		// accept/registration interleaving.
		conn, err := net.DialTimeout("tcp", srv.Addr().String(), time.Second)
		if err == nil {
			_, _ = conn.Write([]byte{0x05, 0x01, 0x00})
		}
		cancel()
		done := make(chan error, 1)
		go func() { done <- srv.Close() }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("iteration %d: Close deadlocked with a live session", i)
		}
	}
}
