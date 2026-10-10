// Package tunnel is the v2 live outbound path for the dialer primitives.
//
// It exposes a minimal, loopback-only SOCKS5 CONNECT forwarder. On every
// session it peeks at the client's first bytes: when they form a TLS
// ClientHello, that one record is written to the upstream through
// dialer.WriteHello — SNI rewriting plus randomized SNI-boundary
// segmentation — and everything after it is relayed untouched, both
// directions.
//
// Scope discipline, restated: this is pure userspace TCP relaying. There are
// no forged TCP flags, no zero-window packets, no raw sockets, and no parity
// frames on the wire. The dialer does the shaping; this package only gives it
// a real connection to shape, which v1.3.0 did not have.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"blackout-engine-v2/pkg/dialer"
)

// ErrBadListen is returned when the configured bind address is not a loopback
// literal. The tunnel is a local entry point, not a LAN service; hostnames are
// refused so the bind target can never silently depend on resolver output.
var ErrBadListen = errors.New("tunnel: listen address must be a loopback literal (127.0.0.1 or [::1])")

// helloReadTimeout bounds how long the tunnel waits for the client's first
// bytes after a successful CONNECT before falling back to transparent
// relaying. A client that sends nothing is still relayed; it just never gets
// shaped.
const helloReadTimeout = 10 * time.Second

// Config configures one tunnel server.
type Config struct {
	// Listen must be a loopback literal with a port ("127.0.0.1:18080").
	Listen string
	// Dialer is the shaping policy applied to the outbound ClientHello.
	Dialer dialer.Config
}

// Server is the running tunnel. It is safe for concurrent use.
type Server struct {
	cfg      Config
	dialer   atomic.Pointer[dialer.Config]
	ln       net.Listener
	bytesIn  atomic.Uint64 // client -> upstream
	bytesOut atomic.Uint64 // upstream -> client

	wg     sync.WaitGroup
	closed atomic.Bool

	// conns tracks live session sockets so Close can terminate them instead
	// of waiting for the peers to hang up first.
	connsMu sync.Mutex
	conns   map[net.Conn]struct{}

	// Log, when set, receives shaping failures for one session. Sessions are
	// never failed loudly — the relay ends quietly, like any TCP proxy.
	Log func(msg string)
}

// New validates the config and binds the listener.
func New(cfg Config) (*Server, error) {
	host, _, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadListen, err)
	}
	switch host {
	case "127.0.0.1", "::1":
	default:
		return nil, fmt.Errorf("%w, got %q", ErrBadListen, host)
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("tunnel: listen: %w", err)
	}
	s := &Server{cfg: cfg, ln: ln, conns: make(map[net.Conn]struct{})}
	s.dialer.Store(&cfg.Dialer)
	return s, nil
}

// SetDialer swaps the shaping policy for future sessions — the IPC tune path
// uses it so a running tunnel honors new chunk/delay/SNI values without a
// restart.
func (s *Server) SetDialer(cfg dialer.Config) { s.dialer.Store(&cfg) }

// Addr reports the bound address; valid once New succeeded.
func (s *Server) Addr() net.Addr { return s.ln.Addr() }

// BytesIn reports bytes relayed client -> upstream.
func (s *Server) BytesIn() uint64 { return s.bytesIn.Load() }

// BytesOut reports bytes relayed upstream -> client.
func (s *Server) BytesOut() uint64 { return s.bytesOut.Load() }

// Serve accepts sessions until ctx is cancelled or the listener closes.
func (s *Server) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = s.ln.Close()
	}()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if ctx.Err() != nil || s.closed.Load() {
				return ctx.Err()
			}
			return fmt.Errorf("tunnel: accept: %w", err)
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serveConn(conn)
		}()
	}
}

// Close stops the listener, terminates live sessions, and waits for the
// session goroutines to exit. Relays are pipes, not protocols: a relay only
// ends when one peer closes, so a graceful drain would block until the
// clients hang up. Force-closing is the honest stop semantics.
func (s *Server) Close() error {
	s.closed.Store(true)
	err := s.ln.Close()
	s.connsMu.Lock()
	for conn := range s.conns {
		_ = conn.Close()
	}
	s.connsMu.Unlock()
	s.wg.Wait()
	return err
}

func (s *Server) serveConn(conn net.Conn) {
	s.connsMu.Lock()
	s.conns[conn] = struct{}{}
	s.connsMu.Unlock()
	defer func() {
		s.connsMu.Lock()
		delete(s.conns, conn)
		s.connsMu.Unlock()
		conn.Close()
	}()

	if err := conn.SetDeadline(time.Time{}); err != nil {
		return
	}
	if !socksGreet(conn) {
		return
	}
	target, ok := socksConnectRequest(conn)
	if !ok {
		return
	}

	up, err := net.DialTimeout("tcp", target, helloReadTimeout)
	if err != nil {
		socksReply(conn, 0x05) // connection refused
		return
	}
	defer up.Close()
	if err := up.SetDeadline(time.Time{}); err != nil {
		return
	}
	if !socksReply(conn, 0x00) {
		return
	}

	s.relay(conn, up)
}

// relay sniffs the client's opening bytes, shapes a TLS ClientHello through
// the dialer when one is present, then pipes both directions until EOF.
func (s *Server) relay(client, up net.Conn) {
	hello, shaped := s.sniffHello(client)
	if shaped {
		rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
		if _, err := dialer.WriteHello(up, hello, *s.dialer.Load(), rnd); err != nil {
			if s.Log != nil {
				s.Log("tunnel: shaping client hello: " + err.Error())
			}
			return
		}
		s.bytesIn.Add(uint64(len(hello)))
	} else if len(hello) > 0 {
		// No ClientHello: whatever was read goes out verbatim.
		if _, err := up.Write(hello); err != nil {
			return
		}
		s.bytesIn.Add(uint64(len(hello)))
	}

	errCh := make(chan error, 2)
	go func() { // upstream -> client
		_, err := io.Copy(client, &countingReader{r: up, s: s, in: false})
		errCh <- err
	}()
	go func() { // client -> upstream
		_, err := io.Copy(up, &countingReader{r: client, s: s, in: true})
		errCh <- err
	}()
	<-errCh
}

// sniffHello reads the client's first TLS record if the opening byte marks a
// handshake record. The read deadline keeps a silent client from wedging the
// relay; on timeout the bytes read so far, if any, are relayed verbatim.
func (s *Server) sniffHello(client net.Conn) (first []byte, isHello bool) {
	_ = client.SetReadDeadline(time.Now().Add(helloReadTimeout))
	head := make([]byte, 5)
	n, err := io.ReadFull(client, head)
	if err != nil {
		return head[:n], false
	}
	if head[0] != 0x16 { // not a TLS handshake record
		return head, false
	}
	recLen := int(head[3])<<8 | int(head[4])
	body := make([]byte, recLen)
	if _, err := io.ReadFull(client, body); err != nil {
		return head, false
	}
	_ = client.SetReadDeadline(time.Time{})
	return append(head, body...), true
}

// countingReader counts bytes as they pass through one relay direction.
type countingReader struct {
	r  io.Reader
	s  *Server
	in bool
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		if c.in {
			c.s.bytesIn.Add(uint64(n))
		} else {
			c.s.bytesOut.Add(uint64(n))
		}
	}
	return n, err
}

// socksGreet performs the method negotiation. Only the no-auth method is
// offered or accepted: the tunnel serves a local process, and adding auth
// would invite storing credentials for a loopback-only listener.
func socksGreet(conn net.Conn) bool {
	_ = conn.SetReadDeadline(time.Now().Add(helloReadTimeout))
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil || head[0] != 0x05 || head[1] == 0 {
		return false
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return false
	}
	for _, m := range methods {
		if m == 0x00 {
			_, err := conn.Write([]byte{0x05, 0x00})
			return err == nil
		}
	}
	_, _ = conn.Write([]byte{0x05, 0xFF})
	return false
}

// socksConnectRequest parses a CONNECT request and returns "host:port".
// Only CONNECT is supported — the tunnel is an outbound path, not a BIND or
// UDP relay.
func socksConnectRequest(conn net.Conn) (string, bool) {
	_ = conn.SetReadDeadline(time.Now().Add(helloReadTimeout))
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return "", false
	}
	if head[0] != 0x05 || head[1] != 0x01 { // VER / CONNECT
		if head[0] == 0x05 {
			socksReply(conn, 0x07) // command not supported
		}
		return "", false
	}
	var host string
	switch head[3] {
	case 0x01: // IPv4
		var ip [4]byte
		if _, err := io.ReadFull(conn, ip[:]); err != nil {
			return "", false
		}
		host = net.IP(ip[:]).String()
	case 0x03: // domain
		ln := make([]byte, 1)
		if _, err := io.ReadFull(conn, ln); err != nil || ln[0] == 0 {
			return "", false
		}
		name := make([]byte, int(ln[0]))
		if _, err := io.ReadFull(conn, name); err != nil {
			return "", false
		}
		host = string(name)
	case 0x04: // IPv6
		var ip [16]byte
		if _, err := io.ReadFull(conn, ip[:]); err != nil {
			return "", false
		}
		host = net.IP(ip[:]).String()
	default:
		socksReply(conn, 0x08) // address type not supported
		return "", false
	}
	var port [2]byte
	if _, err := io.ReadFull(conn, port[:]); err != nil {
		return "", false
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port[0])<<8|int(port[1]))), true
}

// socksReply writes the IPv4-form success/failure reply; 0.0.0.0:0 marks
// "no meaningful bound address", which is what a plain forwarder has.
func socksReply(conn net.Conn, code byte) bool {
	_, err := conn.Write([]byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err == nil
}
