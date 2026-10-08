package dialer

import (
	"context"
	"fmt"
	"net"
	"time"
)

// SocketOptions are the raw socket knobs applied to every outbound connection.
type SocketOptions struct {
	// NoDelay disables Nagle's algorithm. This is mandatory for segmentation
	// to be observable: with Nagle on, the kernel will happily coalesce the
	// deliberately small writes back into one segment.
	NoDelay bool
	// KeepAlive and KeepAlivePeriod keep long-lived tunnels from being
	// silently dropped by middleboxes that expire idle flows.
	KeepAlive       bool
	KeepAlivePeriod time.Duration
	// Timeout bounds connection establishment.
	Timeout time.Duration
}

// DefaultSocketOptions returns the settings v2 uses unless overridden.
func DefaultSocketOptions() SocketOptions {
	return SocketOptions{
		NoDelay:         true,
		KeepAlive:       true,
		KeepAlivePeriod: 30 * time.Second,
		Timeout:         10 * time.Second,
	}
}

// DialTCP opens a TCP connection and applies the socket options.
//
// Options are applied to the concrete *net.TCPConn, so a dialer that returns
// something else (a proxy dialer, a test double) is left alone rather than
// failing — the options simply do not apply.
func DialTCP(ctx context.Context, addr string, o SocketOptions) (net.Conn, error) {
	if o.Timeout <= 0 {
		o.Timeout = DefaultSocketOptions().Timeout
	}
	d := &net.Dialer{Timeout: o.Timeout, KeepAlive: o.KeepAlivePeriod}
	if ctx == nil {
		ctx = context.Background()
	}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dialer: dial %s: %w", addr, err)
	}
	ApplySocketOptions(conn, o)
	return conn, nil
}

// ApplySocketOptions applies the knobs to an established connection.
func ApplySocketOptions(conn net.Conn, o SocketOptions) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	if o.NoDelay {
		_ = tcp.SetNoDelay(true)
	}
	if o.KeepAlive {
		_ = tcp.SetKeepAlive(true)
		if o.KeepAlivePeriod > 0 {
			_ = tcp.SetKeepAlivePeriod(o.KeepAlivePeriod)
		}
	}
}
