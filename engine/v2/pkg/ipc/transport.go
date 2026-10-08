package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// DefaultEndpoint returns the platform's control endpoint.
//
//	Windows -> \\.\pipe\blackout_ipc
//	Linux   -> /tmp/blackout.sock
//
// These are fixed by the v2 spec so the C# HUD, the Python CLI and the daemon
// can all find each other without configuration.
func DefaultEndpoint() string {
	if runtime.GOOS == "windows" {
		return `\\.\pipe\blackout_ipc`
	}
	return filepath.Join("/tmp", "blackout.sock")
}

// ErrUnsupportedPlatform is returned when no transport exists for this OS.
var ErrUnsupportedPlatform = errors.New("ipc: no transport available on this platform")

// IsPipePlatform reports whether this platform binds a Windows named pipe
// rather than a Unix domain socket. Callers use it to build a platform-correct
// endpoint without duplicating the runtime check.
func IsPipePlatform() bool { return runtime.GOOS == "windows" }

// ValidateEndpoint rejects endpoints this package cannot serve. It exists
// mainly so a misconfigured Linux path (or a UNC path handed to the Unix
// listener) fails with a clear message instead of a confusing syscall error.
func ValidateEndpoint(addr string) error {
	if addr == "" {
		return errors.New("ipc: empty endpoint")
	}
	if isPipePath(addr) {
		if runtime.GOOS != "windows" {
			return fmt.Errorf("ipc: pipe endpoint %q requires windows", addr)
		}
		return nil
	}
	if runtime.GOOS == "windows" {
		return fmt.Errorf("ipc: %q is not a windows pipe path; expected \\\\.\\pipe\\<name>", addr)
	}
	if len(addr) > 104 {
		return fmt.Errorf("ipc: unix socket path too long (%d > 104 bytes)", len(addr))
	}
	return nil
}

// isPipePath reports whether addr looks like a Windows named pipe.
func isPipePath(addr string) bool {
	if strings.HasPrefix(addr, `\\.\pipe\`) || strings.HasPrefix(addr, `//./pipe/`) {
		return true
	}
	return strings.HasPrefix(addr, `\\`) && strings.Contains(addr, `\pipe\`)
}

// Listener wraps a net.Listener and remembers whether it owns an on-disk
// artifact (a Unix socket file) that must be removed at shutdown.
type Listener struct {
	net.Listener
	endpoint string
	unlink   bool
}

// Endpoint returns the address this listener is bound to.
func (l *Listener) Endpoint() string { return l.endpoint }

// Close releases the listener and any filesystem artifact it created.
func (l *Listener) Close() error {
	err := l.Listener.Close()
	if l.unlink {
		if rmErr := os.Remove(l.endpoint); rmErr != nil && !os.IsNotExist(rmErr) {
			if err == nil {
				err = rmErr
			}
		}
	}
	return err
}

// Listen binds the control endpoint. Callers should prefer this over the
// platform-specific constructors so Windows and Linux stay symmetric.
func Listen(endpoint string) (*Listener, error) {
	if err := ValidateEndpoint(endpoint); err != nil {
		return nil, err
	}
	ln, err := listenEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	return &Listener{
		Listener: ln,
		endpoint: endpoint,
		unlink:   !isPipePath(endpoint),
	}, nil
}

// DialContext connects to the control endpoint, retrying until ctx expires.
// The retry loop lives here rather than in the client because both platforms
// need it: the daemon binds its endpoint asynchronously after launch.
func DialContext(ctx context.Context, endpoint string) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ValidateEndpoint(endpoint); err != nil {
		return nil, err
	}
	return dialEndpoint(ctx, endpoint)
}

// Dial connects to the control endpoint with a bounded default timeout.
func Dial(endpoint string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return DialContext(ctx, endpoint)
}
