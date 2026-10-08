//go:build !windows

package ipc

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

// listenEndpoint opens a Unix domain socket.
//
// A stale socket file from a crashed daemon would otherwise make bind fail with
// "address already in use" forever, so it is cleared first. The parent
// directory is created because /tmp may be per-user (TMPDIR, private tmp).
func listenEndpoint(addr string) (net.Listener, error) {
	if dir := filepath.Dir(addr); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("ipc: create socket dir %s: %w", dir, err)
		}
	}
	if err := removeStaleSocket(addr); err != nil {
		return nil, err
	}
	ln, err := net.Listen("unix", addr)
	if err != nil {
		return nil, fmt.Errorf("ipc: listen unix %s: %w", addr, err)
	}
	// Restrict after bind: this endpoint can start and stop engines, so it is
	// owner-only even though /tmp is usually sticky. Chmod is used rather than
	// umask because umask is process-global and would race with other tests.
	if err := os.Chmod(addr, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("ipc: chmod %s: %w", addr, err)
	}
	return ln, nil
}

// dialEndpoint connects to a Unix domain socket, retrying while ctx is live.
// The daemon may not have bound the socket yet.
func dialEndpoint(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	backoff := 10 * time.Millisecond
	const maxBackoff = 200 * time.Millisecond

	var lastErr error
	for {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return nil, fmt.Errorf("ipc: dial %s: %w (last: %v)", addr, err, lastErr)
			}
			return nil, fmt.Errorf("ipc: dial %s: %w", addr, err)
		}
		conn, err := d.DialContext(ctx, "unix", addr)
		if err == nil {
			return conn, nil
		}
		lastErr = err

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("ipc: dial %s: %w (last: %v)", addr, ctx.Err(), lastErr)
		case <-time.After(backoff):
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

// removeStaleSocket deletes a leftover socket file. It leaves any other file
// type alone: silently unlinking a real file at a shared path would be worse
// than failing loudly.
func removeStaleSocket(addr string) error {
	info, err := os.Lstat(addr)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("ipc: stat %s: %w", addr, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("ipc: %s exists and is not a socket", addr)
	}
	if err := os.Remove(addr); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("ipc: remove stale socket %s: %w", addr, err)
	}
	return nil
}
