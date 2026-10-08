//go:build windows

package ipc

import (
	"context"
	"fmt"
	"net"
	"time"

	winio "github.com/Microsoft/go-winio"
)

// listenEndpoint opens a Windows named pipe in byte-stream mode.
//
// The security descriptor is deliberately left empty so go-winio applies its
// default: full access to SYSTEM, the local Administrators group and the
// creating user. That matters because this pipe accepts engine control
// commands — leaving it world-writable would let any logon session start or
// stop the bypass engine.
func listenEndpoint(addr string) (net.Listener, error) {
	cfg := &winio.PipeConfig{
		MessageMode:      false, // byte stream, not message mode
		InputBufferSize:  64 * 1024,
		OutputBufferSize: 64 * 1024,
	}
	ln, err := winio.ListenPipe(addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("ipc: listen pipe %s: %w", addr, err)
	}
	return ln, nil
}

// dialEndpoint connects to a named pipe, retrying while the context is live.
//
// Retrying is not cosmetic: the daemon creates the pipe asynchronously after
// the supervisor launches it, so an immediate first dial routinely fails with
// ERROR_FILE_NOT_FOUND even though the daemon is healthy.
func dialEndpoint(ctx context.Context, addr string) (net.Conn, error) {
	// winio.DialPipe takes a timeout rather than a context, so a short per
	// attempt timeout bounds each try and the outer loop honours ctx.
	const attemptTimeout = 2 * time.Second

	backoff := 10 * time.Millisecond
	const maxBackoff = 200 * time.Millisecond

	var lastErr error
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return nil, fmt.Errorf("ipc: dial %s: %w (last: %v)", addr, err, lastErr)
			}
			return nil, fmt.Errorf("ipc: dial %s: %w", addr, err)
		}

		timeout := attemptTimeout
		conn, err := winio.DialPipe(addr, &timeout)
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
