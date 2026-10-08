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
// The pipe carries engine control commands, so its ACL must be tight: an
// overly permissive descriptor would let any logon session start or stop the
// bypass engine. We therefore set an explicit security descriptor instead of
// relying on go-winio's default, which additionally grants SYSTEM and the local
// Administrators group full control.
//
//	SecurityDescriptor: "D:(A;;GA;;;OW)"
//
// SDDL breakdown:
//   - D:      — DACL (discretionary ACL)
//   - (A;;GA;;;OW) — allow (A) generic-all (GA) to the object owner (OW)
//
// GA (generic all) maps to FILE_ALL_ACCESS for a named pipe, and OW is the
// object's owner — i.e. the user that launched the daemon. No other principal
// (SYSTEM, Administrators, or other logon sessions) receives access, so only
// the owning user's processes can open the control channel.
func listenEndpoint(addr string) (net.Listener, error) {
	cfg := &winio.PipeConfig{
		MessageMode:      false, // byte stream, not message mode
		InputBufferSize:  64 * 1024,
		OutputBufferSize: 64 * 1024,
		// Restrict the pipe to the creating user (owner) only. An empty
		// SecurityDescriptor would fall back to go-winio's built-in default that
		// also grants SYSTEM and the local Administrators group full control.
		SecurityDescriptor: "D:(A;;GA;;;OW)",
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
