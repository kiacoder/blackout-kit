package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultEventBuffer is how many telemetry events a client holds before the
// oldest are dropped. The HUD renders at 60Hz and drains continuously; the
// buffer only needs to absorb a UI hitch, not store history.
const DefaultEventBuffer = 256

// Client is the caller side of the control channel — used by the C# HUD, the
// Python CLI and the test battery alike.
type Client struct {
	conn   net.Conn
	reader *frameReader
	writer *frameWriter

	writeMu sync.Mutex

	pendingMu sync.Mutex
	pending   map[string]chan *Envelope

	events chan *Envelope

	id     atomic.Uint64
	closed chan struct{}
	once   sync.Once

	// ServerVersion is populated by a successful Handshake.
	ServerVersion string
	// Methods is the capability list advertised by the daemon.
	Methods []string
}

// ErrClosed is returned once the client has been closed.
var ErrClosed = errors.New("ipc: client is closed")

// NewClient dials the endpoint without performing a handshake. Use Connect
// for the normal case; NewClient exists so tests can drive a handshake
// failure against a live server.
func NewClient(endpoint string) (*Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := DialContext(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	return newClient(conn), nil
}

// Connect dials and completes the handshake. This is what callers normally
// want: it proves the daemon is alive and speaking a compatible version before
// any engine command is attempted.
func Connect(ctx context.Context, endpoint, clientName string) (*Client, error) {
	conn, err := DialContext(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	c := newClient(conn)
	if _, err := c.Handshake(ctx, HandshakeParams{
		APIVersion:    APIVersion,
		ClientName:    clientName,
		ClientVersion: APIVersion,
	}); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

func newClient(conn net.Conn) *Client {
	c := &Client{
		conn:    conn,
		reader:  newFrameReader(conn, MaxFrameSize),
		writer:  newFrameWriter(conn),
		pending: make(map[string]chan *Envelope),
		events:  make(chan *Envelope, DefaultEventBuffer),
		closed:  make(chan struct{}),
	}
	go c.readLoop()
	return c
}

// Handshake negotiates the protocol version and records the server's
// advertised method table.
func (c *Client) Handshake(ctx context.Context, p HandshakeParams) (*HandshakeResult, error) {
	var out HandshakeResult
	if err := c.Call(ctx, MethodHandshake, p, &out); err != nil {
		return nil, err
	}
	c.ServerVersion = out.APIVersion
	c.Methods = out.Methods
	return &out, nil
}

// Call sends one request and waits for its matching response.
//
// params is JSON-marshalled into the request; out, when non-nil, receives the
// response payload. A wire-level error is returned as *Error so callers can
// branch on Code.
func (c *Client) Call(ctx context.Context, method string, params, out any) error {
	if ctx == nil {
		ctx = context.Background()
	}
	id := fmt.Sprintf("%d", c.id.Add(1))

	req, err := NewRequest(id, method, params)
	if err != nil {
		return err
	}

	ch := make(chan *Envelope, 1)
	c.pendingMu.Lock()
	select {
	case <-c.closed:
		c.pendingMu.Unlock()
		return ErrClosed
	default:
	}
	c.pending[id] = ch
	c.pendingMu.Unlock()

	defer func() {
		c.pendingMu.Lock()
		delete(c.pending, id)
		c.pendingMu.Unlock()
	}()

	c.writeMu.Lock()
	writeErr := c.writer.Write(req)
	c.writeMu.Unlock()
	if writeErr != nil {
		return fmt.Errorf("ipc: send %s: %w", method, writeErr)
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.closed:
		return ErrClosed
	case resp := <-ch:
		if resp.Error != nil {
			return resp.Error
		}
		if out != nil {
			return resp.DecodePayload(out)
		}
		return nil
	}
}

// Subscribe opens the telemetry stream. Events become readable through Events.
func (c *Client) Subscribe(ctx context.Context) error {
	var out SubscribeResult
	return c.Call(ctx, MethodSubscribe, nil, &out)
}

// Unsubscribe closes the telemetry stream for this client.
func (c *Client) Unsubscribe(ctx context.Context) error {
	var out SubscribeResult
	return c.Call(ctx, MethodUnsubscribe, nil, &out)
}

// Start asks the daemon to bring an engine up.
func (c *Client) Start(ctx context.Context, p StartParams) (*StartResult, error) {
	var out StartResult
	if err := c.Call(ctx, MethodStart, p, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Stop asks the daemon to bring the engine down.
func (c *Client) Stop(ctx context.Context) (*StatusResult, error) {
	var out StatusResult
	if err := c.Call(ctx, MethodStop, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Tune applies live fragment/SNI settings.
func (c *Client) Tune(ctx context.Context, p TuneParams) (*TuneResult, error) {
	var out TuneResult
	if err := c.Call(ctx, MethodTune, p, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Status reads the current engine state plus a telemetry snapshot.
func (c *Client) Status(ctx context.Context) (*StatusResult, error) {
	var out StatusResult
	if err := c.Call(ctx, MethodStatus, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Ping is a cheap liveness check.
func (c *Client) Ping(ctx context.Context) error {
	var out PongResult
	return c.Call(ctx, MethodPing, nil, &out)
}

// Shutdown asks the daemon to terminate.
func (c *Client) Shutdown(ctx context.Context) error {
	var out PongResult
	return c.Call(ctx, MethodShutdown, nil, &out)
}

// Events exposes the telemetry stream.
func (c *Client) Events() <-chan *Envelope { return c.events }

// NextTelemetry blocks until one telemetry event arrives or ctx expires.
func (c *Client) NextTelemetry(ctx context.Context) (*Telemetry, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, ErrClosed
	case env := <-c.events:
		var t Telemetry
		if err := env.DecodePayload(&t); err != nil {
			return nil, err
		}
		return &t, nil
	}
}

// Close shuts the client down and unblocks any in-flight waits.
func (c *Client) Close() error {
	c.once.Do(func() {
		close(c.closed)
		_ = c.conn.Close()
		c.pendingMu.Lock()
		for id, ch := range c.pending {
			delete(c.pending, id)
			close(ch)
		}
		c.pendingMu.Unlock()
	})
	return nil
}

func (c *Client) readLoop() {
	for {
		env, err := c.reader.Read()
		if err != nil {
			_ = c.Close()
			return
		}
		switch env.Kind {
		case KindEvent:
			select {
			case c.events <- env:
			default:
				// Drop the oldest event rather than blocking the reader; a
				// stalled consumer must not wedge the control channel.
				select {
				case <-c.events:
				default:
				}
				select {
				case c.events <- env:
				default:
				}
			}
		default:
			c.pendingMu.Lock()
			ch, ok := c.pending[env.ID]
			if ok {
				delete(c.pending, env.ID)
			}
			c.pendingMu.Unlock()
			if ok {
				select {
				case ch <- env:
				default:
				}
			}
		}
	}
}
