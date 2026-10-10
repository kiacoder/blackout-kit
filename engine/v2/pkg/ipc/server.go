package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Controller is what the daemon actually drives. The IPC layer owns transport
// and framing only; engine behaviour is injected so the same server can be
// tested against a stub and later wired to the real dialer/sentinel stack.
type Controller interface {
	Start(ctx context.Context, p StartParams) (StartResult, error)
	Stop(ctx context.Context) (EngineStatus, error)
	Tune(ctx context.Context, p TuneParams) (TuneResult, error)
	Status() (EngineStatus, string)
	Snapshot() Telemetry
}

// MemController is the default controller: it records state and does no I/O.
// It ships so the daemon is runnable and testable before the v2 engine stack
// lands, and so unit tests never need a real network.
type MemController struct {
	mu        sync.Mutex
	status    EngineStatus
	engine    string
	tune      TuneResult
	startedAt int64
	bytesIn   uint64
	bytesOut  uint64
	rtt       float64
	failStart bool
}

// NewMemController returns an idle controller with sane tune defaults.
func NewMemController() *MemController {
	return &MemController{
		status: StatusStopped,
		tune: TuneResult{
			MinChunk:  8,
			MaxChunk:  24,
			MinDelay:  100,
			MaxDelay:  500,
			Fragments: true,
		},
	}
}

// SetStartFailure makes the next Start return an error, for failover tests.
func (m *MemController) SetStartFailure(fail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failStart = fail
}

func (m *MemController) Start(_ context.Context, p StartParams) (StartResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failStart {
		m.status = StatusFailed
		return StartResult{}, &Error{Code: CodeEngineFailure, Message: "start failed (injected)"}
	}
	if p.Engine == "" {
		return StartResult{}, &Error{Code: CodeBadRequest, Message: "start requires 'engine'"}
	}
	m.engine = p.Engine
	m.status = StatusRunning
	m.startedAt = time.Now().UnixMilli()
	return StartResult{Engine: p.Engine, Status: string(m.status)}, nil
}

func (m *MemController) Stop(_ context.Context) (EngineStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status = StatusStopped
	m.startedAt = 0
	return m.status, nil
}

func (m *MemController) Tune(_ context.Context, p TuneParams) (TuneResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p.MinChunk > 0 {
		m.tune.MinChunk = p.MinChunk
	}
	if p.MaxChunk > 0 {
		m.tune.MaxChunk = p.MaxChunk
	}
	if m.tune.MinChunk > m.tune.MaxChunk {
		m.tune.MinChunk = m.tune.MaxChunk
	}
	if p.MinDelay > 0 {
		m.tune.MinDelay = p.MinDelay
	}
	if p.MaxDelay > 0 {
		m.tune.MaxDelay = p.MaxDelay
	}
	if m.tune.MinDelay > m.tune.MaxDelay {
		m.tune.MinDelay = m.tune.MaxDelay
	}
	if p.FakeSNI != "" {
		m.tune.FakeSNI = p.FakeSNI
	}
	if p.Fragments != nil {
		m.tune.Fragments = *p.Fragments
	}
	return m.tune, nil
}

func (m *MemController) Status() (EngineStatus, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status, m.engine
}

func (m *MemController) Snapshot() Telemetry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Telemetry{
		Engine:   m.engine,
		Status:   m.status,
		RTTMs:    m.rtt,
		BytesIn:  m.bytesIn,
		BytesOut: m.bytesOut,
		At:       time.Now().UnixMilli(),
	}
}

// AddTraffic is a test hook that moves the byte counters.
func (m *MemController) AddTraffic(in, out uint64) {
	atomic.AddUint64(&m.bytesIn, in)
	atomic.AddUint64(&m.bytesOut, out)
}

// SetRTT is a test hook for the latency field.
func (m *MemController) SetRTT(ms float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rtt = ms
}

// Server is the daemon-side IPC endpoint.
type Server struct {
	endpoint string
	version  string
	ctrl     Controller

	ln     *Listener
	lnMu   sync.Mutex // guards ln: Serve assigns it, Shutdown reads it
	hub    *hub
	seq    atomic.Uint64
	pid    int
	closed chan struct{}
	once   sync.Once

	wg       sync.WaitGroup
	mu       sync.Mutex
	sessions map[*session]struct{}
	serveErr error
}

// NewServer builds a server bound to nothing yet. Endpoint validation happens
// here so a bad path fails at construction, not inside the accept loop.
func NewServer(endpoint string, ctrl Controller) (*Server, error) {
	if err := ValidateEndpoint(endpoint); err != nil {
		return nil, err
	}
	if ctrl == nil {
		ctrl = NewMemController()
	}
	return &Server{
		endpoint: endpoint,
		version:  APIVersion,
		ctrl:     ctrl,
		hub:      newHub(),
		pid:      os.Getpid(),
		closed:   make(chan struct{}),
		sessions: make(map[*session]struct{}),
	}, nil
}

// Endpoint returns the address this server will bind.
func (s *Server) Endpoint() string { return s.endpoint }

// Serve binds the endpoint and accepts connections until ctx is cancelled or
// Shutdown is called. It returns nil on a clean shutdown.
func (s *Server) Serve(ctx context.Context) error {
	ln, err := Listen(s.endpoint)
	if err != nil {
		return err
	}
	s.lnMu.Lock()
	s.ln = ln
	s.lnMu.Unlock()
	defer func() { _ = ln.Close() }()

	// Watch ctx so a cancelled parent tears down the listener.
	go func() {
		select {
		case <-ctx.Done():
			_ = ln.Close()
		case <-s.closed:
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.closed:
				return nil
			case <-ctx.Done():
				return nil
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			// Transient accept failures should not kill the daemon.
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			s.serveErr = err
			return err
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(ctx, conn)
		}()
	}
}

// Shutdown stops accepting, closes every session and waits for them to drain.
func (s *Server) Shutdown(ctx context.Context) error {
	s.once.Do(func() { close(s.closed) })
	s.lnMu.Lock()
	ln := s.ln
	s.lnMu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}

	s.mu.Lock()
	sessions := make([]*session, 0, len(s.sessions))
	for sess := range s.sessions {
		sessions = append(sessions, sess)
	}
	s.mu.Unlock()

	for _, sess := range sessions {
		sess.close()
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	sess := newSession(conn, s)
	s.mu.Lock()
	s.sessions[sess] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.sessions, sess)
		s.mu.Unlock()
		s.hub.remove(sess)
		sess.close()
		_ = conn.Close()
	}()
	sess.run(ctx)
}

// Publish broadcasts a telemetry event to every subscribed session.
// Sessions with a full queue are skipped rather than blocking: telemetry is
// advisory, and stalling the daemon on a slow HUD would be a self-inflicted
// outage of the control channel.
func (s *Server) Publish(t Telemetry) {
	env, err := NewEvent(s.seq.Add(1), t)
	if err != nil {
		return
	}
	s.hub.broadcast(env)
}

// session is one connected client.
type session struct {
	conn   net.Conn
	server *Server
	reader *frameReader
	writer *frameWriter
	out    chan *Envelope
	sub    atomic.Bool
	closed chan struct{}
	once   sync.Once
}

func newSession(conn net.Conn, srv *Server) *session {
	return &session{
		conn:   conn,
		server: srv,
		reader: newFrameReader(conn, MaxFrameSize),
		writer: newFrameWriter(conn),
		out:    make(chan *Envelope, 128),
		closed: make(chan struct{}),
	}
}

func (s *session) run(ctx context.Context) {
	go s.writeLoop()
	s.readLoop(ctx)
}

func (s *session) readLoop(ctx context.Context) {
	for {
		env, err := s.reader.Read()
		if err != nil {
			return
		}
		resp := s.server.dispatch(ctx, s, env)
		if resp == nil {
			continue // notification: no reply
		}
		s.send(resp)
	}
}

func (s *session) writeLoop() {
	for {
		select {
		case env := <-s.out:
			if err := s.writer.Write(env); err != nil {
				return
			}
		case <-s.closed:
			return
		}
	}
}

// send queues a frame. Returns false if the session is closed or saturated.
func (s *session) send(env *Envelope) bool {
	select {
	case <-s.closed:
		return false
	default:
	}
	select {
	case s.out <- env:
		return true
	default:
		return false
	}
}

func (s *session) deliver(env *Envelope) {
	if s.sub.Load() {
		s.send(env)
	}
}

func (s *session) close() {
	s.once.Do(func() {
		close(s.closed)
		// Closing the connection is what unblocks the read loop. Without it a
		// session parked in Read() never returns, and Server.Shutdown — which
		// waits on the session waitgroup — deadlocks until its context expires.
		_ = s.conn.Close()
	})
}

func (s *session) endpointName() string {
	if s.server != nil {
		return s.server.endpoint
	}
	return ""
}

// dispatch routes one request to its handler.
func (s *Server) dispatch(ctx context.Context, sess *session, env *Envelope) *Envelope {
	// Only requests are served. Echoing a stray response or event back would
	// be a loop risk, and the check lives here rather than in the read loop so
	// dispatch is total: any envelope produces a defined answer.
	if env.Kind != KindRequest {
		return NewErrorResponse(env.ID, &Error{
			Code:    CodeBadRequest,
			Message: fmt.Sprintf("server accepts requests only, got %q", env.Kind),
		})
	}

	// Version gate: an incompatible client is rejected before any state change.
	// The daemon's version is authoritative for the session.
	if !Compatible(env.Version, s.version) {
		return NewErrorResponse(env.ID, &Error{
			Code:    CodeUnsupportedVersion,
			Message: fmt.Sprintf("client %q is not compatible with server %q", env.Version, s.version),
		})
	}

	switch env.Method {
	case MethodHandshake:
		var p HandshakeParams
		if err := env.DecodeParams(&p); err != nil {
			return NewErrorResponse(env.ID, err)
		}
		if !Compatible(p.APIVersion, s.version) {
			return NewErrorResponse(env.ID, &Error{
				Code:    CodeUnsupportedVersion,
				Message: fmt.Sprintf("requested %q, server speaks %q", p.APIVersion, s.version),
			})
		}
		res, err := NewResponse(env.ID, HandshakeResult{
			APIVersion: s.version,
			Methods:    Methods,
			Endpoint:   s.endpoint,
			PID:        s.pid,
		})
		if err != nil {
			return NewErrorResponse(env.ID, err)
		}
		return res

	case MethodPing:
		res, err := NewResponse(env.ID, PongResult{OK: true})
		if err != nil {
			return NewErrorResponse(env.ID, err)
		}
		return res

	case MethodStart:
		var p StartParams
		if err := env.DecodeParams(&p); err != nil {
			return NewErrorResponse(env.ID, err)
		}
		out, err := s.ctrl.Start(ctx, p)
		if err != nil {
			return NewErrorResponse(env.ID, err)
		}
		res, mErr := NewResponse(env.ID, out)
		if mErr != nil {
			return NewErrorResponse(env.ID, mErr)
		}
		return res

	case MethodStop:
		status, err := s.ctrl.Stop(ctx)
		if err != nil {
			return NewErrorResponse(env.ID, err)
		}
		engStatus, name := s.ctrl.Status()
		_ = engStatus
		res, mErr := NewResponse(env.ID, StatusResult{
			Engine:    name,
			Status:    status,
			Telemetry: s.ctrl.Snapshot(),
		})
		if mErr != nil {
			return NewErrorResponse(env.ID, mErr)
		}
		return res

	case MethodTune:
		var p TuneParams
		if err := env.DecodeParams(&p); err != nil {
			return NewErrorResponse(env.ID, err)
		}
		out, err := s.ctrl.Tune(ctx, p)
		if err != nil {
			return NewErrorResponse(env.ID, err)
		}
		res, mErr := NewResponse(env.ID, out)
		if mErr != nil {
			return NewErrorResponse(env.ID, mErr)
		}
		return res

	case MethodStatus:
		status, name := s.ctrl.Status()
		res, err := NewResponse(env.ID, StatusResult{
			Engine:    name,
			Status:    status,
			Telemetry: s.ctrl.Snapshot(),
		})
		if err != nil {
			return NewErrorResponse(env.ID, err)
		}
		return res

	case MethodSubscribe:
		sess.sub.Store(true)
		s.hub.add(sess)
		res, err := NewResponse(env.ID, SubscribeResult{Subscribed: true, Endpoint: s.endpoint})
		if err != nil {
			return NewErrorResponse(env.ID, err)
		}
		return res

	case MethodUnsubscribe:
		if !sess.sub.Load() {
			return NewErrorResponse(env.ID, &Error{
				Code:    CodeNotSubscribed,
				Message: "session is not subscribed",
			})
		}
		sess.sub.Store(false)
		s.hub.remove(sess)
		res, err := NewResponse(env.ID, SubscribeResult{Subscribed: false})
		if err != nil {
			return NewErrorResponse(env.ID, err)
		}
		return res

	case MethodShutdown:
		res, err := NewResponse(env.ID, PongResult{OK: true})
		if err != nil {
			return NewErrorResponse(env.ID, err)
		}
		// Shut down after the reply is queued so the caller sees an ack.
		go func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = s.Shutdown(shutdownCtx)
		}()
		return res

	default:
		return NewErrorResponse(env.ID, &Error{
			Code:    CodeUnknownMethod,
			Message: fmt.Sprintf("no such method %q", env.Method),
		})
	}
}

// hub tracks telemetry subscribers.
type hub struct {
	mu   sync.RWMutex
	subs map[*session]struct{}
}

func newHub() *hub { return &hub{subs: make(map[*session]struct{})} }

func (h *hub) add(s *session) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.subs[s] = struct{}{}
}

func (h *hub) remove(s *session) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.subs, s)
}

func (h *hub) broadcast(env *Envelope) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for s := range h.subs {
		s.deliver(env)
	}
}

// Count is a test hook: number of current subscribers.
func (h *hub) Count() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.subs)
}
