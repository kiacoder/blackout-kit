// Command blackout-core is the v2 supervised daemon.
//
// It is a standalone process, not a library loaded into the CLI. That is the
// whole point of the v2 execution model: v1 loaded blackout_core.dll into the
// Python process, so a panic in the Go core took the CLI down with it and no
// telemetry could ever be pushed back. Here the daemon owns the engines and
// exposes them over a local IPC endpoint; clients (the C# HUD, the Python
// CLI, the test battery) are just peers on that pipe.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"blackout-engine-v2/pkg/dialer"
	"blackout-engine-v2/pkg/ipc"
	"blackout-engine-v2/pkg/sentinel"
	"blackout-engine-v2/pkg/tunnel"
)

// controller is the daemon's engine state. It is deliberately small: the real
// engine implementations plug in behind the ipc.Controller interface, and this
// type only owns the policy that has to exist before they land.
type controller struct {
	mu        sync.Mutex
	status    ipc.EngineStatus
	engine    string
	cfg       dialer.Config
	startedAt time.Time
	bytesIn   atomic.Uint64
	bytesOut  atomic.Uint64
	rttMs     atomic.Uint64 // float64 bits
	tunnel    *tunnel.Server
}

func newController() *controller {
	return &controller{
		status: ipc.StatusStopped,
		cfg:    dialer.DefaultConfig(),
	}
}

func (c *controller) Start(_ context.Context, p ipc.StartParams) (ipc.StartResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if p.Engine == "" {
		return ipc.StartResult{}, &ipc.Error{Code: ipc.CodeBadRequest, Message: "start requires 'engine'"}
	}
	if p.Engine == "socks-tunnel" {
		res, err := c.startTunnelLocked(p)
		if err != nil {
			return ipc.StartResult{}, err
		}
		return res, nil
	}
	c.engine = p.Engine
	c.status = ipc.StatusRunning
	c.startedAt = time.Now()
	return ipc.StartResult{Engine: p.Engine, Status: string(c.status)}, nil
}

// defaultTunnelListen is the loopback bind used when StartParams carries no
// explicit "listen" value. The tunnel package refuses anything non-loopback
// regardless of what is configured.
const defaultTunnelListen = "127.0.0.1:18080"

func (c *controller) startTunnelLocked(p ipc.StartParams) (ipc.StartResult, error) {
	if c.tunnel != nil {
		return ipc.StartResult{}, &ipc.Error{Code: ipc.CodeBadRequest, Message: "socks-tunnel is already running; stop it first"}
	}
	listen := p.Config["listen"]
	if listen == "" {
		listen = defaultTunnelListen
	}
	srv, err := tunnel.New(tunnel.Config{Listen: listen, Dialer: c.cfg})
	if err != nil {
		return ipc.StartResult{}, &ipc.Error{Code: ipc.CodeBadRequest, Message: err.Error()}
	}
	srv.Log = func(msg string) { log.Print(msg) }
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(context.Background()) }()
	go func() {
		// A background-context Serve only returns on its own if the accept
		// loop dies unexpectedly (Close makes it return nil). Do not let the
		// status keep claiming a tunnel that is gone.
		if err := <-serveErr; err != nil {
			log.Printf("blackout-core: socks-tunnel stopped: %v", err)
			c.mu.Lock()
			if c.tunnel == srv {
				c.tunnel = nil
				c.status = ipc.StatusFailed
			}
			c.mu.Unlock()
		}
	}()
	c.tunnel = srv
	c.engine = p.Engine
	c.status = ipc.StatusRunning
	c.startedAt = time.Now()
	return ipc.StartResult{
		Engine: p.Engine,
		Status: string(c.status),
		Listen: srv.Addr().String(),
	}, nil
}

func (c *controller) Stop(_ context.Context) (ipc.EngineStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status = ipc.StatusStopped
	c.startedAt = time.Time{}
	if c.tunnel != nil {
		_ = c.tunnel.Close()
		c.tunnel = nil
	}
	return c.status, nil
}

func (c *controller) Tune(_ context.Context, p ipc.TuneParams) (ipc.TuneResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Normalize, never reject: a bad tune value should clamp, not kill the
	// engine that is currently keeping the user online. Zero means "keep the
	// current value" — the same semantics ipc.MemController applies — so a
	// client tuning only FakeSNI cannot accidentally reset chunking to the
	// minimum by sending zeroed, unset fields.
	if p.MinChunk > 0 {
		c.cfg.MinChunk = p.MinChunk
	}
	if p.MaxChunk > 0 {
		c.cfg.MaxChunk = p.MaxChunk
	}
	if p.MinDelay > 0 {
		c.cfg.MinDelay = time.Duration(p.MinDelay) * time.Microsecond
	}
	if p.MaxDelay > 0 {
		c.cfg.MaxDelay = time.Duration(p.MaxDelay) * time.Microsecond
	}
	if p.FakeSNI != "" {
		c.cfg.FakeSNI = p.FakeSNI
	}
	if p.Fragments != nil {
		c.cfg.Fragments = *p.Fragments
	}
	c.cfg = c.cfg.Normalize()
	if c.tunnel != nil {
		c.tunnel.SetDialer(c.cfg)
	}

	return ipc.TuneResult{
		MinChunk:  c.cfg.MinChunk,
		MaxChunk:  c.cfg.MaxChunk,
		MinDelay:  int(c.cfg.MinDelay / time.Microsecond),
		MaxDelay:  int(c.cfg.MaxDelay / time.Microsecond),
		FakeSNI:   c.cfg.FakeSNI,
		Fragments: c.cfg.Fragments,
	}, nil
}

func (c *controller) Status() (ipc.EngineStatus, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status, c.engine
}

func (c *controller) Snapshot() ipc.Telemetry {
	c.mu.Lock()
	engine, status := c.engine, c.status
	var tunnelIn, tunnelOut uint64
	if c.tunnel != nil {
		tunnelIn, tunnelOut = c.tunnel.BytesIn(), c.tunnel.BytesOut()
	}
	c.mu.Unlock()
	return ipc.Telemetry{
		Engine:   engine,
		Status:   status,
		RTTMs:    math.Float64frombits(c.rttMs.Load()),
		BytesIn:  c.bytesIn.Load() + tunnelIn,
		BytesOut: c.bytesOut.Load() + tunnelOut,
		At:       time.Now().UnixMilli(),
	}
}

// tunnelAddr exposes the bound tunnel address for tests and diagnostics; it
// is empty when no tunnel is running.
func (c *controller) tunnelAddr() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tunnel == nil {
		return ""
	}
	return c.tunnel.Addr().String()
}

func (c *controller) setRTT(ms float64) { c.rttMs.Store(math.Float64bits(ms)) }

func main() {
	endpoint := flag.String("endpoint", ipc.DefaultEndpoint(), "control endpoint (pipe name or unix socket path)")
	interval := flag.Duration("telemetry-interval", 1*time.Second, "how often to publish telemetry")
	targets := flag.String("probe-targets", "", "comma-separated host:port pairs for the sentinel; empty disables it")
	noSentinel := flag.Bool("no-sentinel", false, "disable the health watchdog")
	showVersion := flag.Bool("version", false, "print the IPC protocol version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(ipc.APIVersion)
		return
	}

	if err := run(*endpoint, *interval, *targets, *noSentinel); err != nil {
		log.Printf("blackout-core: %v", err)
		os.Exit(1)
	}
}

func run(endpoint string, interval time.Duration, rawTargets string, noSentinel bool) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ctrl := newController()

	srv, err := ipc.NewServer(endpoint, ctrl)
	if err != nil {
		return err
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ctx) }()

	log.Printf("blackout-core: listening on %s (api %s, pid %d)", endpoint, ipc.APIVersion, os.Getpid())

	watchCtx, cancelWatch := context.WithCancel(ctx)
	defer cancelWatch()
	if !noSentinel {
		go runSentinel(watchCtx, ctrl, rawTargets, srv)
	}

	// Telemetry publisher. Runs whether or not anyone is subscribed because
	// Publish is a no-op with no subscribers, and starting it lazily would
	// mean the HUD misses the first samples after connecting.
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case err := <-serveErr:
			if err != nil && ctx.Err() == nil {
				return err
			}
			return nil
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := srv.Shutdown(shutdownCtx); err != nil {
				return fmt.Errorf("shutdown: %w", err)
			}
			log.Print("blackout-core: stopped")
			return nil
		case <-ticker.C:
			srv.Publish(ctrl.Snapshot())
		}
	}
}

// runSentinel wires the health watchdog into telemetry and failover logging.
func runSentinel(ctx context.Context, ctrl *controller, rawTargets string, srv *ipc.Server) {
	cfg := sentinel.DefaultConfig()
	if rawTargets != "" {
		parts := strings.Split(rawTargets, ",")
		targets := make([]string, 0, len(parts))
		for _, p := range parts {
			if t := strings.TrimSpace(p); t != "" {
				targets = append(targets, t)
			}
		}
		if len(targets) > 0 {
			cfg.Targets = targets
		}
	}

	s, err := sentinel.New(cfg, sentinel.TCPProber(cfg.Timeout))
	if err != nil {
		log.Printf("blackout-core: sentinel disabled: %v", err)
		return
	}

	s.OnSample = func(sample sentinel.Sample) {
		ctrl.setRTT(sample.RTTMs)
	}
	s.OnFailover = func(reason string, sample sentinel.Sample) {
		var detail string
		if sample.Err != "" {
			detail = sample.Err
		} else {
			detail = fmt.Sprintf("%.1fms to %s", sample.RTTMs, sample.Target)
		}
		log.Printf("blackout-core: failover (%s): %s", reason, detail)
		srv.Publish(ctrl.Snapshot())
	}

	s.Run(ctx)
}
