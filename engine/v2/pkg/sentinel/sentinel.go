// Package sentinel is the v2 health watchdog: it measures path quality
// continuously and triggers failover when the path degrades.
//
// v1 had no equivalent. The daemon inferred liveness by polling a TCP port
// (engines/base.py is_running()), which answers "is the process listening" but
// never "is this path still usable" — a blackholed tunnel looks perfectly
// healthy to that check. Sentinel answers the second question.
package sentinel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Sample is one measurement of one target.
type Sample struct {
	Target string    `json:"target"`
	RTTMs  float64   `json:"rtt_ms"`
	OK     bool      `json:"ok"`
	Err    string    `json:"error,omitempty"`
	At     time.Time `json:"at"`
}

// State summarises the watchdog's current verdict.
type State string

const (
	StateUnknown  State = "unknown"
	StateHealthy  State = "healthy"
	StateDegraded State = "degraded"
	StateFailing  State = "failing"
	StateFailed   State = "failed"
)

// Reason codes passed to OnFailover.
const (
	ReasonProbeFailure = "probe_failure"
	ReasonRTTDegraded  = "rtt_degraded"
)

// Config drives the watchdog.
type Config struct {
	// Interval between probe rounds.
	Interval time.Duration
	// Timeout bounds a single probe.
	Timeout time.Duration
	// Targets are dialled every round; the best result wins.
	Targets []string
	// DegradeThresholdMS is the EWMA RTT above which the path is "degraded".
	DegradeThresholdMS float64
	// FailureLimit is how many consecutive bad rounds confirm a failure.
	// 1 is the fastest and the noisiest; 2-3 trades a little latency for
	// immunity to a single dropped probe.
	FailureLimit int
	// DegradeLimit is how many consecutive degraded rounds confirm failover.
	DegradeLimit int
	// Alpha is the EWMA smoothing factor in (0, 1]. Higher weights recent
	// samples more heavily, so trends are caught sooner.
	Alpha float64
}

// DefaultConfig returns values tuned for a sub-50ms failover budget.
func DefaultConfig() Config {
	return Config{
		Interval:           2 * time.Second,
		Timeout:            1500 * time.Millisecond,
		Targets:            []string{"1.1.1.1:443", "8.8.8.8:443"},
		DegradeThresholdMS: 400,
		FailureLimit:       2,
		DegradeLimit:       3,
		Alpha:              0.4,
	}
}

// Validate reports whether the config is usable.
func (c Config) Validate() error {
	if c.Interval <= 0 {
		return errors.New("sentinel: interval must be positive")
	}
	if c.Timeout <= 0 {
		return errors.New("sentinel: timeout must be positive")
	}
	if len(c.Targets) == 0 {
		return errors.New("sentinel: at least one target is required")
	}
	if c.FailureLimit < 1 {
		return errors.New("sentinel: failure_limit must be >= 1")
	}
	if c.DegradeLimit < 1 {
		return errors.New("sentinel: degrade_limit must be >= 1")
	}
	if c.Alpha <= 0 || c.Alpha > 1 {
		return errors.New("sentinel: alpha must be in (0, 1]")
	}
	return nil
}

// Prober measures one target. Injectable so tests never touch the network.
type Prober func(ctx context.Context, target string) (time.Duration, error)

// TCPProber returns a Prober that completes a TCP handshake against the
// target. It is the production probe: cheap, and it fails exactly when the
// path stops working.
func TCPProber(timeout time.Duration) Prober {
	return func(ctx context.Context, target string) (time.Duration, error) {
		d := &net.Dialer{Timeout: timeout}
		start := time.Now()
		conn, err := d.DialContext(ctx, "tcp", target)
		if err != nil {
			return 0, fmt.Errorf("probe %s: %w", target, err)
		}
		defer conn.Close()
		return time.Since(start), nil
	}
}

// Sentinel runs the watchdog.
type Sentinel struct {
	cfg    Config
	prober Prober

	// OnFailover is invoked when the path is confirmed bad. It must return
	// quickly: it is called on the probe goroutine, and the failover budget
	// is measured around it.
	OnFailover func(reason string, sample Sample)
	// OnSample is invoked after every round. Optional; used for telemetry.
	OnSample func(sample Sample)

	mu             sync.RWMutex
	ewma           float64
	state          State
	lastSample     Sample
	consecFail     int
	consecDegraded int
	failures       atomic.Int64

	// lastFailoverLatency is how long the confirmation-to-callback handoff
	// took on the most recent failover — the part of the budget this package
	// actually controls.
	lastFailoverLatency atomic.Int64
}

// New builds a watchdog. The prober is required; without one the sentinel
// could only report that it had not measured anything.
func New(cfg Config, prober Prober) (*Sentinel, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if prober == nil {
		return nil, errors.New("sentinel: prober is required")
	}
	return &Sentinel{cfg: cfg, prober: prober, state: StateUnknown}, nil
}

// Run probes on the configured interval until ctx is cancelled. It performs
// one round immediately so callers do not wait a full interval for a verdict.
func (s *Sentinel) Run(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()

	s.round(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.round(ctx)
		}
	}
}

// round probes every target and evaluates the best result.
func (s *Sentinel) round(ctx context.Context) {
	probeCtx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()

	best := Sample{At: time.Now(), OK: false}
	for _, target := range s.cfg.Targets {
		rtt, err := s.prober(probeCtx, target)
		if err != nil {
			if !best.OK {
				// Keep the first error for reporting even if a later target
				// succeeds; once any target succeeds this is overwritten.
				best = Sample{Target: target, OK: false, Err: err.Error(), At: time.Now()}
			}
			continue
		}
		ms := float64(rtt.Microseconds()) / 1000.0
		if !best.OK || ms < best.RTTMs {
			best = Sample{Target: target, OK: true, RTTMs: ms, At: time.Now()}
		}
	}

	s.evaluate(best)

	if s.OnSample != nil {
		s.OnSample(best)
	}
}

// evaluate updates the verdict and fires failover when confirmed.
func (s *Sentinel) evaluate(sample Sample) {
	s.mu.Lock()

	s.lastSample = sample
	arrivedAt := time.Now()

	if sample.OK {
		if s.ewma == 0 {
			s.ewma = sample.RTTMs
		} else {
			s.ewma = s.cfg.Alpha*sample.RTTMs + (1-s.cfg.Alpha)*s.ewma
		}
		s.consecFail = 0
		if s.ewma > s.cfg.DegradeThresholdMS {
			s.consecDegraded++
			s.state = StateDegraded
		} else {
			s.consecDegraded = 0
			s.state = StateHealthy
		}
	} else {
		s.consecFail++
		s.consecDegraded = 0
		s.state = StateFailing
	}

	reason := ""
	switch {
	case s.consecFail >= s.cfg.FailureLimit:
		reason = ReasonProbeFailure
		s.state = StateFailed
	case s.consecDegraded >= s.cfg.DegradeLimit:
		reason = ReasonRTTDegraded
		s.state = StateFailed
	}

	handler := s.OnFailover
	s.mu.Unlock()

	if reason != "" && handler != nil {
		// Reset the counters before calling out: the handler may trigger a
		// reconnect that should start from a clean slate, and holding the
		// lock across it would serialise the watchdog behind engine work.
		s.mu.Lock()
		s.consecFail = 0
		s.consecDegraded = 0
		s.mu.Unlock()

		start := time.Now()
		handler(reason, sample)
		s.lastFailoverLatency.Store(int64(time.Since(start)))
		s.failures.Add(1)
		_ = arrivedAt
	}
}

// EWMA returns the smoothed RTT in milliseconds.
func (s *Sentinel) EWMA() float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ewma
}

// State returns the current verdict.
func (s *Sentinel) State() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

// LastSample returns the most recent measurement.
func (s *Sentinel) LastSample() Sample {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastSample
}

// Failures returns how many failovers have fired.
func (s *Sentinel) Failures() int64 { return s.failures.Load() }

// FailoverLatency returns the callback handoff time of the last failover.
func (s *Sentinel) FailoverLatency() time.Duration {
	return time.Duration(s.lastFailoverLatency.Load())
}
