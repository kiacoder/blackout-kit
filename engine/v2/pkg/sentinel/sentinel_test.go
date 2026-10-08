package sentinel

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fastConfig returns a config with a short interval so tests do not wait on
// production timings.
func fastConfig() Config {
	c := DefaultConfig()
	c.Interval = 5 * time.Millisecond
	c.Timeout = 200 * time.Millisecond
	c.Targets = []string{"test-a:443", "test-b:443"}
	return c
}

// constProber returns a prober with a fixed outcome. No network is touched.
func constProber(rtt time.Duration, err error) Prober {
	return func(ctx context.Context, target string) (time.Duration, error) {
		if err != nil {
			return 0, err
		}
		return rtt, nil
	}
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("condition not met within %v", timeout)
}

func TestConfigValidate(t *testing.T) {
	if err := DefaultConfig().Validate(); err != nil {
		t.Fatalf("DefaultConfig invalid: %v", err)
	}
	cases := []struct {
		name string
		mut  func(*Config)
	}{
		{"zero interval", func(c *Config) { c.Interval = 0 }},
		{"zero timeout", func(c *Config) { c.Timeout = 0 }},
		{"no targets", func(c *Config) { c.Targets = nil }},
		{"failure limit below 1", func(c *Config) { c.FailureLimit = 0 }},
		{"degrade limit below 1", func(c *Config) { c.DegradeLimit = 0 }},
		{"alpha zero", func(c *Config) { c.Alpha = 0 }},
		{"alpha above one", func(c *Config) { c.Alpha = 1.5 }},
	}
	for _, tc := range cases {
		c := DefaultConfig()
		tc.mut(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: expected an error", tc.name)
		}
	}
}

func TestNewRequiresProber(t *testing.T) {
	if _, err := New(DefaultConfig(), nil); err == nil {
		t.Fatal("New should reject a nil prober")
	}
	if _, err := New(Config{}, constProber(time.Millisecond, nil)); err == nil {
		t.Fatal("New should reject an invalid config")
	}
}

// TestFailoverOnProbeFailure is the core watchdog assertion: a dead path must
// be detected and handed to the failover callback well inside the 50ms budget.
func TestFailoverOnProbeFailure(t *testing.T) {
	cfg := fastConfig()
	cfg.FailureLimit = 2

	s, err := New(cfg, constProber(0, errors.New("connection refused")))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var (
		reason string
		fired  = make(chan struct{})
		once   syncOnce
	)
	s.OnFailover = func(r string, sample Sample) {
		if once.Do() {
			reason = r
			close(fired)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	select {
	case <-fired:
	case <-time.After(3 * time.Second):
		t.Fatal("failover never fired")
	}

	if reason != ReasonProbeFailure {
		t.Fatalf("reason = %q, want %q", reason, ReasonProbeFailure)
	}
	if lat := s.FailoverLatency(); lat > 50*time.Millisecond {
		t.Fatalf("failover handoff took %v, budget is 50ms", lat)
	}
	if s.State() != StateFailed {
		t.Fatalf("state = %q, want %q", s.State(), StateFailed)
	}
}

// TestFailoverOnDegradedRTT covers the case v1 could not see at all: the port
// is open and the process is alive, but the path is unusably slow.
func TestFailoverOnDegradedRTT(t *testing.T) {
	cfg := fastConfig()
	cfg.Alpha = 1 // EWMA tracks the latest sample exactly
	cfg.DegradeThresholdMS = 100
	cfg.DegradeLimit = 2

	s, err := New(cfg, constProber(900*time.Millisecond, nil))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var (
		reason string
		fired  = make(chan struct{})
		once   syncOnce
	)
	s.OnFailover = func(r string, _ Sample) {
		if once.Do() {
			reason = r
			close(fired)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	select {
	case <-fired:
	case <-time.After(3 * time.Second):
		t.Fatal("failover never fired on a degraded path")
	}
	if reason != ReasonRTTDegraded {
		t.Fatalf("reason = %q, want %q", reason, ReasonRTTDegraded)
	}
	if lat := s.FailoverLatency(); lat > 50*time.Millisecond {
		t.Fatalf("failover handoff took %v, budget is 50ms", lat)
	}
}

func TestHealthyPathDoesNotFailover(t *testing.T) {
	cfg := fastConfig()
	cfg.DegradeThresholdMS = 500
	cfg.FailureLimit = 1
	cfg.DegradeLimit = 1

	s, err := New(cfg, constProber(20*time.Millisecond, nil))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.OnFailover = func(_ string, _ Sample) {
		t.Error("failover fired on a healthy path")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	waitFor(t, 2*time.Second, func() bool { return s.State() == StateHealthy })

	if got := s.EWMA(); got <= 0 {
		t.Fatalf("EWMA = %v, want a positive measurement", got)
	}
	if s.Failures() != 0 {
		t.Fatalf("failures = %d, want 0", s.Failures())
	}
}

func TestEWMAFollowsSamples(t *testing.T) {
	cfg := fastConfig()
	cfg.Alpha = 1
	cfg.DegradeThresholdMS = 100000 // keep it healthy for the whole test

	s, err := New(cfg, constProber(50*time.Millisecond, nil))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	waitFor(t, 2*time.Second, func() bool { return s.EWMA() > 0 })

	got := s.EWMA()
	if got < 49 || got > 51 {
		t.Fatalf("EWMA = %.3f, want ~50ms", got)
	}
}

// TestBestTargetWins checks that one reachable target among several keeps the
// verdict healthy — the watchdog should reflect the path, not one unlucky probe.
func TestBestTargetWins(t *testing.T) {
	cfg := fastConfig()
	cfg.DegradeThresholdMS = 500
	cfg.Alpha = 1

	s, err := New(cfg, func(ctx context.Context, target string) (time.Duration, error) {
		if target == cfg.Targets[0] {
			return 0, errors.New("first target down")
		}
		return 30 * time.Millisecond, nil
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	waitFor(t, 2*time.Second, func() bool { return s.State() == StateHealthy })

	sample := s.LastSample()
	if sample.Target != cfg.Targets[1] {
		t.Fatalf("best target = %q, want %q", sample.Target, cfg.Targets[1])
	}
	if !sample.OK {
		t.Fatal("best sample should be OK")
	}
}

// syncOnce is a minimal once-flag so a test handler can close its channel
// exactly once even if the watchdog fires again.
type syncOnce struct {
	done bool
}

func (o *syncOnce) Do() bool {
	if o.done {
		return false
	}
	o.done = true
	return true
}
