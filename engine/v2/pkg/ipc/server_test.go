package ipc

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestServerHandshake(t *testing.T) {
	srv := startTestServer(t, NewMemController())
	c := dialTest(t, srv.Endpoint())

	if c.ServerVersion != APIVersion {
		t.Fatalf("server version = %q, want %q", c.ServerVersion, APIVersion)
	}
	found := false
	for _, m := range c.Methods {
		if m == MethodTune {
			found = true
		}
	}
	if !found {
		t.Fatalf("method table missing %q: %v", MethodTune, c.Methods)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestServerStartStopStatus(t *testing.T) {
	ctrl := NewMemController()
	srv := startTestServer(t, ctrl)
	c := dialTest(t, srv.Endpoint())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := c.Start(ctx, StartParams{Engine: "sni"})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if res.Engine != "sni" || res.Status != string(StatusRunning) {
		t.Fatalf("Start result = %+v", res)
	}

	st, err := c.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Status != StatusRunning || st.Engine != "sni" {
		t.Fatalf("Status = %+v, want running/sni", st)
	}

	if _, err := c.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	st, err = c.Status(ctx)
	if err != nil {
		t.Fatalf("Status after stop: %v", err)
	}
	if st.Status != StatusStopped {
		t.Fatalf("Status after stop = %q, want %q", st.Status, StatusStopped)
	}
}

func TestServerStartRequiresEngine(t *testing.T) {
	srv := startTestServer(t, NewMemController())
	c := dialTest(t, srv.Endpoint())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := c.Start(ctx, StartParams{})
	var protoErr *Error
	if !errors.As(err, &protoErr) {
		t.Fatalf("err = %v, want *Error", err)
	}
	if protoErr.Code != CodeBadRequest {
		t.Fatalf("code = %q, want %q", protoErr.Code, CodeBadRequest)
	}
}

func TestServerTune(t *testing.T) {
	srv := startTestServer(t, NewMemController())
	c := dialTest(t, srv.Endpoint())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	off := false
	out, err := c.Tune(ctx, TuneParams{MinChunk: 4, MaxChunk: 16, MinDelay: 100, MaxDelay: 500, Fragments: &off})
	if err != nil {
		t.Fatalf("Tune: %v", err)
	}
	if out.MinChunk != 4 || out.MaxChunk != 16 {
		t.Fatalf("chunks = %d/%d, want 4/16", out.MinChunk, out.MaxChunk)
	}
	if out.Fragments {
		t.Fatal("Fragments should be false after tune")
	}
}

func TestServerUnknownMethod(t *testing.T) {
	srv := startTestServer(t, NewMemController())
	c := dialTest(t, srv.Endpoint())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := c.Call(ctx, "teleport", nil, nil)
	var protoErr *Error
	if !errors.As(err, &protoErr) || protoErr.Code != CodeUnknownMethod {
		t.Fatalf("err = %v, want %s", err, CodeUnknownMethod)
	}
}

// TestDispatchRejectsIncompatibleVersion exercises the version gate directly.
// A v1-era client speaking a different major must be refused before any engine
// state is touched — v1 had no version check at all and failed later with an
// opaque AttributeError.
func TestDispatchRejectsIncompatibleVersion(t *testing.T) {
	srv, err := NewServer(testEndpoint(t), NewMemController())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	sess := &session{}

	resp := srv.dispatch(context.Background(), sess, &Envelope{
		Version: "1.0.0",
		Kind:    KindRequest,
		ID:      "1",
		Method:  MethodStart,
	})
	if resp == nil || resp.Error == nil {
		t.Fatal("expected an error response")
	}
	if resp.Error.Code != CodeUnsupportedVersion {
		t.Fatalf("code = %q, want %q", resp.Error.Code, CodeUnsupportedVersion)
	}
}

func TestDispatchRejectsNonRequest(t *testing.T) {
	srv, err := NewServer(testEndpoint(t), NewMemController())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	sess := &session{}
	resp := srv.dispatch(context.Background(), sess, &Envelope{
		Version: APIVersion,
		Kind:    KindEvent,
		ID:      "1",
	})
	if resp == nil || resp.Error == nil || resp.Error.Code != CodeBadRequest {
		t.Fatalf("resp = %+v, want CodeBadRequest", resp)
	}
}

func TestTelemetryBroadcast(t *testing.T) {
	srv := startTestServer(t, NewMemController())
	c := dialTest(t, srv.Endpoint())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := c.Subscribe(ctx); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	if srv.hub.Count() != 1 {
		t.Fatalf("subscriber count = %d, want 1", srv.hub.Count())
	}

	want := Telemetry{
		Engine:   "sni",
		Status:   StatusRunning,
		RTTMs:    42.5,
		BytesIn:  1024,
		BytesOut: 2048,
		At:       time.Now().UnixMilli(),
	}
	srv.Publish(want)

	got, err := c.NextTelemetry(ctx)
	if err != nil {
		t.Fatalf("NextTelemetry: %v", err)
	}
	if got.Engine != want.Engine || got.Status != want.Status ||
		got.BytesIn != want.BytesIn || got.BytesOut != want.BytesOut {
		t.Fatalf("telemetry = %+v, want %+v", got, want)
	}
	if got.RTTMs != want.RTTMs {
		t.Fatalf("rtt_ms = %v, want %v", got.RTTMs, want.RTTMs)
	}
}

func TestTelemetryStopsAfterUnsubscribe(t *testing.T) {
	srv := startTestServer(t, NewMemController())
	c := dialTest(t, srv.Endpoint())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := c.Subscribe(ctx); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	if err := c.Unsubscribe(ctx); err != nil {
		t.Fatalf("Unsubscribe: %v", err)
	}
	if srv.hub.Count() != 0 {
		t.Fatalf("subscriber count = %d, want 0", srv.hub.Count())
	}

	srv.Publish(Telemetry{Status: StatusRunning})

	short, stop := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer stop()
	if _, err := c.NextTelemetry(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want DeadlineExceeded (no event after unsubscribe)", err)
	}
}

func TestPublishWithNoSubscribersIsSafe(t *testing.T) {
	srv := startTestServer(t, NewMemController())
	// No panic, no block, no error path to assert: this is a regression guard
	// for the daemon's telemetry ticker running before any HUD connects.
	for i := 0; i < 10; i++ {
		srv.Publish(Telemetry{Status: StatusIdle})
	}
}

func TestConcurrentClients(t *testing.T) {
	srv := startTestServer(t, NewMemController())

	const clients = 8

	// Each client reports exactly once: either its live handle (proving it got
	// all the way through subscribe) or an error. Clients stay open until the
	// assertions run, because the hub count is only meaningful while the
	// sessions exist.
	subscribed := make(chan *Client, clients)
	failed := make(chan error, clients)

	for i := 0; i < clients; i++ {
		go func(n int) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			c, err := Connect(ctx, srv.Endpoint(), fmt.Sprintf("client-%d", n))
			if err != nil {
				failed <- err
				return
			}
			if _, err := c.Start(ctx, StartParams{Engine: fmt.Sprintf("engine-%d", n)}); err != nil {
				_ = c.Close()
				failed <- err
				return
			}
			if err := c.Subscribe(ctx); err != nil {
				_ = c.Close()
				failed <- err
				return
			}
			if _, err := c.Status(ctx); err != nil {
				_ = c.Close()
				failed <- err
				return
			}
			subscribed <- c
		}(i)
	}

	var live []*Client
	for i := 0; i < clients; i++ {
		select {
		case c := <-subscribed:
			live = append(live, c)
		case err := <-failed:
			t.Errorf("concurrent client: %v", err)
		case <-time.After(15 * time.Second):
			t.Fatal("timed out waiting for concurrent clients")
		}
	}
	defer func() {
		for _, c := range live {
			_ = c.Close()
		}
	}()

	if len(live) != clients {
		t.Fatalf("%d clients completed, want %d", len(live), clients)
	}
	if got := srv.hub.Count(); got != clients {
		t.Fatalf("subscriber count = %d, want %d", got, clients)
	}

	// Every subscriber must receive the same broadcast.
	srv.Publish(Telemetry{Status: StatusRunning, RTTMs: 1})
	for _, c := range live {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if _, err := c.NextTelemetry(ctx); err != nil {
			t.Errorf("client did not receive telemetry: %v", err)
		}
		cancel()
	}
}

func TestServerShutdownClosesSessions(t *testing.T) {
	srv := startTestServer(t, NewMemController())
	c := dialTest(t, srv.Endpoint())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	shutdownCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	if err := c.Ping(ctx); err == nil {
		t.Fatal("expected an error pinging a shut-down server")
	}
}

func TestValidateEndpoint(t *testing.T) {
	if err := ValidateEndpoint(""); err == nil {
		t.Fatal("empty endpoint should be rejected")
	}
	if err := ValidateEndpoint(testEndpoint(t)); err != nil {
		t.Fatalf("test endpoint rejected: %v", err)
	}
}
