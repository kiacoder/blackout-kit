package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"blackout-engine-v2/pkg/ipc"
)

// TestDaemonEndToEnd builds the daemon, launches it as a separate process and
// drives it through the real control channel.
//
// This is the test that actually justifies the v2 execution model. The unit
// tests exercise the server in-process; only this one proves the daemon is a
// genuinely independent supervised process reachable over the platform
// endpoint, which is what replaces the v1 in-process DLL.
func TestDaemonEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping daemon integration test in short mode")
	}

	binary := buildDaemon(t)

	var endpoint string
	if ipc.IsPipePlatform() {
		endpoint = fmt.Sprintf(`\\.\pipe\blackout_ipc_it_%d_%d`, os.Getpid(), rand.Int31())
	} else {
		endpoint = filepath.Join(t.TempDir(), "blackout-it.sock")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := exec.CommandContext(ctx, binary,
		"-endpoint", endpoint,
		"-no-sentinel",
		"-telemetry-interval", "100ms",
	)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start daemon: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	client, err := ipc.Connect(ctx, endpoint, "integration-test")
	if err != nil {
		t.Fatalf("connect to daemon: %v", err)
	}
	defer client.Close()

	if client.ServerVersion != ipc.APIVersion {
		t.Fatalf("daemon version = %q, want %q", client.ServerVersion, ipc.APIVersion)
	}

	callCtx, callCancel := context.WithTimeout(ctx, 10*time.Second)
	defer callCancel()

	started, err := client.Start(callCtx, ipc.StartParams{Engine: "sni"})
	if err != nil {
		t.Fatalf("start engine: %v", err)
	}
	if started.Status != string(ipc.StatusRunning) {
		t.Fatalf("status = %q, want %q", started.Status, ipc.StatusRunning)
	}

	tuned, err := client.Tune(callCtx, ipc.TuneParams{
		MinChunk: 4,
		MaxChunk: 12,
		MinDelay: 100,
		MaxDelay: 500,
		FakeSNI:  "www.microsoft.com",
	})
	if err != nil {
		t.Fatalf("tune: %v", err)
	}
	if tuned.MinChunk != 4 || tuned.MaxChunk != 12 {
		t.Fatalf("tune = %+v, want chunks 4/12", tuned)
	}
	if tuned.FakeSNI != "www.microsoft.com" {
		t.Fatalf("fake_sni = %q", tuned.FakeSNI)
	}

	if err := client.Subscribe(callCtx); err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	// The daemon publishes on its own ticker; this proves telemetry crosses
	// the process boundary, which the v1 DLL model could never do.
	telemetryCtx, telemetryCancel := context.WithTimeout(ctx, 10*time.Second)
	defer telemetryCancel()
	sample, err := client.NextTelemetry(telemetryCtx)
	if err != nil {
		t.Fatalf("no telemetry from daemon: %v", err)
	}
	if sample.Engine != "sni" {
		t.Fatalf("telemetry engine = %q, want sni", sample.Engine)
	}
	if sample.At <= 0 {
		t.Fatalf("telemetry timestamp missing: %+v", sample)
	}

	if err := client.Shutdown(callCtx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	// The daemon should exit on its own after the shutdown command.
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	select {
	case err := <-exited:
		if err != nil && !errors.Is(err, context.Canceled) {
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) {
				t.Fatalf("daemon exited with: %v", err)
			}
		}
	case <-time.After(10 * time.Second):
		t.Fatal("daemon did not exit after shutdown")
	}
}

// buildDaemon compiles the daemon into a temp directory for this test.
func buildDaemon(t *testing.T) string {
	t.Helper()

	out := filepath.Join(t.TempDir(), "blackout-core")
	if ipc.IsPipePlatform() {
		out += ".exe"
	}

	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build daemon: %v", err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("daemon binary missing: %v", err)
	}
	return out
}

func TestDaemonVersionFlag(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	binary := buildDaemon(t)

	out, err := exec.Command(binary, "-version").CombinedOutput()
	if err != nil {
		t.Fatalf("run -version: %v (output %q)", err, out)
	}
	if got := string(out); got != ipc.APIVersion+"\n" {
		t.Fatalf("-version printed %q, want %q", got, ipc.APIVersion+"\n")
	}
}
