package ipc

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testEndpoint returns a private endpoint for one test so parallel tests and
// repeated runs never collide on the shared daemon address.
func testEndpoint(t *testing.T) string {
	t.Helper()
	if isPipePath(DefaultEndpoint()) {
		return fmt.Sprintf(`\\.\pipe\blackout_ipc_test_%d_%d`, os.Getpid(), rand.Int31())
	}
	return filepath.Join(t.TempDir(), "blackout-test.sock")
}

// startTestServer binds a server on a private endpoint and shuts it down when
// the test ends.
func startTestServer(t *testing.T, ctrl Controller) *Server {
	t.Helper()
	endpoint := testEndpoint(t)
	srv, err := NewServer(endpoint, ctrl)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		shutdownCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = srv.Shutdown(shutdownCtx)
	})
	return srv
}

// dialTest connects a client to a running test server.
func dialTest(t *testing.T, endpoint string) *Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Connect(ctx, endpoint, "test")
	if err != nil {
		t.Fatalf("Connect(%s): %v", endpoint, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}
