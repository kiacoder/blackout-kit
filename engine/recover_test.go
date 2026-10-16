package main

import "testing"

// A panic that escapes a goroutine is fatal and kills the whole host process,
// so if safeGo did not recover, this test binary would die rather than fail.
func TestSafeGoRecoversPanic(t *testing.T) {
	done := make(chan struct{})
	safeGo("test.panic", func() {
		defer close(done)
		panic("boom")
	})
	<-done
}

func TestSafeCallConvertsPanicToError(t *testing.T) {
	err := safeCall("test.panic", func() error {
		panic("boom")
	})
	if err == nil {
		t.Fatal("expected safeCall to convert the panic into an error")
	}
}

func TestSafeCallPassesThroughSuccess(t *testing.T) {
	if err := safeCall("test.ok", func() error { return nil }); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSafeCallPassesThroughError(t *testing.T) {
	sentinel := errString("nope")
	if err := safeCall("test.err", func() error { return sentinel }); err != sentinel {
		t.Fatalf("expected the original error to pass through, got %v", err)
	}
}

type errString string

func (e errString) Error() string { return string(e) }
