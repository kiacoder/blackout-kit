//go:build !windows

package main

import "testing"

func TestGDPINonWindowsIsUnavailable(t *testing.T) {
	if err := startGDPIInternal(); err == nil {
		t.Fatal("expected native GDPI to reject non-Windows platforms")
	}
	if isGDPIRunningInternal() {
		t.Fatal("GDPI must not report as running on non-Windows platforms")
	}
}
