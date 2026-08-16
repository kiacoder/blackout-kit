//go:build !windows

package main

import "fmt"

func startGDPIInternal() error {
	return fmt.Errorf("native GDPI requires Windows and WinDivert")
}

func stopGDPIInternal() {}

func isGDPIRunningInternal() bool {
	return false
}
