package main

import (
	"fmt"
	"os"
	"runtime/debug"
	"sync"
)

// engineMu serialises every engine start/stop path. These are cgo exports:
// the Python host can call Start* and Stop* from different threads (ctypes
// releases the GIL), and unsynchronised access to the engine globals made
// double-start leak instances and concurrent start/stop race on Close.
var engineMu sync.Mutex

// logPanic records a recovered panic.
//
// A panic that escapes this process is fatal: it kills the whole host — the
// Python CLI that loaded blackout_core.dll via ctypes — so every Python
// cleanup handler (finally, atexit, the console close handler) is skipped and
// whatever system state we were holding (notably the system proxy) is left
// stranded. Recovering turns that into a logged, recoverable error.
func logPanic(where string, recovered any) {
	fmt.Fprintf(
		os.Stderr,
		"blackout-core: recovered panic in %s: %v\n%s\n",
		where, recovered, debug.Stack(),
	)
}

// safeGo runs fn in a goroutine that recovers from any panic.
//
// A panic inside a goroutine is fatal even when the goroutine was started from
// a cgo-exported function, so every goroutine must recover for itself.
func safeGo(where string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logPanic(where, r)
			}
		}()
		fn()
	}()
}

// safeCall runs fn and converts a panic into an error.
//
// Used by the cgo-exported entry points so they can return a failure code
// instead of terminating the host process.
func safeCall(where string, fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			logPanic(where, r)
			err = fmt.Errorf("recovered panic in %s: %v", where, r)
		}
	}()
	return fn()
}
