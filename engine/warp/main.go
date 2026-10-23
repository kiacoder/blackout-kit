package main

import "C"

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"sync"

	"github.com/bepass-org/warp-plus/app"
	"github.com/bepass-org/warp-plus/warp"
)

var (
	warpCtx    context.Context
	warpCancel context.CancelFunc
	psiCtx     context.Context
	psiCancel  context.CancelFunc

	// The main core guards its exports with engineMu; this package is a
	// separate main package and had no guard at all, so two Start*C calls
	// raced on the globals and leaked the first context.
	warpMu sync.Mutex
)

// runGuarded starts fn in its own goroutine with a recover.
//
// A bare `go app.RunWarp(...)` meant a panic anywhere inside warp-plus took
// down the whole Python host process - the exact failure mode engine/recover.go
// exists to prevent in the main core.
func runGuarded(name string, fn func() error, l *slog.Logger) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				l.Error("panic in "+name, "panic", fmt.Sprint(r))
			}
		}()
		if err := fn(); err != nil {
			l.Error(name+" failed", "error", err)
		}
	}()
}

//export StartWarpC
func StartWarpC(socksPort C.int, cCountry *C.char) C.int {
	warpMu.Lock()
	defer warpMu.Unlock()
	if warpCancel != nil {
		return 0 // already running; starting twice would leak the first context
	}
	country := C.GoString(cCountry)

	bindAddrPort, err := netip.ParseAddrPort(fmt.Sprintf("127.0.0.1:%d", int(socksPort)))
	if err != nil {
		return 1
	}

	dnsAddr, err := netip.ParseAddr("1.1.1.1")
	if err != nil {
		return 1
	}

	endpoint, err := warp.RandomWarpEndpoint(true, true)
	if err != nil {
		return 1
	}

	opts := app.WarpOptions{
		Bind:     bindAddrPort,
		Endpoint: endpoint.String(),
		DnsAddr:  dnsAddr,
		CacheDir: "warp_plus_cache",
	}

	if country != "" && country != "none" {
		opts.Psiphon = &app.PsiphonOptions{Country: country}
	}

	warpCtx, warpCancel = context.WithCancel(context.Background())
	l := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	runGuarded("warp run", func() error { return app.RunWarp(warpCtx, l, opts) }, l)

	return 0
}

//export StopWarpC
func StopWarpC() {
	warpMu.Lock()
	defer warpMu.Unlock()
	if warpCancel != nil {
		warpCancel()
		warpCancel = nil
	}
}

//export StartPsiphonC
func StartPsiphonC(socksPort C.int, httpPort C.int, cCountry *C.char) C.int {
	warpMu.Lock()
	defer warpMu.Unlock()
	if psiCancel != nil {
		return 0 // already running
	}
	// warp-plus exposes one SOCKS listener; there is no HTTP inbound to bind
	// httpPort to. Say so rather than accepting the argument and leaving a
	// port that nothing listens on.
	if int(httpPort) > 0 {
		fmt.Printf("Psiphon: HTTP proxy port %d is not served (SOCKS only on %d)\n", int(httpPort), int(socksPort))
	}

	// We can run psiphon through the same app.RunWarp with Gool=False and Psiphon enabled,
	// but it would still establish a WARP tunnel over it.
	// If the user wants pure psiphon without warp, we might need to invoke Psiphon directly.
	// However, warp-plus provides an easy entrypoint for Psiphon tunnel. Let's use it for now.
	country := C.GoString(cCountry)
	
	bindAddrPort, err := netip.ParseAddrPort(fmt.Sprintf("127.0.0.1:%d", int(socksPort)))
	if err != nil {
		return 1
	}

	opts := app.WarpOptions{
		Bind:     bindAddrPort,
		Endpoint: "engage.cloudflareclient.com:2408", // Dummy, since it uses Psiphon
		CacheDir: "psiphon_cache",
	}

	if country != "" && country != "none" {
		opts.Psiphon = &app.PsiphonOptions{Country: country}
	} else {
		opts.Psiphon = &app.PsiphonOptions{Country: "DE"}
	}

	psiCtx, psiCancel = context.WithCancel(context.Background())
	l := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	runGuarded("psiphon run", func() error { return app.RunWarp(psiCtx, l, opts) }, l)

	return 0
}

//export StopPsiphonC
func StopPsiphonC() {
	warpMu.Lock()
	defer warpMu.Unlock()
	if psiCancel != nil {
		psiCancel()
		psiCancel = nil
	}
}

func main() {}
