package main

import "C"

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"

	"github.com/bepass-org/warp-plus/app"
	"github.com/bepass-org/warp-plus/psiphon"
	"github.com/bepass-org/warp-plus/warp"
)

var (
	warpCtx    context.Context
	warpCancel context.CancelFunc
)

//export StartWarpC
func StartWarpC(socksPort C.int, cCountry *C.char) C.int {
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

	go func() {
		_ = app.RunWarp(warpCtx, l, opts)
	}()

	return 0
}

//export StopWarpC
func StopWarpC() {
	if warpCancel != nil {
		warpCancel()
		warpCancel = nil
	}
}

var (
	psiCtx    context.Context
	psiCancel context.CancelFunc
)

//export StartPsiphonC
func StartPsiphonC(socksPort C.int, httpPort C.int, cCountry *C.char) C.int {
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

	go func() {
		_ = app.RunWarp(psiCtx, l, opts)
	}()

	return 0
}

//export StopPsiphonC
func StopPsiphonC() {
	if psiCancel != nil {
		psiCancel()
		psiCancel = nil
	}
}

func main() {}
