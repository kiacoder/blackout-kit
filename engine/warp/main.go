package main

import "C"

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"

	"github.com/bepass-org/warp-plus/app"
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



func main() {}
