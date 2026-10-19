package main

// awg-go: userspace AmneziaWG tunnel exposing a local SOCKS5 proxy.
//
//   awg-go --config tunnel.conf --socks 127.0.0.1:10808
//   awg-go --config tunnel.conf --check-config     (parse + print, no tunnel)
//
// No TUN device and no admin rights are needed: traffic is dialed through
// wireguard-go's in-process netstack (tun/netstack) and exposed over SOCKS5.

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "awg-go: "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	var (
		confPath  = flag.String("config", "", "path to AmneziaWG .conf file")
		socksAddr = flag.String("socks", "127.0.0.1:10808", "SOCKS5 listen address")
		httpAddr  = flag.String("http", "", "HTTP CONNECT listen address (e.g. 127.0.0.1:11081; Windows system proxy)")
		mtu       = flag.Int("mtu", 0, "MTU override (0 = conf value or default)")
		verbose   = flag.Bool("verbose", false, "verbose device logging")
		checkOnly = flag.Bool("check-config", false, "parse config and print a summary, then exit")
		readyFile = flag.String("ready-file", "", "write the listening address here once ready")
	)
	flag.Parse()

	if *confPath == "" {
		fatal("--config is required")
	}

	conf, err := LoadConfig(*confPath)
	if err != nil {
		fatal("config: %v", err)
	}
	if *checkOnly {
		fmt.Print(conf.Summary())
		return
	}
	if *mtu > 0 {
		conf.MTU = *mtu
	}
	if conf.MTU <= 0 {
		conf.MTU = device.DefaultMTU
	}

	localAddrs, err := conf.LocalAddrs()
	if err != nil {
		fatal("addresses: %v", err)
	}
	tunDev, tnet, err := netstack.CreateNetTUN(localAddrs, conf.DNSAddrs(), conf.MTU)
	if err != nil {
		fatal("netstack: %v", err)
	}

	level := device.LogLevelError
	if *verbose {
		level = device.LogLevelVerbose
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(level, "awg: "))
	defer dev.Close()

	if err := dev.IpcSet(conf.UAPI()); err != nil {
		fatal("uapi: %v", err)
	}
	if err := dev.Up(); err != nil {
		fatal("device up: %v", err)
	}

	ln, err := net.Listen("tcp", *socksAddr)
	if err != nil {
		fatal("socks listen: %v", err)
	}

	logger := log.New(os.Stdout, "awg-go: ", log.LstdFlags)
	srv := &Socks5Server{Net: tnet, Logf: logger.Printf}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx, ln)

	// Optional HTTP CONNECT listener: Windows/WinINET (and therefore Chrome)
	// cannot use a SOCKS system proxy, so the daemon advertises this one.
	httpListen := ""
	if *httpAddr != "" {
		httpLn, herr := net.Listen("tcp", *httpAddr)
		if herr != nil {
			fatal("http listen: %v", herr)
		}
		ServeHTTPProxy(ctx, httpLn, tnet, logger.Printf)
		httpListen = httpLn.Addr().String()
	}

	// Machine-readable readiness line for the Python engine's health check.
	fmt.Printf("READY socks=%s http=%s mtu=%d endpoint=%s\n",
		ln.Addr().String(), httpListen, conf.MTU, conf.Endpoint)
	if *readyFile != "" {
		_ = os.WriteFile(*readyFile, []byte(ln.Addr().String()+"\n"), 0o644)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	logger.Println("shutting down")
	_ = ln.Close()
	cancel()
	dev.Close()
	time.Sleep(100 * time.Millisecond) // let deferred cleanup settle
}
