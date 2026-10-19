package main

// HTTP CONNECT proxy over the AmneziaWG netstack.
//
// Why this exists: Windows (WinINET) and therefore Chrome/Edge cannot use a
// SOCKS proxy from the system proxy settings — they need an HTTP proxy. The
// SOCKS5 listener stays available for tools that speak SOCKS directly, while
// this listener is what the daemon advertises as the system proxy.

import (
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

// ServeHTTPProxy runs an HTTP CONNECT proxy on ln until it is closed.
func ServeHTTPProxy(ctx context.Context, ln net.Listener, tnet *netstack.Net, logf func(string, ...any)) {
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodConnect {
				http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
				return
			}
			host, portStr, err := net.SplitHostPort(r.Host)
			if err != nil {
				http.Error(w, "bad authority", http.StatusBadRequest)
				return
			}
			port, err := strconv.Atoi(portStr)
			if err != nil || port <= 0 || port > 65535 {
				http.Error(w, "bad port", http.StatusBadRequest)
				return
			}

			ip := net.ParseIP(host)
			if ip == nil {
				lookupCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
				ips, lerr := net.DefaultResolver.LookupIPAddr(lookupCtx, host)
				cancel()
				if lerr != nil || len(ips) == 0 {
					if logf != nil {
						logf("http: resolve %s failed: %v", host, lerr)
					}
					http.Error(w, "resolve failed", http.StatusBadGateway)
					return
				}
				ip = ips[0].IP
			}

			dialCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
			rc, derr := tnet.DialContextTCP(dialCtx, &net.TCPAddr{IP: ip, Port: port})
			cancel()
			if derr != nil {
				if logf != nil {
					logf("http: dial %s:%d failed: %v", ip, port, derr)
				}
				http.Error(w, "dial failed", http.StatusBadGateway)
				return
			}
			defer rc.Close()

			hj, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "hijack unsupported", http.StatusInternalServerError)
				return
			}
			client, _, herr := hj.Hijack()
			if herr != nil {
				return
			}
			defer client.Close()
			if _, werr := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); werr != nil {
				return
			}

			done := make(chan struct{}, 2)
			go func() { _, _ = io.Copy(rc, client); done <- struct{}{} }()
			go func() { _, _ = io.Copy(client, rc); done <- struct{}{} }()
			<-done
		}),
		ReadHeaderTimeout: 15 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	go func() { <-ctx.Done(); _ = srv.Close() }()
}
