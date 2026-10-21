package main

// HTTP CONNECT proxy over the AmneziaWG netstack.
//
// Why this exists: Windows (WinINET) and therefore Chrome/Edge cannot use a
// SOCKS proxy from the system proxy settings — they need an HTTP proxy. The
// SOCKS5 listener stays available for tools that speak SOCKS directly, while
// this listener is what the daemon advertises as the system proxy.
//
// It serves two request forms:
//   - CONNECT host:port          → tunneled TCP (HTTPS, WSS, anything)
//   - absolute-URI GET/POST      → plain HTTP forwarded through the tunnel
//
// The second form matters: WinINET sends plain "GET http://site/ HTTP/1.1"
// for http:// URLs through the system proxy, and any health prober (the
// Blackout daemon included) dials plain-HTTP. A CONNECT-only listener
// answers 405 to those and makes a healthy tunnel look dead.

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

// ServeHTTPProxy runs an HTTP proxy on ln until it is closed.
func ServeHTTPProxy(ctx context.Context, ln net.Listener, tnet *netstack.Net, logf func(string, ...any)) {
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleConnect(ctx, w, r, tnet, logf)
				return
			}
			// Plain HTTP: absolute-form request line (RFC 9112 §3.2.2).
			if r.URL.IsAbs() && r.URL.Host != "" {
				handlePlainHTTP(ctx, w, r, tnet, logf)
				return
			}
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
		}),
		ReadHeaderTimeout: 15 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	go func() { <-ctx.Done(); _ = srv.Close() }()
}

// handleConnect tunnels raw TCP for a CONNECT request.
func handleConnect(ctx context.Context, w http.ResponseWriter, r *http.Request, tnet *netstack.Net, logf func(string, ...any)) {
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

	ip, ok := _resolve(ctx, host, w, logf)
	if !ok {
		return
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
}

// handlePlainHTTP forwards an absolute-URI request through the tunnel.
func handlePlainHTTP(ctx context.Context, w http.ResponseWriter, r *http.Request, tnet *netstack.Net, logf func(string, ...any)) {
	host := r.URL.Hostname()
	portStr := r.URL.Port()
	if portStr == "" {
		if strings.EqualFold(r.URL.Scheme, "https") {
			portStr = "443"
		} else {
			portStr = "80"
		}
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		http.Error(w, "bad port", http.StatusBadRequest)
		return
	}

	ip, ok := _resolve(ctx, host, w, logf)
	if !ok {
		return
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

	// Absolute-form → origin-form on the wire, hop-by-hop headers stripped.
	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.URL.Scheme = ""
	out.URL.Host = ""
	out.Header.Del("Proxy-Connection")
	out.Header.Del("Connection")
	out.Header.Del("Keep-Alive")
	out.Header.Del("Proxy-Authenticate")
	out.Header.Del("Proxy-Authorization")
	out.Header.Del("Te")
	out.Header.Del("Trailer")
	out.Header.Del("Transfer-Encoding")
	out.Header.Del("Upgrade")

	if werr := out.Write(rc); werr != nil {
		if logf != nil {
			logf("http: write to %s failed: %v", host, werr)
		}
		http.Error(w, "write failed", http.StatusBadGateway)
		return
	}

	resp, rerr := http.ReadResponse(bufioReader(rc), out)
	if rerr != nil {
		if logf != nil {
			logf("http: read from %s failed: %v", host, rerr)
		}
		http.Error(w, "read failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// _resolve resolves host to an IP, writing an HTTP error and returning
// ok=false when that fails.
func _resolve(ctx context.Context, host string, w http.ResponseWriter, logf func(string, ...any)) (net.IP, bool) {
	ip := net.ParseIP(host)
	if ip != nil {
		return ip, true
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	ips, lerr := net.DefaultResolver.LookupIPAddr(lookupCtx, host)
	cancel()
	if lerr != nil || len(ips) == 0 {
		if logf != nil {
			logf("http: resolve %s failed: %v", host, lerr)
		}
		http.Error(w, "resolve failed", http.StatusBadGateway)
		return nil, false
	}
	return ips[0].IP, true
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		switch k {
		case "Connection", "Keep-Alive", "Proxy-Connection", "Transfer-Encoding", "Upgrade", "Trailer":
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func bufioReader(r io.Reader) *bufio.Reader {
	br, ok := r.(*bufio.Reader)
	if ok {
		return br
	}
	return bufio.NewReader(r)
}
