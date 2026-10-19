package main

// Minimal SOCKS5 server (CONNECT only) that dials through the AmneziaWG
// netstack, so Blackout CLI can treat the tunnel like any other proxy engine
// without requiring a TUN device or admin rights.
//
// UDP ASSOCIATE is answered with "command not supported" — browsers fall back
// to TCP; QUIC will simply not use the tunnel.

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

type Socks5Server struct {
	Net  *netstack.Net
	Logf func(format string, args ...any)
}

func (s *Socks5Server) Serve(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed
		}
		go s.handle(ctx, conn)
	}
}

func (s *Socks5Server) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

func (s *Socks5Server) handle(ctx context.Context, c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(c)

	// --- greeting: VER, NMETHODS, METHODS ---
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil || hdr[0] != 0x05 {
		return
	}
	if _, err := io.ReadFull(br, make([]byte, int(hdr[1]))); err != nil {
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil { // no auth
		return
	}

	// --- request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT ---
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil || req[0] != 0x05 {
		return
	}
	if req[1] != 0x01 { // only CONNECT
		_, _ = c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var host string
	switch req[3] {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x03: // domain
		l := make([]byte, 1)
		if _, err := io.ReadFull(br, l); err != nil {
			return
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = string(b)
	default:
		_, _ = c.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(pb))

	// Resolve domains locally (the host resolver is the last hop before the
	// tunnel; IP literals skip this entirely).
	ip := net.ParseIP(host)
	if ip == nil {
		lookupCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		ips, err := net.DefaultResolver.LookupIPAddr(lookupCtx, host)
		cancel()
		if err != nil || len(ips) == 0 {
			s.logf("socks: resolve %s failed: %v", host, err)
			_, _ = c.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		ip = ips[0].IP
	}

	dialCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	rc, err := s.Net.DialContextTCP(dialCtx, &net.TCPAddr{IP: ip, Port: port})
	if err != nil {
		s.logf("socks: dial %s:%d failed: %v", ip, port, err)
		_, _ = c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer rc.Close()

	// success: BND.ADDR/PORT are zeroed
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(rc, br); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, rc); done <- struct{}{} }()
	<-done
}
