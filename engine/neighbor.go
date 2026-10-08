package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

var (
	neighborCtx    context.Context
	neighborCancel context.CancelFunc
	neighborWg     sync.WaitGroup
)

func startNeighborInternal(listenPort int, targetPort int, bindLan bool) error {
	if neighborCancel != nil {
		return fmt.Errorf("neighbor is already running")
	}

	neighborCtx, neighborCancel = context.WithCancel(context.Background())

	// 1. TCP Forwarder (Reverse Proxy for SOCKS5/HTTP)
	neighborWg.Add(1)
	go func() {
		defer neighborWg.Done()
		// Bind to loopback by default so the share proxy is only reachable
		// from this machine. Only expose it on all interfaces when the user
		// has explicitly opted in via the neighbor_bind_lan setting.
		bindHost := "127.0.0.1"
		if bindLan {
			bindHost = "0.0.0.0"
		}
		listenAddr := fmt.Sprintf("%s:%d", bindHost, listenPort)
		targetAddr := fmt.Sprintf("127.0.0.1:%d", targetPort)

		l, err := net.Listen("tcp", listenAddr)
		if err != nil {
			fmt.Println("Neighbor proxy failed to listen:", err)
			return
		}
		defer l.Close()

		// Close listener on context cancel
		go func() {
			<-neighborCtx.Done()
			l.Close()
		}()

		for {
			client, err := l.Accept()
			if err != nil {
				if neighborCtx.Err() != nil {
					break // expected shutdown
				}
				continue
			}

			go func(c net.Conn) {
				defer c.Close()
				server, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
				if err != nil {
					return
				}
				defer server.Close()

				go io.Copy(server, c)
				io.Copy(c, server)
			}(client)
		}
	}()

	// 2. UDP Multicast Beacon
	neighborWg.Add(1)
	go func() {
		defer neighborWg.Done()
		addr, err := net.ResolveUDPAddr("udp", "239.255.42.99:51820")
		if err != nil {
			fmt.Println("Failed to resolve UDP multicast address:", err)
			return
		}
		c, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			fmt.Println("Failed to dial UDP multicast:", err)
			return
		}
		defer c.Close()

		payload := []byte(fmt.Sprintf("BLACKOUTKIT:v1:%d", listenPort))

		// Send one beacon immediately
		c.Write(payload)

		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				c.Write(payload)
			case <-neighborCtx.Done():
				return
			}
		}
	}()

	return nil
}

func stopNeighborInternal() {
	if neighborCancel != nil {
		neighborCancel()
		neighborWg.Wait()
		neighborCancel = nil
	}
}
