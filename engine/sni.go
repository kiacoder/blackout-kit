package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"
)

type SNIConfig struct {
	ListenHost  string `json:"LISTEN_HOST"`
	ListenPort  int    `json:"LISTEN_PORT"`
	ConnectIP   string `json:"CONNECT_IP"`
	ConnectPort int    `json:"CONNECT_PORT"`
	FakeSNI     string `json:"FAKE_SNI"`
}

var sniListener net.Listener

func startSNIInternal(configPath string) error {
	engineMu.Lock()
	defer engineMu.Unlock()
	if sniListener != nil {
		return fmt.Errorf("SNI spoofer is already running")
	}
	configFile, err := os.Open(configPath)
	if err != nil {
		return fmt.Errorf("failed to open SNI config: %w", err)
	}
	defer configFile.Close()

	var config SNIConfig
	if err := json.NewDecoder(configFile).Decode(&config); err != nil {
		return fmt.Errorf("failed to parse SNI config JSON: %w", err)
	}

	addr := fmt.Sprintf("%s:%d", config.ListenHost, config.ListenPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to start SNI listener: %w", err)
	}
	sniListener = listener

	// The loop must Accept on the CAPTURED listener, not the global: Stop
	// nils the global, and an Accept on a nil interface is a panic that
	// would kill this accept loop (recovered, but the listener dies with it).
	l := listener
	safeGo("sni.accept", func() {
		for {
			clientConn, err := l.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					break
				}
				fmt.Printf("Accept connection failed: %v\n", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			// Capture per-connection: a panic here must not kill the listener.
			conn := clientConn
			safeGo("sni.handleClient", func() {
				handleClient(conn, config.ConnectIP, config.ConnectPort, config.FakeSNI)
			})
		}
	})
	return nil
}

func stopSNIInternal() {
	engineMu.Lock()
	defer engineMu.Unlock()
	if sniListener != nil {
		sniListener.Close()
		sniListener = nil
		fmt.Println("SNI spoofer stopped")
	}
}

func RunSNI(configPath string) error {
	if err := startSNIInternal(configPath); err != nil {
		return err
	}
	return nil
}

func handleClient(client net.Conn, targetIP string, targetPort int, fakeSNI string) {
	defer client.Close()
	// A panic in a connection handler must never take down the host process.
	defer func() {
		if r := recover(); r != nil {
			logPanic("sni.handleClient", r)
		}
	}()

	// Connect to target with Dialer keepalive
	targetAddr := net.JoinHostPort(targetIP, strconv.Itoa(targetPort))
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	server, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		fmt.Printf("Connect to target %s failed: %v\n", targetAddr, err)
		return
	}
	defer server.Close()

	// Disable Nagle's algorithm and enable KeepAlive to make connections smarter and more reliable
	if tcpClient, ok := client.(*net.TCPConn); ok {
		tcpClient.SetNoDelay(true)
		tcpClient.SetKeepAlive(true)
		tcpClient.SetKeepAlivePeriod(30 * time.Second)
	}
	if tcpServer, ok := server.(*net.TCPConn); ok {
		tcpServer.SetNoDelay(true)
		tcpServer.SetKeepAlive(true)
		tcpServer.SetKeepAlivePeriod(30 * time.Second)
	}

	// Channel to signal completion of transfer
	done := make(chan struct{}, 2)

	// Forward client -> server with TLS ClientHello fragmentation
	safeGo("sni.relayClientToServer", func() {
		defer func() {
			server.Close()
			client.Close()
			done <- struct{}{}
		}()
		
		buf := make([]byte, 32*1024)
		hasWritten := false
		for {
			n, err := client.Read(buf)
			if n > 0 {
				data := buf[:n]
				if !hasWritten && n > 20 {
					// The first write is the TLS ClientHello. Two things
					// happen to it before it leaves the machine:
					//
					//  1. SNI rewriting, when FAKE_SNI is configured. This is
					//     the actual evasion: a DPI box keying on the SNI of
					//     an outbound handshake sees the innocuous name. The
					//     config value was parsed and then ignored, so the
					//     feature was a no-op until now.
					//  2. Fragmentation, into chunks small enough that a DPI
					//     box reassembling only the first N bytes never sees
					//     the hostname at all.
					payload := data
					if fakeSNI != "" {
						rewritten, errR := rewriteClientHelloSNI(data, fakeSNI)
						switch {
						case errR == nil:
							payload = rewritten
						case errors.Is(errR, errSNINoExtension):
							// Nothing to rewrite; forward untouched.
						default:
							// A truncated read is not fatal: send what we have
							// rather than dropping a connection that may be
							// perfectly fine.
							fmt.Printf("SNI rewrite skipped: %v\n", errR)
						}
					}

					// DPI Bypass: fragment the ENTIRE ClientHello into
					// 10-byte chunks. Without a pause the kernel coalesces
					// the writes straight back into one segment and the
					// fragmentation is invisible on the wire, so each chunk is
					// flushed before the next is handed over.
					chunkSize := 10
					for i := 0; i < len(payload); i += chunkSize {
						end := i + chunkSize
						if end > len(payload) {
							end = len(payload)
						}
						_, errW := server.Write(payload[i:end])
						if errW != nil {
							return
						}
						if end < len(payload) {
							time.Sleep(200 * time.Microsecond)
						}
					}
					hasWritten = true
				} else {
					_, errW := server.Write(data)
					if errW != nil {
						return
					}
				}
			}
			if err != nil {
				return
			}
		}
	})

	// Forward server -> client directly
	safeGo("sni.relayServerToClient", func() {
		defer func() {
			client.Close()
			server.Close()
			done <- struct{}{}
		}()
		io.Copy(client, server)
	})

	// Wait until both directions finish
	<-done
	<-done
}
