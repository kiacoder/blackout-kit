package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
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

	fmt.Printf("SNI Spoofer running at %s (forwarding to %s:%d, fake SNI: %s)\n",
		addr, config.ConnectIP, config.ConnectPort, config.FakeSNI)

	go func() {
		for {
			clientConn, err := sniListener.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					break
				}
				fmt.Printf("Accept connection failed: %v\n", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			go handleClient(clientConn, config.ConnectIP, config.ConnectPort)
		}
	}()
	return nil
}

func stopSNIInternal() {
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

func handleClient(client net.Conn, targetIP string, targetPort int) {
	defer client.Close()

	// Connect to target with Dialer keepalive
	targetAddr := fmt.Sprintf("%s:%d", targetIP, targetPort)
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
	go func() {
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
				// Check if this is a TLS ClientHello
				// 0x16 = Handshake, 0x03 = TLS version (usually 0x03 0x01, 0x03 0x02, 0x03 0x03)
				if !hasWritten {
					hasWritten = true
					if n > 5 && data[0] == 0x16 && data[1] == 0x03 {
					
						// Fragment the ClientHello at the TLS record layer to bypass DPI.
						// We write the first 5 bytes (TLS record header), sleep to force a packet push,
						// then write the rest.
						_, err1 := server.Write(data[:5])
						if err1 != nil {
							return
						}
						
						// Sleep for 15ms to ensure the TCP packet is pushed out separately.
						// This overwhelms typical DPI reassembly buffers that inspect packet boundaries.
						time.Sleep(15 * time.Millisecond)
						
						_, err2 := server.Write(data[5:])
						if err2 != nil {
							return
						}
					} else {
						_, errW := server.Write(data)
						if errW != nil {
							return
						}
					}
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
	}()

	// Forward server -> client directly
	go func() {
		defer func() {
			client.Close()
			server.Close()
			done <- struct{}{}
		}()
		io.Copy(client, server)
	}()

	// Wait until both directions finish
	<-done
	<-done
}
