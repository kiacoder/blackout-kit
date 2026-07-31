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
				if !hasWritten && n > 20 {
					// DPI Bypass: Fragment the ENTIRE ClientHello into 10-byte chunks.
					// We rely on Go's default TCP_NODELAY (Nagle's disabled) to push them
					// as separate TCP segments instantly, bypassing DPI without artificial lag!
					chunkSize := 10
					for i := 0; i < len(data); i += chunkSize {
						end := i + chunkSize
						if end > len(data) {
							end = len(data)
						}
						_, errW := server.Write(data[i:end])
						if errW != nil {
							return
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
