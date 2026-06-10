package main

import "C"

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/armon/go-socks5"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var (
	wgDevice *device.Device
	wgCtx    context.Context
	wgCancel context.CancelFunc
)

func parseConfigToIPC(configPath string) (string, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var ipc strings.Builder
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch strings.ToLower(key) {
		case "privatekey":
			b, err := base64.StdEncoding.DecodeString(val)
			if err == nil {
				ipc.WriteString(fmt.Sprintf("private_key=%s\n", hex.EncodeToString(b)))
			}
		case "listenport":
			ipc.WriteString(fmt.Sprintf("listen_port=%s\n", val))
		case "publickey":
			b, err := base64.StdEncoding.DecodeString(val)
			if err == nil {
				ipc.WriteString(fmt.Sprintf("public_key=%s\n", hex.EncodeToString(b)))
			}
		case "endpoint":
			ipc.WriteString(fmt.Sprintf("endpoint=%s\n", val))
		case "allowedips":
			ips := strings.Split(val, ",")
			for _, ip := range ips {
				ipc.WriteString(fmt.Sprintf("allowed_ip=%s\n", strings.TrimSpace(ip)))
			}
		case "presharedkey":
			b, err := base64.StdEncoding.DecodeString(val)
			if err == nil {
				ipc.WriteString(fmt.Sprintf("preshared_key=%s\n", hex.EncodeToString(b)))
			}
		case "persistentkeepalive":
			ipc.WriteString(fmt.Sprintf("persistent_keepalive_interval=%s\n", val))
		}
	}
	return ipc.String(), nil
}

func startWireGuardInternal(configPath string, socksPort int) error {
	// Create userspace TUN device via netstack
	localIPs := []netip.Addr{netip.MustParseAddr("10.0.0.2")} 
	dnsIPs := []netip.Addr{netip.MustParseAddr("1.1.1.1")}

	tun, tnet, err := netstack.CreateNetTUN(localIPs, dnsIPs, 1420)
	if err != nil {
		return err
	}

	ipcString, err := parseConfigToIPC(configPath)
	if err != nil {
		return err
	}

	logger := device.NewLogger(device.LogLevelError, "wg")
	wgDevice = device.NewDevice(tun, conn.NewDefaultBind(), logger)

	err = wgDevice.IpcSet(ipcString)
	if err != nil {
		return fmt.Errorf("failed to apply wireguard IPC config: %w", err)
	}

	wgCtx, wgCancel = context.WithCancel(context.Background())
	err = wgDevice.Up()
	if err != nil {
		return err
	}

	conf := &socks5.Config{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return tnet.DialContext(ctx, network, addr)
		},
	}
	server, err := socks5.New(conf)
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort))
	if err != nil {
		return err
	}

	go func() {
		_ = server.Serve(listener)
	}()

	fmt.Printf("WireGuard started natively via userspace TUN. SOCKS5 on port %d\n", socksPort)
	
	return nil
}

//export StartWireGuardC
func StartWireGuardC(configPath *C.char, socksPort C.int) C.int {
	path := C.GoString(configPath)
	if err := startWireGuardInternal(path, int(socksPort)); err != nil {
		fmt.Printf("StartWireGuardC error: %v\n", err)
		return 1
	}
	return 0
}

//export StopWireGuardC
func StopWireGuardC() {
	if wgCancel != nil {
		wgCancel()
		wgCancel = nil
	}
	if wgDevice != nil {
		wgDevice.Close()
		wgDevice = nil
		fmt.Println("WireGuard stopped")
	}
}
