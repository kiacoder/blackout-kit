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
	wgDevice   *device.Device
	wgCtx      context.Context
	wgCancel   context.CancelFunc
	wgListener net.Listener
)

type wireGuardConfig struct {
	ipc       string
	localIPs  []netip.Addr
	dnsIPs    []netip.Addr
}

func parseWGConfig(configPath string) (*wireGuardConfig, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	wgc := &wireGuardConfig{}
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
		case "address":
			ips := strings.Split(val, ",")
			for _, ip := range ips {
				ipStr := strings.TrimSpace(ip)
				// Strip CIDR prefix if present (e.g. "10.0.0.2/32" -> "10.0.0.2")
				addr, err := netip.ParsePrefix(ipStr)
				if err != nil {
					// Try as plain address
					if a, err2 := netip.ParseAddr(ipStr); err2 == nil {
						wgc.localIPs = append(wgc.localIPs, a)
					}
				} else {
					wgc.localIPs = append(wgc.localIPs, addr.Addr())
				}
			}
		case "dns":
			ips := strings.Split(val, ",")
			for _, ip := range ips {
				ipStr := strings.TrimSpace(ip)
				if a, err := netip.ParseAddr(ipStr); err == nil {
					wgc.dnsIPs = append(wgc.dnsIPs, a)
				}
			}
		}
	}
	wgc.ipc = ipc.String()
	return wgc, nil
}

func startWireGuardInternal(configPath string, socksPort int) error {
	// Create userspace TUN device via netstack
	// Fallback addresses if config has no Address or DNS
	localIPs := []netip.Addr{netip.MustParseAddr("10.0.0.2")}
	dnsIPs := []netip.Addr{netip.MustParseAddr("1.1.1.1")}

	wgc, err := parseWGConfig(configPath)
	if err != nil {
		return err
	}
	if len(wgc.localIPs) > 0 {
		localIPs = wgc.localIPs
	}
	if len(wgc.dnsIPs) > 0 {
		dnsIPs = wgc.dnsIPs
	}

	tun, tnet, err := netstack.CreateNetTUN(localIPs, dnsIPs, 1420)
	if err != nil {
		return err
	}

	ipcString := wgc.ipc

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
	wgListener = listener

	go func() {
		_ = server.Serve(wgListener)
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
	if wgListener != nil {
		wgListener.Close()
		wgListener = nil
	}
	if wgDevice != nil {
		wgDevice.Close()
		wgDevice = nil
		fmt.Println("WireGuard stopped")
	}
}
