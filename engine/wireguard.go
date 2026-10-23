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
	"strconv"
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
	ipc      string
	localIPs []netip.Addr
	dnsIPs   []netip.Addr
	// MTU from [Interface]; 1420 is the usual default when the file omits it.
	mtu int
}

func parseWGConfig(configPath string) (*wireGuardConfig, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	wgc := &wireGuardConfig{mtu: 1420}
	var ipc strings.Builder
	scanner := bufio.NewScanner(file)

	// The file is sectioned: [Interface] describes this side, [Peer] each
	// remote. The old parser was a flat key switch that ignored the sections
	// entirely, so a key in the wrong section was accepted, MTU was silently
	// dropped (always 1420) and every peer's fields were written into the same
	// IPC stream.
	section := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		val := strings.TrimSpace(parts[1])

		// An unsectioned file is tolerated (some generators emit bare keys),
		// but a sectioned one is enforced.
		inInterface := section == "interface" || section == ""
		inPeer := section == "peer" || section == ""

		switch {
		case inInterface && key == "privatekey":
			if b, err := base64.StdEncoding.DecodeString(val); err == nil {
				ipc.WriteString(fmt.Sprintf("private_key=%s\n", hex.EncodeToString(b)))
			}
		case inInterface && key == "listenport":
			ipc.WriteString(fmt.Sprintf("listen_port=%s\n", val))
		case inInterface && key == "address":
			for _, ip := range strings.Split(val, ",") {
				ipStr := strings.TrimSpace(ip)
				if ipStr == "" {
					continue
				}
				if addr, err := netip.ParsePrefix(ipStr); err == nil {
					wgc.localIPs = append(wgc.localIPs, addr.Addr())
				} else if a, err2 := netip.ParseAddr(ipStr); err2 == nil {
					wgc.localIPs = append(wgc.localIPs, a)
				}
			}
		case inInterface && key == "dns":
			for _, ip := range strings.Split(val, ",") {
				ipStr := strings.TrimSpace(ip)
				if a, err := netip.ParseAddr(ipStr); err == nil {
					wgc.dnsIPs = append(wgc.dnsIPs, a)
				}
			}
		case inInterface && key == "mtu":
			if mtu, err := strconv.Atoi(val); err == nil && mtu >= 576 && mtu <= 65535 {
				wgc.mtu = mtu
			}
		case inPeer && key == "publickey":
			if b, err := base64.StdEncoding.DecodeString(val); err == nil {
				ipc.WriteString(fmt.Sprintf("public_key=%s\n", hex.EncodeToString(b)))
			}
		case inPeer && key == "presharedkey":
			if b, err := base64.StdEncoding.DecodeString(val); err == nil {
				ipc.WriteString(fmt.Sprintf("preshared_key=%s\n", hex.EncodeToString(b)))
			}
		case inPeer && key == "endpoint":
			ipc.WriteString(fmt.Sprintf("endpoint=%s\n", val))
		case inPeer && key == "allowedips":
			for _, ip := range strings.Split(val, ",") {
				if trimmed := strings.TrimSpace(ip); trimmed != "" {
					ipc.WriteString(fmt.Sprintf("allowed_ip=%s\n", trimmed))
				}
			}
		case inPeer && key == "persistentkeepalive":
			ipc.WriteString(fmt.Sprintf("persistent_keepalive_interval=%s\n", val))
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	wgc.ipc = ipc.String()
	return wgc, nil
}

func startWireGuardInternal(configPath string, socksPort int) (err error) {
	engineMu.Lock()
	defer engineMu.Unlock()
	if wgDevice != nil {
		return fmt.Errorf("wireguard is already running")
	}

	// Every failure below used to leave wgDevice (and possibly the listener)
	// non-nil, so the next start hit "wireguard is already running" for the
	// rest of the process lifetime - one bad config or an occupied SOCKS port
	// bricked the engine until the daemon restarted. Roll back instead.
	defer func() {
		if err == nil {
			return
		}
		if wgListener != nil {
			wgListener.Close()
			wgListener = nil
		}
		if wgCancel != nil {
			wgCancel()
			wgCancel = nil
		}
		if wgDevice != nil {
			wgDevice.Close()
			wgDevice = nil
		}
	}()
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

	// Honour [Interface] MTU; 1420 was hardcoded and a file asking for 1280
	// (the WARP value) got the wrong one.
	mtu := wgc.mtu
	if mtu <= 0 {
		mtu = 1420
	}
	tun, tnet, err := netstack.CreateNetTUN(localIPs, dnsIPs, mtu)
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

	safeGo("wireguard.serve", func() {
		_ = server.Serve(wgListener)
	})

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
	engineMu.Lock()
	defer engineMu.Unlock()
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
