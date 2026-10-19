//go:build android || linux || darwin || ios

// Package awgmobile exposes the AmneziaWG core to mobile platforms.
//
// It is designed for `gomobile bind` so Blackout Mobile can drive the same
// userspace core as the desktop CLI:
//
//	gomobile bind -target=android/arm64 -o awgmobile.aar ./cmd/awg-mobile
//	gomobile bind -target=ios/arm64   -o AwgMobile.xcframework ./cmd/awg-mobile
//
// Android: create the TUN interface with VpnService.Builder, call
// establish(), and pass the returned ParcelFileDescriptor's fd here.
// iOS: pass the utun file descriptor from NEPacketTunnelProvider.
//
// All entry points are safe to call from any goroutine; Start/Stop are
// serialized internally.
package awgmobile

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// obfKeys mirrors the desktop core: obfuscation parameters forwarded to the UAPI.
var obfKeys = []string{
	"jc", "jmin", "jmax",
	"s1", "s2", "s3", "s4",
	"h1", "h2", "h3", "h4",
	"i1", "i2", "i3", "i4", "i5",
	"header_protection_key", "content_padding_addition",
	"rekey_after_time", "rekey_timeout", "reject_after_time",
	"keepalive_timeout", "max_handshake_attempts",
	"random_trailers", "disable_cookies",
}

// keyToHex converts a .conf key (base64) to the hex form the UAPI expects.
func keyToHex(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	if len(s) == 64 {
		if _, err := hex.DecodeString(s); err == nil {
			return strings.ToLower(s)
		}
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return s
	}
	return hex.EncodeToString(raw)
}

var (
	mu  sync.Mutex
	dev *device.Device
)

// StartTunnel brings up an AmneziaWG tunnel on an existing TUN file descriptor.
//
//	configText — a standard AmneziaWG .conf ([Interface] + [Peer], incl. Jc/S1/H1…)
//	tunFd      — file descriptor of the OS TUN interface (VpnService / NEPacketTunnelProvider)
//
// Returns 0 on success, non-zero on error (the message is available from
// GetLastError for the most recent failure).
func StartTunnel(configText string, tunFd int) int {
	mu.Lock()
	defer mu.Unlock()

	if dev != nil {
		return 1 // already running
	}

	conf, err := parseConf(configText)
	if err != nil {
		lastErr = err.Error()
		return 2
	}

	file := os.NewFile(uintptr(tunFd), "awg-tun")
	if file == nil {
		lastErr = "invalid tun fd"
		return 3
	}
	mtu := conf.mtu
	if mtu <= 0 {
		mtu = device.DefaultMTU
	}
	tunDev, err := tun.CreateTUNFromFile(file, mtu)
	if err != nil {
		lastErr = "tun: " + err.Error()
		return 4
	}

	d := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "awg-mobile: "))
	if err := d.IpcSet(conf.uapi()); err != nil {
		_ = tunDev.Close()
		lastErr = "uapi: " + err.Error()
		return 5
	}
	if err := d.Up(); err != nil {
		d.Close()
		lastErr = "up: " + err.Error()
		return 6
	}

	dev = d
	lastErr = ""
	return 0
}

// StopTunnel tears the tunnel down. Returns 0 on success.
func StopTunnel() int {
	mu.Lock()
	defer mu.Unlock()
	if dev == nil {
		return 0
	}
	dev.Close()
	dev = nil
	return 0
}

// GetTunnelStats returns the UAPI dump (tx_bytes, rx_bytes, last_handshake_time_sec, …)
// as key=value lines, or an empty string when the tunnel is down.
func GetTunnelStats() string {
	mu.Lock()
	defer mu.Unlock()
	if dev == nil {
		return ""
	}
	s, err := dev.IpcGet()
	if err != nil {
		return ""
	}
	return s
}

var lastErr string

// GetLastError returns the message for the most recent StartTunnel failure.
func GetLastError() string {
	mu.Lock()
	defer mu.Unlock()
	return lastErr
}

// IsRunning reports whether a tunnel is currently up.
func IsRunning() bool {
	mu.Lock()
	defer mu.Unlock()
	return dev != nil
}

// parseConf / uapi mirror cmd/awg-socks/config.go. Kept local so this package
// has no dependency on the CLI command.
type mobileConf struct {
	privateKey   string
	addresses    []string
	dns          []string
	mtu          int
	obf          map[string]string
	publicKey    string
	presharedKey string
	endpoint     string
	allowedIPs   []string
	keepalive    int
}

func parseConf(text string) (*mobileConf, error) {
	c := &mobileConf{obf: map[string]string{}}
	section := ""
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		switch section {
		case "interface":
			switch k {
			case "privatekey":
				c.privateKey = v
			case "address":
				c.addresses = splitList(v)
			case "dns":
				c.dns = splitList(v)
			case "mtu":
				fmt.Sscanf(v, "%d", &c.mtu)
			default:
				c.obf[k] = v
			}
		case "peer":
			switch k {
			case "publickey":
				c.publicKey = v
			case "presharedkey":
				c.presharedKey = v
			case "endpoint":
				c.endpoint = v
			case "allowedips":
				c.allowedIPs = splitList(v)
			case "persistentkeepalive":
				fmt.Sscanf(v, "%d", &c.keepalive)
			}
		}
	}
	if c.privateKey == "" || c.publicKey == "" || c.endpoint == "" {
		return nil, fmt.Errorf("config needs PrivateKey, PublicKey and Endpoint")
	}
	return c, nil
}

func (c *mobileConf) uapi() string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", keyToHex(c.privateKey))
	for _, k := range obfKeys {
		if v, ok := c.obf[k]; ok {
			fmt.Fprintf(&b, "%s=%s\n", k, v)
		}
	}
	b.WriteString("replace_peers=true\n")
	fmt.Fprintf(&b, "public_key=%s\n", keyToHex(c.publicKey))
	if c.presharedKey != "" {
		fmt.Fprintf(&b, "preshared_key=%s\n", keyToHex(c.presharedKey))
	}
	fmt.Fprintf(&b, "endpoint=%s\n", c.endpoint)
	if c.keepalive > 0 {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", c.keepalive)
	}
	for _, ip := range c.allowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", ip)
	}
	return b.String()
}

func splitList(v string) []string {
	out := []string{}
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
