package main

// AmneziaWG .conf parsing and UAPI generation.
//
// The AmneziaWG UAPI is WireGuard's UAPI plus device-level obfuscation keys
// (jc, jmin, jmax, s1-s4, h1-h4, i1-i5, ...). Device keys must appear before
// the first public_key= line; peer keys after it.

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// Obfuscation keys accepted from .conf and forwarded verbatim to the UAPI.
// Order matters only for readability of the generated config.
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

// confToUAPI maps .conf key names (lowercased) to UAPI names where they differ.
var confToUAPI = map[string]string{
	"headerprotectionkey":   "header_protection_key",
	"contentpaddingaddition": "content_padding_addition",
	"rekeyaftertime":        "rekey_after_time",
	"rekeytimeout":          "rekey_timeout",
	"rejectaftertime":       "reject_after_time",
	"keepalivetimeout":      "keepalive_timeout",
	"maxhandshakeattempts":  "max_handshake_attempts",
	"randomtrailers":        "random_trailers",
	"disablecookies":        "disable_cookies",
}

type Config struct {
	// [Interface]
	PrivateKey string
	Addresses  []string // CIDR or bare IP
	DNS        []string
	MTU        int
	ListenPort int

	// [Interface] obfuscation (device-level)
	Obfuscation map[string]string

	// [Peer]
	PublicKey    string
	PresharedKey string
	Endpoint     string
	AllowedIPs   []string
	Keepalive    int
}

// LoadConfig reads an AmneziaWG .conf (INI) file.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{Obfuscation: map[string]string{}}
	section := ""
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)

		switch section {
		case "interface":
			switch key {
			case "privatekey":
				c.PrivateKey = val
			case "address":
				c.Addresses = splitList(val)
			case "dns":
				c.DNS = splitList(val)
			case "mtu":
				if n, err := strconv.Atoi(val); err == nil {
					c.MTU = n
				}
			case "listenport":
				if n, err := strconv.Atoi(val); err == nil {
					c.ListenPort = n
				}
			default:
				if u, ok := confToUAPI[key]; ok {
					c.Obfuscation[u] = val
				} else if isObfKey(key) {
					c.Obfuscation[key] = val
				}
			}
		case "peer":
			switch key {
			case "publickey":
				if c.PublicKey == "" { // first peer only
					c.PublicKey = val
				}
			case "presharedkey":
				if c.PresharedKey == "" {
					c.PresharedKey = val
				}
			case "endpoint":
				if c.Endpoint == "" {
					c.Endpoint = val
				}
			case "allowedips":
				if len(c.AllowedIPs) == 0 {
					c.AllowedIPs = splitList(val)
				}
			case "persistentkeepalive":
				if n, err := strconv.Atoi(val); err == nil {
					c.Keepalive = n
				}
			}
		}
	}

	if c.PrivateKey == "" {
		return nil, fmt.Errorf("missing [Interface] PrivateKey")
	}
	if c.PublicKey == "" {
		return nil, fmt.Errorf("missing [Peer] PublicKey")
	}
	if c.Endpoint == "" {
		return nil, fmt.Errorf("missing [Peer] Endpoint")
	}
	if len(c.Addresses) == 0 {
		c.Addresses = []string{"10.66.66.2/32"}
	}
	if len(c.AllowedIPs) == 0 {
		c.AllowedIPs = []string{"0.0.0.0/0", "::/0"}
	}
	return c, nil
}

func isObfKey(k string) bool {
	for _, o := range obfKeys {
		if o == k {
			return true
		}
	}
	return false
}

func splitList(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// keyToHex converts a .conf key (base64, as written by wg/awg tools) to the
// hex form the WireGuard UAPI requires. Hex input passes through unchanged.
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
		return s // let the device surface the error
	}
	return hex.EncodeToString(raw)
}

// UAPI renders the config in AmneziaWG UAPI text form.
func (c *Config) UAPI() string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", keyToHex(c.PrivateKey))
	if c.ListenPort > 0 {
		fmt.Fprintf(&b, "listen_port=%d\n", c.ListenPort)
	}
	for _, k := range obfKeys {
		if v, ok := c.Obfuscation[k]; ok {
			fmt.Fprintf(&b, "%s=%s\n", k, v)
		}
	}
	b.WriteString("replace_peers=true\n")
	fmt.Fprintf(&b, "public_key=%s\n", keyToHex(c.PublicKey))
	if c.PresharedKey != "" {
		fmt.Fprintf(&b, "preshared_key=%s\n", keyToHex(c.PresharedKey))
	}
	fmt.Fprintf(&b, "endpoint=%s\n", c.Endpoint)
	if c.Keepalive > 0 {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", c.Keepalive)
	}
	for _, ip := range c.AllowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", ip)
	}
	return b.String()
}

// LocalAddrs converts configured addresses to netip.Addr values for netstack.
func (c *Config) LocalAddrs() ([]netip.Addr, error) {
	out := make([]netip.Addr, 0, len(c.Addresses))
	for _, a := range c.Addresses {
		if strings.Contains(a, "/") {
			p, err := netip.ParsePrefix(a)
			if err != nil {
				return nil, fmt.Errorf("bad address %q: %w", a, err)
			}
			out = append(out, p.Addr())
			continue
		}
		addr, err := netip.ParseAddr(a)
		if err != nil {
			return nil, fmt.Errorf("bad address %q: %w", a, err)
		}
		out = append(out, addr)
	}
	return out, nil
}

// DNSAddrs converts configured DNS servers to netip.Addr values.
func (c *Config) DNSAddrs() []netip.Addr {
	out := make([]netip.Addr, 0, len(c.DNS))
	for _, d := range c.DNS {
		if a, err := netip.ParseAddr(d); err == nil {
			out = append(out, a)
		}
	}
	return out
}

// Summary is a human-readable one-screen description (used by --check-config).
func (c *Config) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "endpoint:   %s\n", c.Endpoint)
	fmt.Fprintf(&b, "addresses:  %s\n", strings.Join(c.Addresses, ", "))
	fmt.Fprintf(&b, "dns:        %s\n", strings.Join(c.DNS, ", "))
	fmt.Fprintf(&b, "allowed:    %s\n", strings.Join(c.AllowedIPs, ", "))
	fmt.Fprintf(&b, "keepalive:  %d\n", c.Keepalive)
	obf := make([]string, 0, len(c.Obfuscation))
	for _, k := range obfKeys {
		if v, ok := c.Obfuscation[k]; ok {
			obf = append(obf, fmt.Sprintf("%s=%s", k, v))
		}
	}
	if len(obf) == 0 {
		fmt.Fprintf(&b, "obfuscation: (none — plain WireGuard)\n")
	} else {
		fmt.Fprintf(&b, "obfuscation: %s\n", strings.Join(obf, " "))
	}
	return b.String()
}
