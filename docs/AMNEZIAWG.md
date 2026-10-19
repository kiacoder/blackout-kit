# AmneziaWG (awg) — native engine

AmneziaWG is WireGuard with **junk-packet obfuscation** designed to survive DPI. Blackout Kit
ships its own userspace core instead of relying on a sing-box outbound patch, so the engine works
on a stock install with **no TUN adapter, no drivers, and no administrator rights**.

```
awg.conf ──► awg-go core ──► wireguard-go netstack ──► SOCKS5 127.0.0.1:11080
                                                    └─► HTTP   127.0.0.1:11081  (system proxy)
```

## Why a native core

The old engine generated a sing-box `amnezia-wireguard` outbound and failed at startup because the
bundled runtime does not register that outbound type. The native core:

- parses `.conf` directly (including every obfuscation parameter),
- converts keys from **base64** (`.conf`) to **hex** (UAPI) — a silent killer if skipped,
- terminates the tunnel in `tun/netstack` (an in-process TCP/IP stack), and
- exposes ordinary proxies, so every existing Blackout feature (daemon, rotation, system proxy)
  works unchanged.

## Quick start

```bash
blackout settings set awg_config_file C:\path\to\awg.conf
blackout ready awg          # checks binary, config, and both ports
blackout start awg -d
blackout status             # System proxy ● Active  127.0.0.1:11081
```

Test the tunnel:

```bash
curl.exe -x http://127.0.0.1:11081 -s https://api.ipify.org        # server IP
curl.exe -x socks5h://127.0.0.1:11080 -s https://api.ipify.org     # same, via SOCKS5
```

## Ports

| Setting | Default | Purpose |
|---|---|---|
| `awg_socks_port` | **11080** | SOCKS5 for tools that speak it (curl `--socks5-hostname`, browsers with SOCKS support) |
| `awg_http_port` | **11081** | HTTP CONNECT — **this is what the Windows system proxy uses** |

Both are dedicated: AmneziaWG never touches `xray_socks_port` (10808), so it can run alongside
XRay/v2rayN.

> **Why HTTP matters:** Windows (WinINET) and therefore Chrome/Edge cannot use a SOCKS system
> proxy at all. A `socks=…` system proxy is silently ignored by the browser. That is why the
> engine serves both.

## Configuration

Standard AmneziaWG `.conf`:

```ini
[Interface]
PrivateKey = <base64>
Address    = 10.10.10.2/32
DNS        = 1.1.1.1
MTU        = 1280
Jc         = 4
Jmin       = 50
Jmax       = 1000
S1         = 30
S2         = 60
H1         = 12345678
H2         = 87654321
H3         = 11223344
H4         = 44332211

[Peer]
PublicKey  = <server public key>
Endpoint   = 185.215.244.95:39006
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

Supported obfuscation keys: `Jc`, `Jmin`, `Jmax`, `S1`–`S4`, `H1`–`H4`, `I1`–`I5`,
`HeaderProtectionKey`, `ContentPaddingAddition`, `RekeyAfterTime`, `RekeyTimeout`,
`RejectAfterTime`, `KeepaliveTimeout`, `MaxHandshakeAttempts`, `RandomTrailers`,
`DisableCookies`.

**The client must use the same obfuscation values as the server.** A mismatch produces a tunnel
that never handshakes (silent, no error).

### `awg://` URIs

Instead of a file you can pass a URI as the engine config:

```
awg://<base64 of the whole .conf>
awg://?private_key=…&address=10.10.10.2/32&endpoint=185.215.244.95:39006&public_key=…&jc=4&jmin=50&jmax=1000&s1=30&s2=60&h1=12345678&h2=87654321&h3=11223344&h4=44332211
```

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `awg-core is not installed` | Binary missing | `go -C core/amneziawg-go build -o ../bins/awg-go.exe ./cmd/awg-socks` |
| `did not open SOCKS port` | Bad key, wrong endpoint, or port taken | Read the core output in the error — it names the exact UAPI field |
| Tunnel up, browser dead | System proxy is `socks=` | Upgrade to 1.9.0+ (`awg_http_port`); verify `blackout status` shows `127.0.0.1:11081` |
| `curl` works, Chrome stalls on video | QUIC (UDP/443) cannot cross an HTTP proxy | `chrome://flags#enable-quic` → Disabled |
| Handshake never completes | Obfuscation mismatch or wrong server key | Compare `Jc/S1/H1–H4` and `PublicKey` with the server |

## Mobile bindings

`core/amneziawg-go/cmd/awg-mobile` exposes the same core to Android/iOS via `gomobile`:

```bash
gomobile bind -target=android/arm64 -o awgmobile.aar ./cmd/awg-mobile
gomobile bind -target=ios/arm64   -o AwgMobile.xcframework ./cmd/awg-mobile
```

| Function | Purpose |
|---|---|
| `StartTunnel(configText, tunFd) int` | Parse `.conf`, attach to the VpnService/utun fd, bring the device up |
| `StopTunnel() int` | Tear down |
| `GetTunnelStats() string` | UAPI dump (`tx_bytes`, `rx_bytes`, handshake times) |
| `GetLastError() string` | Last failure message |
| `IsRunning() bool` | Tunnel state |

## Verified results (2026-10-19)

| Check | Result |
|---|---|
| Handshake on production server | fresh `latest-handshake`, 1.5 MB transferred, 784 packets on `awg0` |
| Egress IP via HTTP proxy | `185.215.244.95` (server) |
| YouTube | `200` in 3.3 s via HTTP and SOCKS5 |
| Test suite | 1,523 passed, 2 skipped |
