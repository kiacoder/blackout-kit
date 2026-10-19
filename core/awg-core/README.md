# awg-core — native AmneziaWG core

The AmneziaWG client used by `blackout start awg`. It is a thin wrapper around the
vendored [`amneziawg-go`](../amneziawg-go) (module `github.com/amnezia-vpn/amneziawg-go/v3`),
terminating the tunnel in wireguard-go's **in-process netstack** and exposing a local
**SOCKS5** proxy — no TUN device, no admin rights, no sing-box outbound patch.

## Layout

```
core/
  amneziawg-go/              vendored upstream (source of truth for the protocol)
    cmd/awg-socks/           CLI daemon: .conf → UAPI → netstack → SOCKS5
    cmd/awg-mobile/          mobile bindings (gomobile): StartTunnel/StopTunnel/GetTunnelStats
```

The commands live inside the vendored module on purpose: building them from a separate
module trips `go mod tidy` over gvisor's `pkg/tcpip/stack/bridge_test.go` (which declares a
non-standard `package bridge_test`). Keeping the module boundary out of the way makes the
build hermetic — no network fetch, no replace directive.

## Build (desktop)

```bash
# Windows
cd core/amneziawg-go
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ../../bins/awg-go.exe ./cmd/awg-socks

# Linux
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ../../bins/awg-go ./cmd/awg-socks
```

Pure Go (CGO disabled), ~6 MB. `blackout bins` reports it as **AmneziaWG Core (awg-go)**.

## Build (mobile)

```bash
cd core/amneziawg-go

# Android (aar; pass the VpnService fd to StartTunnel)
gomobile bind -target=android/arm64 -o awgmobile.aar ./cmd/awg-mobile

# iOS (xcframework; pass the utun fd from NEPacketTunnelProvider)
gomobile bind -target=ios/arm64 -o AwgMobile.xcframework ./cmd/awg-mobile
```

Exported API (package `awgmobile`):

| Function | Purpose |
|---|---|
| `StartTunnel(configText string, tunFd int) int` | Parse .conf, attach to the fd, bring the device up. 0 = success. |
| `StopTunnel() int` | Tear down. |
| `GetTunnelStats() string` | UAPI dump (`tx_bytes`, `rx_bytes`, handshake times). |
| `GetLastError() string` | Message for the last failed start. |
| `IsRunning() bool` | Whether a tunnel is active. |

The mobile package is build-tagged `android || linux || darwin || ios` (fd-based TUN does
not exist on Windows).

## Configuration

Standard AmneziaWG `.conf`:

```ini
[Interface]
PrivateKey = <base64>
Address    = 10.66.66.2/32, fd42:42:42::2/128
DNS        = 1.1.1.1
MTU        = 1280
Jc         = 4
Jmin       = 40
Jmax       = 70
S1         = 30
S2         = 40
H1         = 123456-123500
H2         = 234567-234600
H3         = 345678-345700
H4         = 456789-456800

[Peer]
PublicKey  = <base64>
Endpoint   = 185.215.244.95:39006
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

Supported obfuscation keys: `Jc`, `Jmin`, `Jmax`, `S1`–`S4`, `H1`–`H4`, `I1`–`I5`,
`HeaderProtectionKey`, `ContentPaddingAddition`, `RekeyAfterTime`, `RekeyTimeout`,
`RejectAfterTime`, `KeepaliveTimeout`, `MaxHandshakeAttempts`, `RandomTrailers`,
`DisableCookies`.

Keys in `.conf` are **base64**; the UAPI requires **hex** — the wrapper converts them
automatically (a plain passthrough fails with "failed to set private_key").

## Blackout integration

- Setting: `awg_config_file` → path to the `.conf` (or pass an `awg://` URI as the engine config)
- Local proxy: `127.0.0.1:<xray_socks_port>` (SOCKS5), reported by
  `settings.get_engine_proxy_details("awg", …)`
- Lifecycle: `AmneziaWGEngine.start()` spawns the core with
  `--config <conf> --socks 127.0.0.1:<port> --ready-file <tmp>`, waits for the port, and on
  failure logs the core's own output (bad key, unreachable endpoint, etc.).
