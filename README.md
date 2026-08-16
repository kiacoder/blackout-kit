<div align="center">

```
██████╗ ██╗      █████╗  ██████╗██╗  ██╗ ██████╗ ██╗   ██╗████████╗
██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██╔═══██╗██║   ██║╚══██╔══╝
██████╔╝██║     ███████║██║     █████╔╝ ██║   ██║██║   ██║   ██║
██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ██║   ██║██║   ██║   ██║
██████╔╝███████╗██║  ██║╚██████╗██║  ██╗╚██████╔╝╚██████╔╝   ██║
╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝
                  ██╗  ██╗██╗████████╗
                  ██║ ██╔╝██║╚══██╔══╝
                  █████╔╝ ██║   ██║
                  ██╔═██╗ ██║   ██║
                  ██║  ██╗██║   ██║
                  ╚═╝  ╚═╝╚═╝   ╚═╝
```

**BlackoutKit (`blackout-kit`) — Local Censorship-Circumvention Toolkit**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-0078d4?style=flat-square&logo=linux)
![GUI](https://img.shields.io/badge/GUI-CustomTkinter-00A8FF?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Version](https://img.shields.io/badge/Version-1.1.1-orange?style=flat-square)
![Security Audited](https://img.shields.io/badge/Security-Audited-blueviolet?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

*A Windows GUI and cross-platform command-line toolkit for locally available bypass engines, proxy configuration, and targeted network diagnostics. Windows provides the broad engine set; Linux supports XRay, XRay → sing-box TUN, Hysteria2, and TUIC through the managed runner.*

**🇮🇷 Iran · 🇨🇳 China · 🇮🇶 Iraq · 🇬🇧 United Kingdom · 🇺🇸 United States · 🇪🇺 Europe**

</div>

---

## Table of Contents

- [Why Blackout Kit](#why-blackout-kit)
- [Native Desktop App GUI](#native-desktop-app-gui)
- [Omni AI Agent Controller (MCP Server)](#omni-ai-agent-controller-mcp-server)
- [Split Tunneling](#split-tunneling)
- [Supported Countries](#supported-countries)
- [Engines](#engines)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [VLESS REALITY](#vless-reality)
- [All Commands](#all-commands)
- [Security Modes](#security-modes)
- [Settings Reference](#settings-reference)
- [How It Works](#how-it-works)
- [Two Versions](#two-versions)
- [Troubleshooting](#troubleshooting)
- [Roadmap](#roadmap)
- [Disclaimer](#disclaimer)

---

## Omni AI Agent Controller (MCP Server)

BlackoutKit includes a Model Context Protocol (MCP) server for AI clients with a limited collection of local operations. Its connect, disconnect, configuration, Windows system-proxy bypass, log, and diagnostic tools can change local networking or saved state; review requests before granting an agent permission to invoke them:

```json
{
  "mcpServers": {
    "blackout-kit": {
      "command": "blackout",
      "args": ["mcp"]
    }
  }
}
```

### Exposed AI Agent Tools

* `blackout_connect`: Start an explicitly selected engine. The MCP interface intentionally does not expose `auto` or the temporary Iran profile.
* `blackout_disconnect`: Stop the managed daemon and remove only Blackout-managed local proxy and kill-switch state; unrelated external proxy settings remain unchanged.
* `blackout_emergency`: Start the configured local candidate sequence (Linux uses its supported subset).
* `blackout_status`: Read daemon state and the current system-proxy state; it does not report public IP or remote latency.
* `blackout_read_logs`: Read recent local daemon logs.
* `blackout_config`: List, add, import, or remove saved proxy URIs. Routine replies never echo URI credentials.
* `blackout_settings`: Read, change, or reset settings with the same value validation as the terminal CLI. Credential-bearing values are masked in routine reads.
* `blackout_split_tunnel`: Maintain locally stored Windows `ProxyOverride` bypass patterns; it is not network-level routing.
* `blackout_net_tools`: Run DNS benchmark/flush/set, targeted recovery, hotspot, and TCP ping actions; network-changing calls return their actual result.
* `blackout_scan`: Run the built-in Cloudflare IP reachability scan; it does not scan a local network or arbitrary ports.
* `blackout_doctor`: Run diagnostics. The MCP implementation currently does not forward its `fix` option.
* `blackout_security_mode`: Apply the same local SPEED/PRIVATE/LEGEND preset as `blackout mode`; it does not toggle the kill switch.

---

## Split Tunneling

BlackoutKit can maintain **Windows system-proxy bypass** rules for domains and IP patterns. These entries are stored locally and applied to Windows `ProxyOverride`; matching traffic bypasses the system proxy directly.

They are not per-process routing rules, Linux TUN routes, or a general network-layer split-tunneling system.

```bash
# Add a domain or IP pattern to the Windows proxy-bypass list
blackout split-tunnel add example.com
blackout split-tunnel add 192.168.1.*

# List or remove locally saved bypass rules
blackout split-tunnel list
blackout split-tunnel remove example.com
```

---

## Native Desktop App GUI

BlackoutKit features a modern native Windows Dark GUI built with `CustomTkinter`:

* **⚡ Animated Connection Map:** Programmatic vector canvas rendering live animated connection nodes and arcs.
* **📡 Real-Time Engine Log Stream:** Live tailing of daemon logs directly inside the dashboard.
* **🛡️ Security Profiles & Kill Switch:** Direct toggle for TIC 2026 Iran Evasion mode and strict network kill-switch.
* **⏱️ Live Uptime & Latency Probing:** Real-time TCP latency checks and active session timer.

Launch the GUI anytime with:
```cmd
blackout gui
```
Or simply double-click `blackout.exe` to launch the interactive workspace selector.

---

## Why Blackout Kit

Most bypass tools are single-purpose: one protocol, one config, one point of failure.

**Blackout Kit is different.** It coordinates local bypass engines, monitors managed processes, and provides targeted recovery for Blackout Kit-owned network state. Windows exposes the full engine set; Linux supports the managed XRay, XRay → sing-box TUN, Hysteria2, and TUIC paths.

Key design decisions:

- **Offline-capable release assets** — release packages can include the required runtime assets; source installs still need dependencies and any missing runtime binaries.
- **One command** — `blackout connect` uses a local readiness recommendation when no engine is specified.
- **Bounded recovery** — the daemon retries failed starts with capped backoff and repairs only verified Blackout Kit-owned state.
- **Country-aware guidance** — when a country is pinned, its local profile informs recommendations; otherwise country-aware commands may query ISP information when network access is available.
- **Security settings** — SPEED, PRIVATE, and LEGEND apply documented XRay/GDPI settings. They do not guarantee anonymity, bypass success, or resistance to traffic correlation.

---

## Local Data and Privacy Boundaries

Blackout Kit does not include an analytics or telemetry service. It stores operational state locally, including settings, saved configuration URIs, daemon logs, stability history, and optional certificate or proxy-bypass records. Treat those local files as sensitive because a proxy URI can contain credentials.

Some commands intentionally make network requests: subscription imports, updates, IP/SNI scans, DNS resolution, certificate checks, speed tests, and unpinned ISP/country lookup. The selected proxy or VPN server also observes traffic routed through it; Blackout Kit does not operate those upstream servers.

Several engines manipulate or tunnel traffic locally, but that does not establish anonymity, prevent endpoint logging, or guarantee censorship circumvention. Review the source and [security policy](SECURITY.md) before using the tool in a high-risk environment.

---

## Supported Countries

| Country profile | Censorship level | Local candidate order | Notes |
|-----------------|-----------------|-----------------------|-------|
| 🇮🇷 Iran | **HIGH** | SNI → WARP → Psiphon → GDPI | Local profile guidance for changing filtering conditions. |
| 🇨🇳 China | **EXTREME** | XRay → Psiphon → WARP → TUN | Local profile guidance; use a compatible upstream configuration. |
| 🇮🇶 Iraq | **MEDIUM** | SNI → WARP → GDPI → Psiphon | Local profile guidance for ISP-level filtering. |
| 🇬🇧 United Kingdom | **LOW** | GDPI → WARP → Psiphon | Local profile guidance for configured engines. |
| 🇺🇸 United States | **MINIMAL** | WARP → Psiphon | Local profile guidance, not a privacy assessment. |
| 🇪🇺 Europe | **LOW** | GDPI → WARP → WireGuard → Psiphon | Local profile guidance; WireGuard needs a supplied configuration. |

Country guidance: when a command needs an unpinned profile, Blackout Kit may look up ISP information and use the matching profile as one local recommendation input. It does not establish that an engine or remote proxy will work. You can pin a country manually:

```
blackout country set IR
blackout country set CN
blackout country reset   ← back to auto-detect
```

---

## Engines

Windows exposes the broad engine set below. Linux x86_64 supports only XRay, the XRay → sing-box TUN stack, Hysteria2, and TUIC through the managed `blackout-engine` runner.

| Engine | Protocol | What It Does | Best For |
|--------|----------|--------------|----------|
| **SNI Spoofing** | TCP injection | Windows local SNI component used with XRay; results depend on the network and upstream configuration | Some DPI environments |
| **XRay / V2Ray** | VLESS · Trojan · TLS / REALITY | Local XRay proxy using a saved supported configuration | Configured proxy use |
| **GoodbyeDPI** | TCP handling | Windows-only legacy or experimental native TCP handling | Some light-DPI environments |
| **Cloudflare WARP** | WARP client | Windows runtime path using its configured WARP client | Networks where that upstream is reachable |
| **Psiphon** | Multi-protocol client | Windows runtime path using Psiphon Tunnel Core | Fallback where locally available |
| **Hysteria2** | QUIC proxy | sing-box proxy from a saved Hysteria2 configuration | QUIC-capable configurations |
| **TUIC** | QUIC proxy | sing-box proxy from a saved TUIC configuration | QUIC-capable configurations |
| **Tor** | Onion-routing client | Local SOCKS proxy using a separately supplied Tor runtime | Cases needing a Tor-compatible client |
| **TUN** | System-level tunnel | Windows uses sing-box; Linux starts XRay upstream of sing-box through `blackout-engine` | Proxy-unaware applications |
| **IKEv2 / L2TP** | Windows native VPN | Windows RAS connection using saved settings | Windows VPN use |
| **WireGuard** | WireGuard VPN | Windows client using a supplied `.conf` file | Windows WireGuard use |
| **OpenVPN** | OpenVPN | Windows client using a supplied `.ovpn` file | Windows OpenVPN use |
| **SoftEther** | SoftEther VPN | Windows SoftEther client using saved settings | Windows SoftEther use |
| **mhrv** | HTTP GAS relay | Embedded HTTP relay; HTTPS CONNECT is unsupported | Last-resort HTTP-only access |
| **Google Apps Script** | HTTP relay | HTTP relay through configured Apps Script deployments; HTTPS CONNECT is unsupported | Last-resort HTTP-only access |

GoodbyeDPI currently has two internal backends:
- **legacy** — the stable default built around `goodbyedpi.exe`, modesets, connectivity probing, and elevation fallback
- **native** — an experimental Go/WinDivert backend that is not the default yet

For product safety, the legacy backend remains the default until the native path reaches parity.

**Note for Iran:** The Iran country profile supplies a local candidate order, but filtering behavior changes by network and time. Test the supported local engines with the user's own upstream configuration rather than treating a profile order as proof of effectiveness.

**Note for UK/light DPI:** The legacy GDPI backend remains the product default; its effectiveness depends on the network and should be tested against the user's own conditions.

**Runtime note:** if the legacy backend is unstable on a specific Windows machine, you can switch locally to the experimental backend:
```bash
blackout settings set gdpi_backend native
blackout connect gdpi
```
The repository still treats `legacy` as the default product path until native reaches parity.

**For maintainers:** after editing `engine/` sources, rebuild `bins/blackout_core.dll` so the exported native engine changes actually reach the app runtime.

---

## Installation

### Option 1 — Standalone Executable (Zero Dependencies)

Download `blackout.exe` from the [Releases page](https://github.com/kiacoder/blackout-kit/releases).

This executable is fully standalone. No Python installation required. Just double-click `blackout.exe` and it will automatically extract its internal engines and open the CLI.

> **Note:** The `.exe` comes pre-packed with native C/C++ DLLs. On first run, it drops them into `~/.blackout-kit/bins/` so they can be securely updated later.

---

### Option 2 — Developer Source Version

```cmd
git clone https://github.com/kiacoder/blackout-kit.git
cd blackout-kit
pip install -r requirements.txt
python blackout.py bins download
```

`bins download` auto-downloads all necessary binaries from their official sources with a progress bar.

> **Warning:** The Source version requires internet to download binaries and dependencies. If you are already in a blackout, use the standalone `.exe` instead.

---

### Requirements

**Windows**
- Python 3.10+
- Windows 10 or 11 (x64)
- Administrator privileges for Defender exclusion and VPN engines; the kill switch is unavailable because unsafe legacy Windows Firewall rules are removed

**Linux x86_64 — Ubuntu/Debian, Fedora, and Arch**
- Python 3.10+, `iproute2`, and either `nftables` or both `iptables` and `ip6tables`
- The Linux `blackout-engine` release asset in `bins/` with execute permission
- `sudo` for system-wide TUN routing, firewall protection, and targeted cleanup
- A direct VLESS (including REALITY), Trojan, Hysteria2, or TUIC configuration; the Windows SNI packet-injection fallback and VMess runtime path are not available on Linux

On Linux, `blackout connect xray` uses the managed XRay runner; `blackout connect tun` starts XRay first, then sing-box TUN through the same runner. Hysteria2 and TUIC are also supported. SNI spoofing, GoodbyeDPI, Windows VPN engines, the desktop GUI, and Windows proxy-bypass rules are unavailable there. The packages in `requirements.txt` supply the shared Python CLI.

### Linux Quick Start

```bash
python3 -m pip install blackout-kit
mkdir -p bins
# Download the Linux x86_64 `blackout-engine` asset from the matching release.
chmod +x bins/blackout-engine
blackout config add '<your-vless-or-trojan-uri>'
sudo blackout connect tun --background
```

Use `sudo blackout doctor` to inspect Linux prerequisites. `sudo blackout stop` removes Blackout Kit's own TUN/firewall state. The Linux kill switch uses only an endpoint-scoped `inet blackoutkit` nftables table, with `iptables`/`ip6tables` fallback; it refuses to enable unless it can validate an upstream proxy endpoint.

To repair a stale crash state, run:

```bash
sudo blackout fix
```

This removes only `BlackoutKit-TUN`, Blackout-owned firewall rules, and the dedicated routing table `20220`; it does not reset system routes, NetworkManager, DNS configuration, or third-party VPNs. ARP repair is deliberately separate because it briefly affects local-network discovery:

```bash
sudo blackout tools arp-flush
```

or:

```bash
sudo blackout fix --flush-arp
```

---

## Quick Start

```cmd
:: 1. Run the app — shows an interactive menu
python blackout.py

:: 2. Let the doctor check everything first
python blackout.py doctor

:: 3. Connect (uses a local readiness recommendation unless you specify an engine)
python blackout.py connect

:: 4. If that fails, try locally supported candidates in sequence
python blackout.py emergency
```

The selected engine may expose a local proxy or manage its own routes. In daemon mode, Blackout Kit monitors its managed engine and retries failed starts up to the configured limit; this does not prove upstream reachability or guarantee a successful failover.

---

## VLESS REALITY

Blackout Kit supports **client-side VLESS REALITY** through the existing XRay path. Add or import a standard `vless://` URI, then connect with `blackout connect xray`; use `blackout connect tun` when a system-wide tunnel is required. REALITY is a VLESS security mode, not a separate `blackout reality` engine.

A compatible URI needs `security=reality`, `sni`, and `pbk` (or `publicKey`). `sid`/`shortId`, `spx`/`spiderX`, `flow`, `fp`, and `serviceName` are preserved when supplied. TCP, WebSocket, and gRPC transports are supported.

```text
vless://UUID@server:443?security=reality&sni=server-name&pbk=server-public-key&type=tcp#label
```

Use a trusted server configuration and key supplied by that server's operator. Blackout Kit does not discover servers, generate server keys, change server-side XRay configuration, or guarantee anonymity or resistance to detection. Lists and tests display only the protocol, transport mode, and optional label, not URI credentials or REALITY key material.

`blackout tools cert-check` applies to normal TLS configurations only. REALITY verification happens inside XRay's REALITY handshake using the configured public key, so Blackout Kit does not run its TLS certificate probe or certificate policy for a REALITY connection.

---

## All Commands

### Connection

```
blackout connect                   Use a local readiness recommendation and connect
blackout connect sni               Connect with a specific engine
blackout connect xray
blackout connect warp
blackout connect psiphon
blackout connect gdpi
blackout connect tor
blackout connect tun
blackout connect wireguard
blackout connect openvpn
blackout connect softether
blackout connect ikev2
blackout connect mhrv
blackout connect hysteria2
blackout connect tuic
blackout connect appsscript

blackout connect --background      Run in background (daemon mode)
blackout connect sni --background
blackout connect --iran            Apply Iran TIC 2026 evasion profile

blackout emergency                 Try locally supported candidates in configured order
blackout emergency --background

blackout stop                      Stop the background daemon
blackout status                    Show a read-only local daemon/proxy snapshot
blackout status --watch            Refresh the local snapshot until Ctrl+C
blackout status --watch --interval 5
blackout route                     Rank engines from local readiness and health history
blackout theme                     Show the active Blackout Kit terminal palette
blackout theme light               Use Blackout Kit's light Rich palette only
blackout theme dark                Use Blackout Kit's dark Rich palette only
blackout logs                      View daemon log

# Automatic daemon reconnect policy (defaults: 2s initial delay, 60s cap)
blackout settings set reconnect_initial_delay 2
blackout settings set reconnect_max_delay 60
blackout settings set max_retries 3
blackout logs --lines 200          Show last 200 lines
```

### Scanning & Testing

```
blackout scan                      Scan Cloudflare IPs + test SNI domains
blackout scan --ips                Scan IPs only
blackout scan --sni                Test SNI domains only
blackout scan --count 300          Scan 300 IPs (default: 100)
```

### Configuration

```
blackout config list               List saved V2Ray/proxy configs
blackout config add <uri>          Add a vless://, trojan://, vmess://, hysteria2://, or tuic:// URI
blackout config import <url>       Import from a subscription URL
blackout config remove <n>         Remove config by number
```

### Binaries

```
blackout bins                      Show all binaries: installed? size?
blackout bins download             Download all missing binaries
blackout bins download xray        Download a specific binary
blackout bins update               Update all installed binaries to latest
```

### Country Profile

```
blackout country                   Show detected country + recommended engines
blackout country set IR            Pin country (IR / US / GB / CN / IQ / EU)
blackout country reset             Remove pin — return to auto-detect
```

### Security Mode

```
blackout mode                      Show current security mode
blackout mode speed                Compatibility-focused local XRay/GDPI settings (default)
blackout mode private              Random XRay fingerprint and MUX settings
blackout mode legend               Adds strict handling for known-bad normal TLS certificates

# Kill switch and config encryption remain explicit opt-in actions
blackout killswitch on
blackout config encrypt
```

### Network Tools

```
blackout tools ping [host]             TCP ping test
blackout tools speedtest               Download speed test (Cloudflare)
blackout tools dns-bench               Benchmark all DNS servers
blackout tools dns-set cloudflare      Switch DNS (cloudflare / google / shecan / electro / 403 / begzar / alibaba / tencent)
blackout tools dns-flush               Flush DNS cache
blackout tools adapters                List network adapters
blackout tools mtu [host]              Detect path MTU
blackout tools traceroute [host]       Traceroute
blackout tools hotspot                 Toggle Windows Mobile Hotspot
blackout tools share-vpn               Show manual Windows ICS guidance for a detected adapter
blackout tools netfix                  Targeted post-crash recovery (safe default)
blackout tools cert-check <host>       Check a normal TLS certificate for a host
blackout tools cert-check <host> --allow   Manually allow a normal TLS host in LEGEND mode
blackout network                       Show IP, ISP, country, and connection status
blackout network isp                   Detailed ISP info + country censorship context
```

### Diagnostics & Repair

```
blackout doctor                    Run all diagnostic checks
blackout doctor --fix              Auto-fix everything fixable
blackout doctor --fix-av           Add bins/ to Windows Defender exclusions
blackout fix                       Targeted post-crash network recovery
blackout fix --full-route-reset    Windows emergency only: flush every IPv4 route, then renew DHCP
blackout fix --full-stack-reset    Windows emergency only: reset Winsock, TCP/IP, autotuning, and DHCP
blackout fix --flush-arp           Explicit ARP/neighbor-cache flush (Windows or Linux)
```

### Post-Crash Network Recovery

Run `blackout fix` **after stopping Blackout Kit** if a crashed TUN, WireGuard, or VPN session leaves Windows offline. Its safe default:

- Removes only routes owned by a detected stale Blackout-compatible virtual adapter.
- Restores DHCP DNS only on connected physical adapters still pointed at loopback DNS such as `127.0.0.1` or `::1`; custom DNS servers remain unchanged.
- Restarts only the deterministic `BlackoutKit-TUN` adapter when diagnosed unhealthy; Wi-Fi, Ethernet, WireGuard, and third-party VPN adapters are never cycled.
- Clears stale Blackout proxy settings and flushes DNS without resetting the Windows network stack.

`blackout tools netfix` runs the same targeted default. If it cannot restore connectivity, use an explicit emergency option: `blackout fix --full-route-reset` runs `route -f` and renews DHCP, removing all IPv4 routes—including unrelated VPN and custom LAN routes; `blackout fix --full-stack-reset` resets Winsock, TCP/IP, autotuning, and the DHCP lease.

### Automatic Daemon Reconnect

When a background engine crashes or its proxy port closes, the daemon attempts an immediate restart. Failed starts remain in `reconnecting` state and retry with capped exponential delays (2s, 4s, 8s… up to the configured maximum) until `max_retries` is exhausted or you run `blackout stop`. A healthy heartbeat resets the retry budget.

After the first failed restart, the daemon may remove only verified stale Blackout routes, loopback DNS, and Blackout-owned virtual adapters before retrying. It preserves the active system proxy and kill switch, and it never runs Winsock/TCP-IP/DHCP resets or `route -f`; those remain manual recovery actions.

### Smart Routing, Live Status, and Prompts

`blackout route` is a local readiness dashboard. It ranks engines using the current platform, installed local components, saved proxy protocols, an explicitly pinned country profile when present, explicit preference, and recorded local health history. It does **not** probe remote nodes, download binaries, look up an ISP, or change settings/network routes.

`blackout connect` without an engine opens a small wizard only in an interactive terminal; it can accept the recommendation, select an engine manually, or cancel. Any explicit engine argument or option is authoritative. In pipes, CI, and other non-interactive sessions, commands never wait for a prompt.

`blackout status --watch` (also available as **Live Status** in the zero-flag terminal menu) only reads daemon state, system-proxy state, local proxy ports, and saved local stability history. It never reconnects, runs repair, or sends an external connectivity probe. `blackout theme dark|light` changes the Rich colors printed by Blackout Kit only; it does not modify Windows Terminal, PowerShell, a Linux terminal, or GUI appearance settings.

Unexpected CLI errors display a safe redacted panel with non-destructive next steps. Existing daemon and engine technical details stay in local logs rather than exposing configuration credentials or subscription URLs in the terminal.

### Settings

```
blackout settings list                  Show all settings with descriptions
blackout settings get <key>             Get a single setting value
blackout settings set <key> <val>       Change a setting
blackout settings set gdpi_backend legacy   Use the stable GoodbyeDPI backend
blackout settings set gdpi_backend native   Use the experimental Go/WinDivert backend
blackout settings reset                 Reset all settings to defaults
```

`gdpi_flags` and `gdpi_always_test_all` apply to the **legacy** backend only.

### Help

```
blackout help                      Show help overview
blackout help engines              Engine descriptions and when to use each
blackout help countries            Country profiles and recommended engines
blackout help security             Security modes explained
blackout help cert                 TLS certificate bypass system
blackout help troubleshoot         Common issues and fixes
blackout help quick_start          5-minute getting started guide
```

---

## Security Modes

Blackout Kit has three security tiers. Switch with `blackout mode <name>`.

### SPEED (default)
> Prioritizes compatibility and low local overhead.

- XRay fingerprint: Chrome
- XRay logging: none
- XRay MUX: disabled
- Normal TLS policy: `allowInsecure=True`
- Kill switch: unchanged; enable it explicitly when appropriate

Best for: ordinary connectivity where the upstream server is already trusted. This mode does not provide anonymity or validate normal TLS certificates.

---

### PRIVATE
> Applies a randomized XRay fingerprint and enables XRay MUX.

- XRay fingerprint: random
- XRay logging: none
- XRay MUX: enabled
- Normal TLS policy: `allowInsecure=True`; the client may record a certificate warning after startup
- Kill switch: unchanged; enable it explicitly when appropriate

Best for: users who want these local XRay settings. It does not prevent traffic analysis, identify a trusted server, or guarantee privacy.

---

### LEGEND
> Applies the same randomized XRay fingerprint and MUX settings, then uses strict handling for known-bad normal TLS certificates when XRay starts.

- XRay fingerprint: random
- XRay MUX: enabled
- Normal TLS policy: refuses a known-bad certificate unless it was explicitly allowed
- Kill switch: unchanged; enable it explicitly when appropriate
- Config encryption: available through `blackout config encrypt`; it is not enabled automatically

This mode does not guarantee anonymity, untraceability, traffic-analysis resistance, or an upstream Tor path. For REALITY configurations, XRay validates the configured public key during its REALITY handshake and does not use `cert-check`.

```
blackout mode legend
blackout tools cert-check myvpnserver.com          ← optional normal-TLS check
blackout tools cert-check myvpnserver.com --allow  ← explicitly allow a trusted normal-TLS host
blackout connect xray
```

---

## Settings Reference

Run `blackout settings list` to see all available settings. Key ones:

| Setting | Default | Description |
|---------|---------|-------------|
| `security_mode` | `speed` | Active security mode |
| `xray_socks_port` | `10808` | XRay SOCKS5 proxy port |
| `xray_http_port` | `10809` | XRay HTTP proxy port |
| `xray_fingerprint` | `chrome` | TLS fingerprint (chrome/firefox/random) |
| `xray_mux_enabled` | `false` | Enable connection multiplexing |
| `sni_listen_port` | `40443` | SNI spoofer listen port |
| `sni_connect_ip` | `104.19.229.21` | Windows SNI engine target IP; scanning measures TCP reachability only |
| `sni_fake_sni` | `www.hcaptcha.com` | Windows SNI component's configured fake-SNI value |
| `auto_set_proxy` | `true` | Apply a system proxy for engines that expose one |
| `engine_order` | `sni, gdpi, psiphon` | Windows emergency-mode candidate order |
| `country` | `""` | Pinned country code (empty = ISP lookup when a country-aware command needs one) |
| `terminal_theme` | `dark` | Blackout Kit Rich palette (`dark` / `light`) only |
| `kill_switch` | `false` | Persist whether Blackout Kit should attempt its platform kill switch on a compatible start |
| `wg_config_file` | `""` | Path to WireGuard `.conf` file |
| `openvpn_config` | `""` | Path to OpenVPN `.ovpn` file |
| `ikev2_server` | `""` | Windows built-in VPN server address |
| `softether_host` | `""` | SoftEther server hostname |
| `psiphon_country` | `DE` | Requested Psiphon exit-country setting |

---

## How It Works

### SNI Spoofing and Fragmentation (Windows)

The Windows SNI engine combines a local SNI-spoofing component with XRay. XRay exposes local SOCKS/HTTP ports and sends the configured proxy stream to the local SNI component on port `40443`; the SNI component applies its own packet-handling strategy before the upstream connection.

Some networks inspect TLS metadata such as SNI, and the effectiveness of any packet strategy depends on the ISP, destination, current filtering rules, and selected configuration. The Linux runtime does not provide this Windows-only SNI path. Use `blackout route`, `blackout status`, and local logs to inspect the local setup rather than treating a specific technique as a guarantee of connectivity or anonymity.

### GoodbyeDPI (UK / Light DPI)

Applies Windows TCP packet handling through the selected GoodbyeDPI backend. Its results depend on the network and filtering equipment; it is not available on Linux and should not be treated as a guaranteed bypass method.

### Emergency Mode

When a normal `connect` fails, `emergency` tries engines in order:

```
1. sni      → failed (blocked)
2. gdpi     → failed (reassembly DPI)
3. warp     → failed (IP blocked)
4. psiphon  ← CONNECTED ✓
```

The configured order is used when present; otherwise the active country profile supplies the foreground fallback order. It can be overridden:

```
blackout settings set engine_order xray,warp,psiphon,tor
```

---

## Two Versions

| | Standalone `.exe` | Source Code |
|--|--------------|--------------|
| **Contains** | Code + native DLL engines | Code only |
| **Download size** | ~63 MB | ~2 MB |
| **Works offline/blackout** | ✅ Yes | ❌ No — needs internet for `bins download` |
| **Who it's for** | End users, general public | Developers, contributors |
| **GitHub Release asset** | `blackout.exe` | `Source code.zip` |

Choose the packaged executable or source installation based on the user's platform, release provenance, and available dependencies. The source version is intended for contributors and people who can provision dependencies before connectivity is disrupted.

---

## Troubleshooting

### Connection fails immediately

```
blackout doctor
```

The doctor will identify the specific problem — missing binary, wrong port, Defender blocking the exe, etc.

### Windows Defender flags the binaries

```
blackout doctor --fix-av
```

This adds `bins/` to Defender's exclusion list. Run as Administrator.

### System proxy not being set

```
blackout settings set auto_set_proxy true
```

Requires the app to be run as Administrator for the first time.

### LEGEND mode refuses to connect ("cert verification FAILED")

A normal TLS configuration has a known-bad certificate and LEGEND mode refused it. This does not apply to VLESS REALITY, which uses its configured public key in XRay's REALITY handshake. For a normal TLS configuration, you have two options:

```
:: Option 1 — Check what's wrong
blackout tools cert-check yourserver.com

:: Option 2 — Manually trust this specific server
blackout tools cert-check yourserver.com --allow
```

### XRay exits immediately after launch

Run `blackout logs` to see the error. Common causes:
- Port already in use — change `xray_socks_port` in settings
- Config file issue — run `blackout doctor`
- Defender quarantined xray.exe — run `blackout doctor --fix-av`

### "Binary not found" for any engine

```
blackout bins download
```

Or if you have the Full version, make sure you're running from the correct folder where `bins/` exists.

### YouTube website loads but videos won't play (GoodbyeDPI)

GoodbyeDPI is a **TCP-only** tool. It cannot bypass DPI for UDP traffic. Because YouTube uses the UDP-based **QUIC** protocol for video streaming by default, the videos bypass the engine and get blocked by your ISP, even though the website shell (HTML/CSS) loads perfectly.

To fix this, force your browser to use TCP:
1. Go to `chrome://flags/#enable-quic` (or `edge://flags/#enable-quic`).
2. Set **Experimental QUIC protocol** to **Disabled**.
3. Relaunch your browser.

### DNS or routing stays broken after a crash

First stop the daemon, then run the targeted recovery:

```
blackout stop
blackout fix
```

On Windows, it restores DHCP DNS only when a connected physical adapter is still using loopback DNS and cycles only the deterministic `BlackoutKit-TUN` adapter. On Linux, it removes only Blackout Kit-owned firewall/TUN/routing state and flushes a supported local DNS cache. If Windows targeted recovery cannot restore connectivity, choose the applicable explicit emergency repair:

```
blackout fix --full-route-reset
```

```bash
blackout fix --full-stack-reset
```

### Country not detected correctly

```
blackout country
blackout country set IR   ← pin manually
```

---

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full version plan.

The current release line includes Linux x86_64 XRay/TUN support, local routing/status/theme UX, targeted recovery, and client-side VLESS REALITY handling. See [ROADMAP.md](ROADMAP.md) for planned work and supported-platform boundaries.

---

## License

MIT — Free and open source. Use it, build on it, share it.

See [LICENSE](LICENSE) for full text.

---

## Disclaimer

This tool is for **legitimate personal use only** — accessing blocked entertainment, educational resources, development tools, and personal communications.

Do not use this tool for illegal activities. Users are fully responsible for their own actions. The author bears no responsibility for misuse.

---

<div align="center">

Made by [Kiacoder](https://github.com/kiacoder) — for everyone who just wants to use the internet.

</div>
