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

**DPI Bypass & Censorship Circumvention Toolkit**

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-0078d4?style=flat-square&logo=windows)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Version](https://img.shields.io/badge/Version-1.1.0-orange?style=flat-square)
![Security Audited](https://img.shields.io/badge/Security-Audited-blueviolet?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

*A unified command-line toolkit that orchestrates 16 bypass engines, auto-switches on failure, sets your system proxy automatically, and includes a full network diagnostic suite — all in one place.*

**🇮🇷 Iran · 🇨🇳 China · 🇮🇶 Iraq · 🇬🇧 United Kingdom · 🇺🇸 United States · 🇪🇺 Europe**

</div>

---

## Table of Contents

- [Why Blackout Kit](#why-blackout-kit)
- [Supported Countries](#supported-countries)
- [Engines](#engines)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [All Commands](#all-commands)
- [Security Modes](#security-modes)
- [Settings Reference](#settings-reference)
- [How It Works](#how-it-works)
- [Two Versions](#two-versions)
- [Troubleshooting](#troubleshooting)
- [Roadmap](#roadmap)
- [Disclaimer](#disclaimer)

---

## Why Blackout Kit

Most bypass tools are single-purpose: one protocol, one config, one point of failure.

**Blackout Kit is different.** It is a *coordinator* — it manages multiple bypass engines simultaneously, auto-switches to the next one when the current one fails, monitors connection health, and recovers automatically. When Iran's TIC flips to whitelist mode during unrest, Blackout Kit's emergency mode tries every engine until something gets through.

Key design decisions:

- **Zero internet required to start** — the Full version ships with all binaries bundled. Unzip and run. No GitHub downloads during a blackout.
- **One command** — `blackout connect` is all most users need.
- **Self-healing** — the daemon monitors the connection and auto-restarts failed engines.
- **Country-aware** — detects your ISP and automatically recommends the right engine and DNS for your region.
- **Privacy tiers** — three security modes (SPEED / PRIVATE / LEGEND) let you trade performance for anonymity.

---

## Privacy First (Zero Logs)

Blackout Kit is built on absolute privacy and transparency:

- **Zero Telemetry:** The tool does not phone home, track usage, or report analytics to any server.
- **Zero Remote Logging:** All operational logs (like connection statuses and engine errors) are stored strictly locally on your own machine in the `~/.blackout-kit/` folder.
- **Local Evasion:** Engines like GoodbyeDPI and SNI Spoofing manipulate packets *locally* on your PC. Your traffic goes straight to the destination website without ever passing through a middleman server.
- **Fully Open Source:** The entire codebase is open for you (or any AI) to verify.

---

## Supported Countries

| Country | Censorship Level | Best Engine | Notes |
|---------|-----------------|-------------|-------|
| 🇮🇷 Iran | **HIGH** | SNI → WARP → Psiphon | TIC uses hardware DPI. Pure TCP fragmentation is no longer enough; SNI sequence injection remains the core bypass. |
| 🇨🇳 China | **EXTREME** | XRay → Psiphon → WARP → TUN | Great Firewall blocks IPs + SNI simultaneously. XRay is the main manual and auto-selected path. |
| 🇮🇶 Iraq | **MEDIUM** | SNI → WARP → GoodbyeDPI | ISP-level DPI similar to Iran. SNI spoofing is usually the best first option. |
| 🇬🇧 United Kingdom | **LOW** | GoodbyeDPI → WARP | Ofcom ISP content filtering and light DPI are easy to bypass. |
| 🇺🇸 United States | **MINIMAL** | WARP → Psiphon | ISP throttling and geo-restrictions only. No deep inspection. |
| 🇪🇺 Europe | **LOW** | GoodbyeDPI → WARP → WireGuard | Privacy-focused profile with ad-blocking DNS defaults for common ISP filtering cases. |

Auto-detection: Blackout Kit reads your ISP info at startup and silently selects the optimal engine order and DNS for your country. You can also pin a country manually:

```
blackout country set IR
blackout country set CN
blackout country reset   ← back to auto-detect
```

---

## Engines

Blackout Kit coordinates **16 bypass engines**. Each serves a different threat model.

| Engine | Protocol | What It Does | Best For |
|--------|----------|--------------|----------|
| **SNI Spoofing** | TCP injection | Injects a fake TLS ClientHello before the real handshake — the DPI sees an allowed domain | Iran, Iraq: ISP-level DPI |
| **XRay / V2Ray** | VLESS · Trojan · WS+TLS | Encrypted proxy tunnel with TLS fingerprint camouflage | All countries |
| **GoodbyeDPI** | TCP fragmentation | Splits TCP packets so the DPI engine can't reassemble the SNI field | UK, light DPI |
| **Cloudflare WARP** | WireGuard / MASQUE | Tunnels through Cloudflare's network | All countries |
| **Psiphon** | Multi-protocol VPN | Automatic protocol switching: SSH, meek, obfuscated SSH | Heavy blackouts |
| **Hysteria2** | QUIC proxy | High-performance QUIC proxy through sing-box | QUIC-friendly networks |
| **TUIC** | QUIC proxy | Low-latency QUIC tunnel through sing-box | Low-latency censorship bypass |
| **Tor** | Onion routing | 3-hop anonymized routing | Max privacy |
| **TUN (sing-box)** | System-level tunnel | Routes ALL app traffic — not just proxy-aware apps | Stubborn apps |
| **IKEv2 / L2TP** | Windows native VPN | No extra binary — uses Windows built-in RAS | Corporate networks |
| **WireGuard** | WireGuard VPN | Fast, kernel-level, modern UDP VPN | Speed + privacy |
| **OpenVPN** | OpenVPN | Battle-tested TLS-based VPN, works over TCP:443 | Wide compatibility |
| **SoftEther** | SSL-VPN | VPN over HTTPS — indistinguishable from web traffic | Extreme filtering |
| **mhrv** | Rust MITM proxy | HTTP+SOCKS5 proxy with custom obfuscation | Experimental |
| **Google Apps Script** | HTTPS relay | Domain-fronts traffic through script.google.com | Last resort |

GoodbyeDPI currently has two internal backends:
- **legacy** — the stable default built around `goodbyedpi.exe`, modesets, connectivity probing, and elevation fallback
- **native** — an experimental Go/WinDivert backend that is not the default yet

For product safety, the legacy backend remains the default until the native path reaches parity.

**Note for Iran:** GDPI is still weaker than SNI/XRay against modern TIC-style DPI. Keep SNI/XRay as the primary recommendation for Iran.

**Note for UK/light DPI:** GDPI remains a strong first option, and the legacy backend stays the production default until the native path is field-proven.

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

- **Python 3.9+**
- **Windows 10 or 11** (x64)
- Administrator privileges (for kill switch, Defender exclusion, VPN engines)
- The packages in `requirements.txt`: `rich`, `httpx`, `psutil`, `cryptography`

---

## Quick Start

```cmd
:: 1. Run the app — shows an interactive menu
python blackout.py

:: 2. Let the doctor check everything first
python blackout.py doctor

:: 3. Connect (auto-picks the best engine for your country)
python blackout.py connect

:: 4. If that fails, try all engines one by one
python blackout.py emergency
```

That's it. Blackout Kit handles the rest — sets your system proxy, monitors the connection, and auto-switches if the engine drops.

---

## All Commands

### Connection

```
blackout connect                   Auto-select best engine and connect
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

blackout emergency                 Try all engines in order until one works
blackout emergency --background

blackout stop                      Stop the background daemon
blackout status                    Show daemon status + connection health
blackout logs                      View daemon log
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
blackout config add <uri>          Add a vless:// or trojan:// URI
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
blackout mode speed                Max speed, no overhead (default)
blackout mode private              Random TLS fingerprint + DoH DNS
blackout mode legend               Full privacy: multi-hop, kill switch, encrypted configs
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
blackout tools share-vpn               Share VPN over hotspot (ICS)
blackout tools netfix                  Auto-fix common network problems (Winsock + TCP/IP reset)
blackout tools cert-check <host>       Check TLS certificate for a host
blackout tools cert-check <host> --allow   Manually allow a host in LEGEND mode
blackout network                       Show IP, ISP, country, and connection status
blackout network isp                   Detailed ISP info + country censorship context
```

### Diagnostics & Repair

```
blackout doctor                    Run all diagnostic checks
blackout doctor --fix              Auto-fix everything fixable
blackout doctor --fix-av           Add bins/ to Windows Defender exclusions
blackout fix                       Quick network repair (Winsock + DNS + TCP reset)
```

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
> Just get through. Maximum compatibility, zero overhead.

- TLS fingerprint: Chrome
- Logging: none
- MUX: disabled
- Cert checking: silent bypass (`allowInsecure=True` always)
- Kill switch: off

Best for: daily use, streaming, browsing.

---

### PRIVATE
> Harder to fingerprint. Slightly slower.

- TLS fingerprint: random (rotates per session)
- Logging: none
- MUX: enabled
- Cert checking: warns if server cert is invalid, but still connects
- Background cert probing after connect

Best for: users who want to avoid traffic analysis without sacrificing reliability.

---

### LEGEND
> Near-untraceable. Multi-hop. Hard fail on bad certs.

- TLS fingerprint: random
- MUX: enabled
- Routing: SNI → XRay → Tor (3-hop)
- Cert checking: **refuses to connect** if certificate is known-bad (unless manually allowed)
- Kill switch: auto-enabled
- Config encryption: AES-256-GCM tied to machine hardware ID

Best for: journalists, activists, high-risk users. Slow but maximally private.

```
blackout mode legend
blackout tools cert-check myvpnserver.com          ← check cert first
blackout tools cert-check myvpnserver.com --allow  ← if self-signed, manually trust it
blackout connect xray
```

---

## Settings Reference

Run `blackout settings list` to see all 90+ settings. Key ones:

| Setting | Default | Description |
|---------|---------|-------------|
| `security_mode` | `speed` | Active security mode |
| `xray_socks_port` | `10808` | XRay SOCKS5 proxy port |
| `xray_http_port` | `10809` | XRay HTTP proxy port |
| `xray_fingerprint` | `chrome` | TLS fingerprint (chrome/firefox/random) |
| `xray_mux_enabled` | `false` | Enable connection multiplexing |
| `sni_listen_port` | `40443` | SNI spoofer listen port |
| `sni_connect_ip` | `""` | Best Cloudflare IP (set after scanning) |
| `sni_fake_sni` | `www.hcaptcha.com` | Fake SNI domain to inject |
| `auto_set_proxy` | `true` | Auto-configure Windows system proxy |
| `engine_order` | `[]` | Emergency mode engine order (empty = country profile default) |
| `country` | `""` | Pinned country code (empty = auto-detect) |
| `kill_switch` | `false` | Block all non-proxy traffic |
| `wg_config_file` | `""` | Path to WireGuard .conf file |
| `openvpn_config` | `""` | Path to .ovpn file |
| `ikev2_server` | `""` | IKEv2 VPN server address |
| `softether_host` | `""` | SoftEther server hostname |
| `psiphon_egress_country` | `""` | Psiphon exit country code |

---

## How It Works

### SNI Spoofing & TCP Fragmentation (Iran/Iraq)

Iran's TIC uses hardware DPI at the internet gateway. It reads the **SNI field** in the TLS ClientHello to identify which site you're connecting to.

Blackout Kit defeats this with **TCP Fragmentation**:

```
[Your App]
    │
    ▼
[XRay — SOCKS5 :10808]
    │  Trojan/VLESS over TLS
    ▼
[SNI Spoofer — :40443]
    │
    ├─── Shredded ClientHello ──► [Cloudflare IP :443]
    │    (Fragmented into 10-byte chunks)
    │
    └─── Real TLS Handshake ► [Cloudflare IP :443]
         SNI = "your-actual-server.com"    DPI: cannot reassemble SNI
```

The TLS ClientHello is intercepted and shredded into tiny 10-byte TCP segments before being sent. Because Go's TCP stack sends them instantly without artificial lag, the connection is lightning fast. The hardware DPI cannot reassemble the fragmented packets in real-time and lets the traffic pass, while the destination server perfectly reconstructs the TLS handshake.

### GoodbyeDPI (UK / Light DPI)

Fragments TCP packets at the IP layer so the DPI engine receives split packets and cannot reconstruct the SNI field for inspection. Works against simple stateless DPI that doesn't reassemble packets.

> Note: Does NOT work against Iran's TIC (2025+). Their hardware does full TCP reassembly before SNI inspection.

### Emergency Mode

When a normal `connect` fails, `emergency` tries engines in order:

```
1. sni      → failed (blocked)
2. gdpi     → failed (reassembly DPI)
3. warp     → failed (IP blocked)
4. psiphon  ← CONNECTED ✓
```

The order defaults to your country's recommended profile but can be overridden:

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

**Always share the `blackout.exe` version with people who need it RIGHT NOW.** The Source version is for developers and people who install it before a crisis.

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

The server's TLS certificate failed strict validation. You have two options:

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

### DNS not resolving after disconnecting

```
blackout tools dns-flush
blackout tools netfix
```

### Country not detected correctly

```
blackout country
blackout country set IR   ← pin manually
```

---

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full version plan.

Highlights coming in **v1.1**:
- **Hysteria2** — QUIC-based protocol, extremely hard to block
- **TUIC** — Low-latency QUIC tunnel
- **TLS Record-Layer Fragmentation** — Fragment at TLS level, not TCP. Overwhelms Iran's DPI hardware.
- **`blackout connect --iran`** — One-flag profile: ArvanCloud SNI + TLS fragment + Firefox fingerprint
- **DoH bootstrapping** — Resolve proxy server via DNS-over-HTTPS before connecting

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
