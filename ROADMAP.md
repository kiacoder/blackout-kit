# Blackout Kit — Full Roadmap & TODO

Items marked ✅ are implemented. Ranks follow the project scale: Common → Uncommon → Rare → Unique → Epic → Heroic → Legendary → Myth.

---

## 🛡️ AUDIT & HARDENING (v1.0.1)

| Feature | Status | Rank | Notes |
|---------|--------|------|-------|
| 10-Agent Autonomous Audit | ✅ Done | Epic | Full codebase review |
| Fix Zip Slip Path Traversal | ✅ Done | Heroic | `updater.py` |
| Fix Subprocess Deadlocks | ✅ Done | Epic | `DEVNULL` instead of `PIPE` |
| Localization-Independent Parsing | ✅ Done | Epic | `psutil` & `PowerShell` in `tools.py` |
| Graceful Go Engine Shutdowns | ✅ Done | Epic | Prevents routing/DNS corruption |
| Concurrent Cache Safety | ✅ Done | Rare | Atomic `replace()` |
| Windows UAC Awareness | ✅ Done | Rare | Admin checks in network tools |

---

## 🛡️ BYPASS ENGINES

Windows exposes the full engine catalog below. Linux x86_64 supports only XRay,
XRay → sing-box TUN, Hysteria2, and TUIC through the managed `blackout-engine`
runner; availability still depends on local prerequisites and a compatible saved
configuration.

| Feature | Status | Rank | Notes |
|---------|--------|------|-------|
| SNI Spoofing (TCP Sequence Injection) | ✅ Done | Epic | Windows-local SNI component; network effectiveness varies |
| XRay-core (Trojan + VLESS, TLS and REALITY) | ✅ Done | Epic | Dynamic transport-aware config generation; REALITY is client-side only |
| GoodbyeDPI (Windows TCP handling) | ✅ Done | Rare | Legacy backend is the stable default; native Go/WinDivert backend is experimental |
| Psiphon multi-protocol | ✅ Done | Rare | Windows Psiphon Tunnel Core path with configured country preference |
| Cloudflare WARP | ✅ Done | Rare | Windows WARP client path using warp-plus |
| Tor / Onion routing | ✅ Done | Rare | Local SOCKS5 listener on :9050 when the supplied Tor runtime starts |
| TUN mode | ✅ Done | Rare | Windows runs sing-box; Linux uses XRay → sing-box through the managed runner |
| IKEv2 / L2TP / SSTP / PPTP | ✅ Done | Rare | Windows built-in VPN, no extra binary |
| WireGuard (real monitoring) | ✅ Done | Epic | Real sc query thread, no fake sentinel |
| OpenVPN (startup verified) | ✅ Done | Epic | Reads log for "Initialization Sequence Completed" |
| SoftEther (real monitoring) | ✅ Done | Epic | vpncmd AccountStatusGet polling |
| mhrv (embedded HTTP GAS relay) | ✅ Done | Rare | HTTP :8085; HTTPS CONNECT is intentionally unsupported |
| Google Apps Script relay | ✅ Done | Rare | HTTP relay through configured Google Apps Script endpoints; HTTPS CONNECT is unsupported |
| **Hysteria 2** | ✅ Done | Rare | QUIC proxy through sing-box from a compatible saved configuration, selectable as `hysteria2` |
| **TUIC** | ✅ Done | Rare | QUIC proxy through sing-box from a compatible saved configuration, selectable as `tuic` |
| **XRay client-side VLESS REALITY** | ✅ Done | Rare | Imports standard VLESS REALITY URIs for XRay/TUN; it does not provide server setup, anonymity, or a detection-resistance guarantee. |
| **ShadowTLS** | 🔜 v1.2 | — | Evaluate a verified ShadowTLS configuration path |
| **ShadowSocks + Obfs4** | 🔜 v1.2 | — | Evaluate sing-box support and interoperability |
| **XTLS Direct Read/Write** | 🔜 v1.3 | — | Evaluate XRay performance-mode support and safety boundaries |
| **ECH (Encrypted Client Hello)** | 🔜 future | — | Research experimental client support and network compatibility |

---

## 🇮🇷 IRAN-SPECIFIC EVASION (TIC 2026)

Iran operates centralized "chokepoint" DPI at TIC gateways.
During unrest they switch to White List mode (NIN — National Information Network).
Standard TCP fragmentation NO LONGER WORKS — their hardware reassembles TCP before inspecting SNI.

| Feature | Status | Rank | Notes |
|---------|--------|------|-------|
| TCP Sequence Injection (out-of-window decoy) | ✅ Done | Epic | SNI spoofer's core mechanism |
| XRay fingerprint setting | ✅ Done | Rare | PRIVATE applies a random XRay fingerprint; it does not guarantee camouflage or bypass |
| Configurable fake SNI | ✅ Done | Rare | Windows SNI stack supports a configured local fake-SNI value; network effectiveness varies |
| `blackout connect --iran` profile | ✅ Done | Rare | Applies documented local XRay/SNI settings while respecting an existing custom fake SNI |
| **TLS Record-Layer Fragmentation** | ✅ Done | Rare | XRay `fragment` mode is generated from `xray_fragment` |
| **DoH bootstrapping at startup** | ✅ Done | Rare | Resolves XRay proxy hosts through Cloudflare DoH before connection |
| Active probing resistance | 🔜 v1.2 | — | Research verified server-side approaches; no client-only guarantee |
| Iran White List mode survival (NIN) | 🔜 v1.2 | — | Research network-specific fallback options; availability cannot be assumed |

---

## 🔒 PRIVACY & SECURITY

| Feature | Status | Rank | Notes |
|---------|--------|------|-------|
| Security modes (Speed / Private / LEGEND) | ✅ Done | Rare | `blackout mode speed\|private\|legend` |
| Kill switch (Windows Firewall / Linux nftables) | ✅ Done | Rare | Endpoint-scoped Linux rules with iptables fallback |
| Config encryption (AES-256-GCM) | ✅ Done | Rare | Machine-derived local encryption; not portable and not a replacement for device security |
| Windows Defender exclusion | ✅ Done | Rare | `blackout doctor --fix-av` |
| Stability tracking (latency + trend) | ✅ Done | Rare | Per-engine history |
| Multi-hop (XRay → Tor) | 🔜 v1.2 | — | Requires an explicit verified chain implementation before being documented as available |
| XRay fingerprint setting | ✅ Done | Rare | Configures the XRay fingerprint; it does not guarantee anti-fingerprinting results |
| **DoH bootstrapping** | ✅ Done | Rare | Resolves configured XRay proxy hosts through DoH before connection when required |
| **Config encryption** | ✅ Done | Rare | AES-256-GCM encryption with a machine-derived key; not portable |
| **Triple-hop / Cascaded VPN** | 🔜 v1.2 | — | Chain 3+ proxies |
| **WebRTC + IPv6 leak protection** | 🔜 v1.2 | — | Windows Firewall rules |
| **DNS over QUIC (DoQ)** | 🔜 v1.2 | — | Faster than DoH |
| **Process-level split tunneling** | 🔜 v1.2 | — | Route per-app via WFP driver |
| **PFS policy review** | 🔜 v1.3 | — | Document protocol-specific forward-secrecy properties and configuration limits |
| **Post-Quantum Cryptography (PQC)** | 🔜 future | — | Research upstream support and compatibility before exposing a setting |

---

## 🔧 SELF-HEALING & NETWORK REPAIR

| Feature | Status | Rank | Notes |
|---------|--------|------|-------|
| Doctor (self-diagnosis + auto-fix) | ✅ Done | Rare | `blackout doctor [--fix]` |
| Winsock + TCP/IP stack reset | ✅ Done | Rare | Explicit `blackout fix --full-stack-reset` emergency option |
| DNS flush | ✅ Done | Rare | `blackout tools dns-flush` |
| DNS preset switching | ✅ Done | Rare | Cloudflare / Shecan / Electro / 403 / Begzar |
| Network adapter list | ✅ Done | Uncommon | `blackout tools adapters` |
| MTU detection | ✅ Done | Uncommon | `blackout tools mtu` |
| Ping + traceroute | ✅ Done | Uncommon | TCP-based |
| Hotspot sharing | ✅ Done | Uncommon | Windows Mobile Hotspot toggle |
| ICS guidance (share VPN over hotspot) | ✅ Done | Uncommon | Detects an eligible Windows adapter and prints manual ICS steps; it does not configure ICS |
| **`blackout fix` shorthand** | ✅ Done | Rare | One command runs the core network repair steps with a live Rich checklist |
| **TUN/TAP / Wintun driver reset** | ✅ Done | Rare | `blackout fix` restarts only its stale deterministic `BlackoutKit-TUN` adapter; physical, WireGuard, and third-party adapters are excluded |
| **Stale routing table flush** | ✅ Done | Rare | Default removes only stale Blackout virtual-adapter routes; `--full-route-reset` keeps `route -f` explicit |
| **DNS hijack recovery** | ✅ Done | Rare | Restores DHCP DNS only on connected physical adapters still pointed at loopback DNS |
| **Real-time fixer checklist** | ✅ Done | Rare | `blackout fix` shows a live Rich checklist for each repair step |
| **Auto-reconnect with backoff** | ✅ Done | Rare | Daemon retries with cancellable capped exponential backoff; targeted daemon recovery preserves proxy/routes outside Blackout ownership |
| **Certificate store cleanup** | N/A | — | mhrv is an HTTP relay and never creates, trusts, or installs a CA certificate |
| **ARP / neighbor cache flush** | ✅ Done | Rare | Explicit only: `tools arp-flush` or `fix --flush-arp`; never daemon recovery |

---

## 🖥️ CLI / UX — GEMINI REDESIGN

> Gemini recommends full migration from argparse → Typer + Rich interactive menus.
> "Normal users should never have to type a flag."

| Feature | Status | Rank | Notes |
|---------|--------|------|-------|
| Rich terminal output (colors, tables, panels) | ✅ Done | Rare | Already looks good |
| ASCII banner + spinner animations | ✅ Done | Rare | On startup and long operations |
| argparse-based commands | ✅ Done | Uncommon | Works but not beginner-friendly |
| **Typer migration** | ✅ Done | Rare | Typer is the public command entrypoint and delegates to the proven dispatcher |
| **Interactive dashboard (Zero-Flag mode)** | ✅ Done | Rare | `blackout` with no args opens a keyboard-driven menu for common actions |
| **`blackout connect` smart command** | ✅ Done | Rare | Uses the highest locally ready recommendation unless an engine is explicit |
| **`blackout connect --iran`** | ✅ Done | Rare | Applies documented local profile settings; it does not guarantee bypass success |
| **`blackout fix`** | ✅ Done | Rare | One command runs the core network repair steps with a live Rich checklist |
| **Global exception handler** | ✅ Done | Rare | Redacted Rich error panel with safe local diagnostic guidance |
| **Rich.Prompt interactive menus** | ✅ Done | Rare | Prompts only in interactive terminals; explicit CLI arguments remain script-safe |
| **Real-time status panel** | ✅ Done | Rare | Read-only `blackout status --watch`: daemon, local ports, stability, and reconnect state |
| **Smart-routing dashboard** | ✅ Done | Rare | `blackout route` ranks local readiness/history; `connect auto` uses its recommendation |
| **Dark/Light theme toggle** | ✅ Done | Rare | Persistent Blackout Kit Rich palette only; host-terminal and GUI settings stay unchanged |
| **Tauri desktop app** | 🔜 future | — | Optional GUI wrapper |
| **Tray integration** | 🔜 future | — | System tray icon + quick connect |

---

## ⚡ PERFORMANCE & SPEED

| Feature | Status | Rank | Notes |
|---------|--------|------|-------|
| Async IP scanner (100 concurrent) | ✅ Done | Rare | asyncio-based |
| IP scan cache (12h TTL) | ✅ Done | Rare | Offline-first |
| **Lazy CLI imports** | 🔜 v1.2 | — | Import engine only when used → startup ~800ms → ~200ms |
| **KNOWN_GOOD_IPS scan first** | 🔜 v1.2 | — | Try pre-tested IPs before full scan |
| **Parallel engine startup** | 🔜 v1.2 | — | Start SNI + XRay threads simultaneously |
| **Binary detection cache** | 🔜 v1.2 | — | Don't re-scan bins/ on every command |
| **Persistent daemon IPC socket** | 🔜 v1.2 | — | Replace PID file polling with proper socket |
| **Compressed GAS relay** | 🔜 v1.2 | — | gzip responses → less bandwidth |
| **Connection pooling in proxy tester** | 🔜 v1.2 | — | Reuse TCP connections |

---

## 🌍 PLATFORM SUPPORT

| Feature | Status | Rank | Notes |
|---------|--------|------|-------|
| Windows 10/11 | ✅ Done | Epic | Broad engine catalog; individual engines retain their own runtime and privilege prerequisites |
| WSL (Ubuntu on Windows) | ✅ Done | Uncommon | Linux runtime subset where WSL supports required TUN/firewall commands; no WinDivert or Windows Firewall integration |
| **Linux native (x86_64)** | ✅ Done | Rare | Ubuntu/Debian, Fedora, Arch: XRay, XRay → sing-box TUN, Hysteria2, and TUIC through blackout-engine; endpoint-scoped nftables/iptables kill switch |
| **macOS (pf firewall)** | 🔜 future | — | Kill switch + proxy |
| **Russia TSPU research** | 🔜 far future | — | Assess regional constraints and supported upstream configurations before promising a bypass path |

---

## 📊 ANALYTICS & MONITORING

| Feature | Status | Rank | Notes |
|---------|--------|------|-------|
| Stability tracking (latency + loss% + trend) | ✅ Done | Rare | Per-engine, stored in stability.json |
| Speed test (Cloudflare) | ✅ Done | Uncommon | `blackout tools speedtest` |
| **Real-time latency graph** | 🔜 v1.2 | — | Live terminal graph during connection |
| **Connection event log** | 🔜 v1.2 | — | Timestamped connect/disconnect history |
| **Data transferred counter** | 🔜 v1.2 | — | Show total bytes proxied |
| **Node health auto-check** | 🔜 v1.2 | — | Ping all saved V2Ray configs, sort by speed |

---

## 🗓️ VERSION TARGETS

| Version | Focus | Key items |
|---------|-------|-----------|
| **v1.1.1** (current) | Release stabilization | Installable package, standalone executable, CLI parity, Linux x86_64 managed runner, local route/status/theme UX, targeted recovery, and client-side VLESS REALITY |
| **v1.2** (next) | Advanced transport + monitoring | ShadowTLS, process-level split tunneling, and real-time monitoring work |
| **v1.3** | Performance + hardening | XTLS, lazy imports, persistent IPC, and remaining performance improvements |
| **far future** | GUI + Russia + exotic protocols | Tauri, tray, Russia TSPU, ECH, PQC, macOS |

---

*Community-driven. Open an issue to suggest features or report what's blocked in your region.*
