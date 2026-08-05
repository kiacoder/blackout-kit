# Blackout Kit — Full Roadmap & TODO

Items marked ✅ are implemented. Ranks: Common → Uncommon → Rare → Epic → Legendary → Myth

---

## 🛡️ AUDIT & HARDENING (v1.0.1)

| Feature | Status | Rank | Notes |
|---------|--------|------|-------|
| 10-Agent Autonomous Audit | ✅ Done | Epic | Full codebase review |
| Fix Zip Slip Path Traversal | ✅ Done | Critical | `updater.py` |
| Fix Subprocess Deadlocks | ✅ Done | High | `DEVNULL` instead of `PIPE` |
| Localization-Independent Parsing | ✅ Done | High | `psutil` & `PowerShell` in `tools.py` |
| Graceful Go Engine Shutdowns | ✅ Done | High | Prevents routing/DNS corruption |
| Concurrent Cache Safety | ✅ Done | Med | Atomic `replace()` |
| Windows UAC Awareness | ✅ Done | Med | Admin checks in network tools |

---

## 🛡️ BYPASS ENGINES

| Feature | Status | Rank | Notes |
|---------|--------|------|-------|
| SNI Spoofing (TCP Sequence Injection) | ✅ Done | Epic | patterniha's engine — core bypass for Iran 2026 |
| XRay-core (Trojan + VLESS over TLS) | ✅ Done | Epic | Dynamic config generation |
| GoodbyeDPI (TCP fragmentation) | ✅ Done | Rare | Legacy backend is the stable default; native Go backend is experimental |
| Psiphon multi-protocol | ✅ Done | Rare | Germany exit node |
| Cloudflare WARP | ✅ Done | Rare | warp-plus, reduces captchas |
| Tor / Onion routing | ✅ Done | Rare | SOCKS5 :9050 |
| TUN mode (sing-box) | ✅ Done | Rare | Tunnels ALL apps, not just proxy-aware ones |
| IKEv2 / L2TP / SSTP / PPTP | ✅ Done | Rare | Windows built-in VPN, no extra binary |
| WireGuard (real monitoring) | ✅ Done | Epic | Real sc query thread, no fake sentinel |
| OpenVPN (startup verified) | ✅ Done | Epic | Reads log for "Initialization Sequence Completed" |
| SoftEther (real monitoring) | ✅ Done | Epic | vpncmd AccountStatusGet polling |
| mhrv (Rust MITM proxy) | ✅ Done | Rare | HTTP :8085 / SOCKS :8086 |
| Google Apps Script relay | ✅ Done | Rare | Domain-fronts through script.google.com, 20 relay IDs, pure Python |
| **Hysteria 2** | ✅ Done | Rare | QUIC-based proxy via sing-box, selectable as `hysteria2` |
| **TUIC** | ✅ Done | Rare | Low-latency QUIC tunnel via sing-box, selectable as `tuic` |
| **XRay REALITY protocol** | 🔜 v1.2 | — | Mimics legitimate HTTPS to microsoft.com/etc perfectly. Undetectable. |
| **ShadowTLS** | 🔜 v1.2 | — | Makes traffic look like real TLS to a real server |
| **ShadowSocks + Obfs4** | 🔜 v1.2 | — | Via sing-box |
| **XTLS Direct Read/Write** | 🔜 v1.3 | — | Zero-overhead XRay performance mode |
| **ECH (Encrypted Client Hello)** | 🔜 future | — | Hides SNI completely at TLS layer — experimental |

---

## 🇮🇷 IRAN-SPECIFIC EVASION (TIC 2026)

Iran operates centralized "chokepoint" DPI at TIC gateways.
During unrest they switch to White List mode (NIN — National Information Network).
Standard TCP fragmentation NO LONGER WORKS — their hardware reassembles TCP before inspecting SNI.

| Feature | Status | Rank | Notes |
|---------|--------|------|-------|
| TCP Sequence Injection (out-of-window decoy) | ✅ Done | Epic | SNI spoofer's core mechanism |
| uTLS / JA3 fingerprint camouflage | ✅ Done | Rare | `xray_fingerprint = firefox` in PRIVATE mode |
| Fake SNI (www.hcaptcha.com / auth.vercel.com) | ✅ Done | Rare | DPI sees whitelisted domain |
| ArvanCloud / Aparat CDN SNI camouflage | 🔜 v1.1 | — | Iran can't block ArvanCloud (their own CDN), spoof SNI to look like arvancloud.ir |
| **TLS Record-Layer Fragmentation** | 🔜 v1.1 | — | Fragment at TLS layer, NOT TCP — overwhelms Iran's DPI reassembly. XRay `fragment` mode. HIGH PRIORITY |
| **`blackout connect --iran` profile** | ✅ Done | Rare | One-command Iran profile: ArvanCloud SNI + firefox fingerprint + private mode + existing fragment settings |
| **DoH bootstrapping at startup** | 🔜 v1.1 | — | Use 1.1.1.1/dns-query BEFORE connecting so DNS poisoning can't intercept server lookup |
| Active probing resistance | 🔜 v1.2 | — | Respond correctly to probes so firewall can't fingerprint the server |
| Iran White List mode survival (NIN) | 🔜 v1.2 | — | Fall back to ArvanCloud/domestic CDN fronting when NIN is active |

---

## 🔒 PRIVACY & SECURITY

| Feature | Status | Rank | Notes |
|---------|--------|------|-------|
| Security modes (Speed / Private / LEGEND) | ✅ Done | Rare | `blackout mode speed\|private\|legend` |
| Kill switch (Windows Firewall) | ✅ Done | Rare | Blocks ALL traffic if proxy drops |
| Config obfuscation (XOR + base64) | ✅ Done | Uncommon | Not real encryption — shoulder-surf protection only |
| Windows Defender exclusion | ✅ Done | Rare | `blackout doctor --fix-av` |
| Stability tracking (latency + trend) | ✅ Done | Rare | Per-engine history |
| Multi-hop (XRay → Tor) | ✅ Done | Rare | LEGEND mode |
| uTLS fingerprint enforcement | ✅ Done | Rare | Via XRay xray_fingerprint setting |
| **DoH bootstrapping** | 🔜 v1.1 | — | Must resolve proxy server IP via DoH, not system DNS |
| **True config encryption (AES-256)** | 🔜 v1.2 | — | Replace XOR obfuscation with real AES-GCM |
| **Triple-hop / Cascaded VPN** | 🔜 v1.2 | — | Chain 3+ proxies |
| **WebRTC + IPv6 leak protection** | 🔜 v1.2 | — | Windows Firewall rules |
| **DNS over QUIC (DoQ)** | 🔜 v1.2 | — | Faster than DoH |
| **Process-level split tunneling** | 🔜 v1.2 | — | Route per-app via WFP driver |
| **PFS enforcement** | 🔜 v1.3 | — | Already in TLS 1.3, but force-require it |
| **Post-Quantum Cryptography (PQC)** | 🔜 future | — | Kyber (experimental in XRay) |

---

## 🔧 SELF-HEALING & NETWORK REPAIR

| Feature | Status | Rank | Notes |
|---------|--------|------|-------|
| Doctor (self-diagnosis + auto-fix) | ✅ Done | Rare | `blackout doctor [--fix]` |
| Winsock + TCP/IP stack reset | ✅ Done | Rare | `blackout tools netfix` |
| DNS flush | ✅ Done | Rare | `blackout tools dns-flush` |
| DNS preset switching | ✅ Done | Rare | Cloudflare / Shecan / Electro / 403 / Begzar |
| Network adapter list | ✅ Done | Uncommon | `blackout tools adapters` |
| MTU detection | ✅ Done | Uncommon | `blackout tools mtu` |
| Ping + traceroute | ✅ Done | Uncommon | TCP-based |
| Hotspot sharing | ✅ Done | Uncommon | Windows Mobile Hotspot toggle |
| ICS (share VPN over hotspot) | ✅ Done | Uncommon | Internet Connection Sharing |
| **`blackout fix` shorthand** | ✅ Done | Rare | One command runs the core network repair steps with a live Rich checklist |
| **TUN/TAP / Wintun driver reset** | 🔜 v1.1 | — | Force restart virtual adapter when TUN crashes (DPI connection drops can lock it) |
| **Stale routing table flush** | 🔜 v1.1 | — | `route -f` to clear zombie proxy routes left after crash |
| **DNS hijack recovery** | 🔜 v1.1 | — | Detect if DNS is still pointing to dead 127.0.0.1, auto-restore |
| **Real-time fixer checklist** | 🔜 v1.1 | — | Rich live checklist that ticks off each repair step as it runs |
| **Auto-reconnect with backoff** | 🔜 v1.1 | — | Daemon retries with exponential backoff instead of fixed interval |
| **Certificate store cleanup** | 🔜 v1.2 | — | Remove stale mhrv CA certs after uninstall |
| **ARP table flush** | 🔜 v1.2 | — | Clear ARP cache if LAN routing breaks |

---

## 🖥️ CLI / UX — GEMINI REDESIGN

> Gemini recommends full migration from argparse → Typer + Rich interactive menus.
> "Normal users should never have to type a flag."

| Feature | Status | Rank | Notes |
|---------|--------|------|-------|
| Rich terminal output (colors, tables, panels) | ✅ Done | Rare | Already looks good |
| ASCII banner + spinner animations | ✅ Done | Rare | On startup and long operations |
| argparse-based commands | ✅ Done | Uncommon | Works but not beginner-friendly |
| **Typer migration** | 🔜 v1.1 | — | Replace argparse with Typer: type-safe, auto-help, cleaner code |
| **Interactive dashboard (Zero-Flag mode)** | ✅ Done | Rare | `blackout` with no args opens a keyboard-driven menu for common actions |
| **`blackout connect` smart command** | 🔜 v1.1 | — | Auto-selects best engine + connects. One word, done. |
| **`blackout connect --iran`** | ✅ Done | Rare | Forces TIC evasion profile: arvancloud.ir SNI + firefox fingerprint + existing fragment settings |
| **`blackout fix`** | ✅ Done | Rare | One command runs the core network repair steps with a live Rich checklist |
| **Global exception handler** | 🔜 v1.1 | — | No raw Python tracebacks EVER. All errors caught → Rich red Panel → offer auto-fix |
| **Rich.Prompt interactive menus** | 🔜 v1.1 | — | User can answer questions instead of typing flags |
| **Real-time status panel** | 🔜 v1.2 | — | Live updating: IP, latency, engine, bytes transferred |
| **Smart-routing dashboard** | 🔜 v1.2 | — | Auto-switch to best available engine |
| **Dark/Light theme toggle** | 🔜 v1.2 | — | Rich theme switching |
| **Tauri desktop app** | 🔜 future | — | Optional GUI wrapper |
| **Tray integration** | 🔜 future | — | System tray icon + quick connect |

---

## ⚡ PERFORMANCE & SPEED

| Feature | Status | Rank | Notes |
|---------|--------|------|-------|
| Async IP scanner (100 concurrent) | ✅ Done | Rare | asyncio-based |
| IP scan cache (12h TTL) | ✅ Done | Rare | Offline-first |
| **Lazy CLI imports** | 🔜 v1.1 | — | Import engine only when used → startup ~800ms → ~200ms |
| **KNOWN_GOOD_IPS scan first** | 🔜 v1.1 | — | Try pre-tested IPs before full scan |
| **Parallel engine startup** | 🔜 v1.1 | — | Start SNI + XRay threads simultaneously |
| **Binary detection cache** | 🔜 v1.1 | — | Don't re-scan bins/ on every command |
| **Persistent daemon IPC socket** | 🔜 v1.2 | — | Replace PID file polling with proper socket |
| **Compressed GAS relay** | 🔜 v1.2 | — | gzip responses → less bandwidth |
| **Connection pooling in proxy tester** | 🔜 v1.2 | — | Reuse TCP connections |

---

## 🌍 PLATFORM SUPPORT

| Feature | Status | Rank | Notes |
|---------|--------|------|-------|
| Windows 10/11 | ✅ Done | Epic | Full support |
| WSL (Ubuntu on Windows) | ✅ Done | Uncommon | Partial (no WinDivert, no Firewall rules) |
| **Linux native (iptables)** | 🔜 v1.2 | — | Kill switch + TUN routing for Linux |
| **macOS (pf firewall)** | 🔜 future | — | Kill switch + proxy |
| **Russia TSPU evasion** | 🔜 far future | — | VLESS + REALITY, avoid TUN interfaces (Russian apps scan for VPN), TSPU hardware jamming workarounds |

---

## 📊 ANALYTICS & MONITORING

| Feature | Status | Rank | Notes |
|---------|--------|------|-------|
| Stability tracking (latency + loss% + trend) | ✅ Done | Rare | Per-engine, stored in stability.json |
| Speed test (Cloudflare) | ✅ Done | Uncommon | `blackout tools speedtest` |
| **Real-time latency graph** | 🔜 v1.1 | — | Live terminal graph during connection |
| **Connection event log** | 🔜 v1.2 | — | Timestamped connect/disconnect history |
| **Data transferred counter** | 🔜 v1.2 | — | Show total bytes proxied |
| **Node health auto-check** | 🔜 v1.1 | — | Ping all saved V2Ray configs, sort by speed |

---

## 🗓️ VERSION TARGETS

| Version | Focus | Key items |
|---------|-------|-----------|
| **v1.0** (current) | Core foundation | All engines, security modes, doctor, neighbor, preflight, Apps Script relay |
| **v1.1** (next) | Iran 2026 hardening + UX | Hysteria2, TUIC, TLS fragment, ArvanCloud SNI, DoH, Typer, interactive menu, `blackout connect/fix`, real fixer checklist |
| **v1.2** | Advanced privacy + polish | REALITY, ShadowTLS, triple-hop, process split tunnel, Linux, smart routing, real-time dashboard |
| **v1.3** | Performance + hardening | XTLS, lazy imports, PFS, AES-256 configs, persistent IPC |
| **far future** | GUI + Russia + exotic protocols | Tauri, tray, Russia TSPU, ECH, PQC, macOS |

---

*Community-driven. Open an issue to suggest features or report what's blocked in your region.*
