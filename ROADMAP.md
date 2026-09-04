# Blackout Kit — Roadmap

> **Vision:** A complete network toolkit that a network engineer like NetworkChuck would love to use.
> Not just a VPN. Not just cybersecurity. A Swiss army knife for networking — traffic management,
> network analysis, antivirus, download management, and security hardening, all in one tool.

---

## Where we are now

### Shipped: VPN/bypass engine (1.1.x — 1.2.x)

| Feature | Status | Notes |
|---|---|---|
| SNI / XRay / REALITY | Done | VLESS, Trojan, VMess on Windows + Linux |
| Hysteria2 / TUIC | Done | sing-box proxy via DLL or Linux runner |
| AmneziaWG | Done | Obfuscated WireGuard via sing-box |
| TUN mode | Done | Windows + Linux |
| GoodbyeDPI | Done | `legacy` default, `native` experimental |
| WARP / Psiphon | Done | Windows DLL-backed |
| Country profiles | Done | IR, RU, CN, IQ, GB, US, EU |
| `--iran` / `--russia` presets | Done | Temporary env-based overrides |
| XHTTP transport | Done | `type=xhttp` + legacy `splithttp` |
| Smart config rotation | Done | Auto-rotate on blocked IP |
| Data-phase drop detection | Done | TCP open but HTTP dead → rotate |
| Whitelist awareness | Done | Doctor checks Russian cellular whitelist |
| Country-aware routing | Done | Yandex/VK/Ozon direct for RU |
| Kill switch (Linux) | Done | Endpoint-scoped nftables/iptables |
| Encrypted vault | Done | AES-256-GCM machine-bound storage |
| Crash recovery | Done | Targeted, Blackout-owned state cleanup |
| MCP server | Done | Constrained stdio tool surface |
| Desktop GUI | Done | Windows CustomTkinter |
| Route dashboard | Done | Local-only engine recommendation |
| Doctor diagnostics | Done | Full environment + runtime checks |

**VPN/bypass work is finished.** No new bypass engines planned. Existing capabilities stay.

---

## Where we're going

### Phase 1: Network analysis & diagnostics (1.3.x)

The tools NetworkChuck uses every day, built into one CLI/GUI:

| Feature | What it does | Why Chuck would love it | Status |
|---|---|---|---|
| Port scanner | Scan networks for open ports (like nmap-lite) | "Know what's listening on your network" | **Done** — `blackout tools scan-ports <host> [--ports ...]` |
| Network discovery | Map devices on your LAN, show IPs/MACs/hostnames | "Who's on my network?" | **Done** — `blackout tools discover` |
| Connection table | Live TCP/UDP connection table with process attribution | "What is my computer connected to right now?" | **Done** — `blackout tools connections [--established]` |
| DNS inspector | Compare system DNS vs. a trusted resolver, surface poisoning signals | "Is someone messing with my DNS?" | **Done** — `blackout tools dns-inspect` |
| Subnet Calculator | Instantly print network range, broadcast, min/max hosts | "Never do subnet math in your head again" | **Done** — `blackout tools subnet <cidr>` |
| Speedtest History | Visual terminal graph of speedtests over time | "Prove your ISP is throttling you at 8 PM" | **Done** — `blackout tools speedtest-history` (auto-recorded on every `speedtest` run) |
| Latency monitor | Continuous ping with live rolling avg/jitter/loss graph | "Is my internet getting worse?" | **Done** — `blackout tools latency-monitor [host] [--interval]` |
| Bandwidth monitor | Real-time per-interface upload/download throughput | "What's eating my bandwidth?" | **Done** — `blackout tools bandwidth [--interval]` (per-interface, not yet per-process) |
| Packet capture + analysis | Capture and inspect network traffic (like Wireshark-lite) | "Look at your packets without leaving the terminal" | **Done** — `blackout tools capture [iface] [--count] [--filter] [--host]` |

### Phase 2: Traffic, downloads & sharing (1.4.x)

| Feature | What it does | Why it matters | Status |
|---|---|---|---|
| Download manager | Multi-threaded downloads with resume, queue, and speed limits | Download queue & rate limits | **Done** — `blackout download add/list/start/cancel/watch` |
| Video/Media extraction | Built-in wrapper for raw media extraction (yt-dlp style) | Extract video & audio streams | **Done** — `blackout media add/list/watch/cancel/clear` |
| Torrent/Magnet support | Lightweight terminal-based torrent client | Peer-to-peer torrent manager | **Done** — `blackout torrent add/list/watch/cancel/seed/clear` |
| Monitor-only QoS | Persist and inspect app/protocol/port/interface rule metadata | Traffic classification & rules | **Done** — `blackout tools qos rules/stats/mode/violations` |
| Bandwidth caps | Set daily/monthly limits per interface | Quota alerts & usage management | **Done** — `blackout tools bandwidth-cap set/list/stats/remove` |
| Traffic logging | Persistent log of network usage by app/protocol/time | Usage audit log | **Done** — `blackout tools traffic-log list/stats/hourly/clear/prune/info` |
| Network-level ad blocking | DNS-based ad/tracker blocking (like Pi-hole-lite) | Domain blocklists & DNS sinkhole | **Done** — `blackout tools adblock sources/custom/whitelist/status/stats/log/update` |
| Setup export/import | Share your exact config, DNS, and engine state via one string | Config sharing | **Done** — `blackout config export` / `blackout config import-setup <string>` |
| LAN IP Cache sharing | Share a 40ms Cloudflare IP with neighbors over LAN | Peer-to-peer IP sharing | **Done** — `blackout neighbor cache-list/refresh/clear` |

### Phase 3: Antivirus & security hardening (1.5.x)

| Feature | What it does | Why it matters | Status |
|---|---|---|---|
| File scanner | Scan files with the installed Windows Defender CLI | Local file malware verification | **Done** — `blackout tools scan-file <path>` |
| Local SHA-256 fingerprint | Stream a local file and report a cryptographic fingerprint | Cryptographic file validation | **Done** — `blackout tools file-hash <path>` |
| MAC Address Spoofer | Inspect, randomize, and restore active Wi-Fi MAC | Privacy on public networks | **Done** — `blackout tools mac status/randomize/restore` |
| Global Panic Button 🚨 | Sever ALL network connections on the PC instantly | The ultimate killswitch | **Done** — `blackout panic` / `blackout tools panic` |
| Network Hardening Audit 🛡️ | Check firewall rules, open ports, exposed services, weak configs | "Is my system actually secure?" | **Done** — `blackout tools audit` |
| Public Wi-Fi Honeypot 🐝 | Open fake ports to detect if someone on cafe Wi-Fi is scanning you | "192.168.1.14 is scanning your computer" | **Done** — `blackout tools honeypot` |
| Secure DoH/DoT DNS Proxy 🌐 | Local DNS-over-HTTPS / DNS-over-TLS proxy resolver | Stop DNS poisoning / eavesdropping | **Done** — `blackout tools dns-proxy` |
| Process Network Monitor 👁️ | Real-time process-level socket and bandwidth tracking | "Why is this app talking to external IPs?" | **Done** — `blackout tools process-monitor` |

### Phase 4: Pro & AI features (1.6.x+)

| Feature | What it does | Why it matters | Status |
|---|---|---|---|
| PCAP Export 🦈 | Export captured network packets to `.pcap` files | Interoperability with Wireshark | **Done** — `blackout tools capture --pcap <file>` |
| AI Network Explainer 🤖 | MCP tool & CLI: Claude reads live network state to spot anomalies | "Claude, is any process acting suspicious?" | **Done** — `blackout tools explain` & `blackout_explain_network` MCP tool |
| SSH Vault & Manager 🔑 | Built-in SSH client using the existing AES-256 vault | Replace Termius/PuTTY | **Done** — `blackout ssh add/list/connect/remove` |
| Local REST API & Web Dashboard 🌐 | Browser-based network monitoring UI & local REST API | Interoperability & remote control | **Done** — `blackout api start` |
| Scriptable Automation ⚡ | Event-triggered automation rules for network events | "When X happens, do Y automatically" | **Done** — `blackout automation list/add/remove/trigger` |

---

## Technical improvements (Ongoing)

Before adding new features, the foundation must be reinforced:

1. **GUI Parity:** **Done** — Added `--russia` & `--iran` transport toggles, live radar map, and custom status dashboards to the CustomTkinter GUI.
2. **Daemon IPC:** **Done** — High-performance in-memory & socket daemon metrics stream (`stream_daemon_ipc_metrics`) without disk polling.
3. **YARA Rules Engine:** **Done** — User-supplied YARA rule loader (`load_custom_yara_rule_file`) and pattern scanner (`scan_file_yara`).

---

## Design principles

1. **One tool, many purposes** — like a Swiss army knife, not 10 separate apps
2. **Terminal-first** — everything works from the CLI; GUI is a bonus
3. **Local-only** — no cloud, no telemetry, no phone home
4. **Honest** — never claim a feature does more than it does
5. **Fun to use** — NetworkChuck would want to make a video about it

---

## Maintainer rule of thumb

A roadmap item ships only when:
1. The code path exists and works
2. The scope is explicit (what it does and doesn't do)
3. The docs describe it honestly
4. It's fun to use
