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

| Feature | What it does | Why Chuck would love it |
|---|---|---|
| Packet capture + analysis | Capture and inspect network traffic (like Wireshark-lite) | "Look at your packets without leaving the terminal" |
| Port scanner | Scan networks for open ports (like nmap-lite) | "Know what's listening on your network" |
| Network discovery | Map devices on your LAN, show IPs/MACs/vendors | "Who's on my network?" |
| Bandwidth monitor | Real-time per-process and per-connection traffic stats | "What's eating my bandwidth?" |
| Connection table | Live TCP/UDP connection table with process attribution | "What is my computer connected to right now?" |
| Latency monitor | Continuous ping/traceroute with history graph | "Is my internet getting worse?" |
| DNS inspector | Show which DNS servers you're using, query logs, poisoning detection | "Is someone messing with my DNS?" |
| Subnet Calculator | Instantly print network range, broadcast, min/max hosts | "Never do subnet math in your head again" |
| Speedtest History | Visual terminal graph of speedtests over 30 days | "Prove your ISP is throttling you at 8 PM" |

### Phase 2: Traffic, downloads & sharing (1.4.x)

| Feature | What it does | Why it matters |
|---|---|---|
| Download manager | Multi-threaded downloads with resume, queue, and speed limits | Everyone needs this |
| Video/Media extraction | Built-in wrapper for raw media extraction (yt-dlp style) | Clean CLI downloading |
| Torrent/Magnet support | Lightweight terminal-based torrent client | No need for heavy GUI apps |
| Traffic shaper | QoS rules — prioritize/govern specific apps or protocols | "Make my games faster, slow down background updates" |
| Bandwidth caps | Set daily/monthly limits per interface | Data caps are real, especially on cellular |
| Traffic logging | Persistent log of network usage by app/protocol/time | "Where did my 50GB go this month?" |
| Network-level ad blocking | DNS-based ad/tracker blocking (like Pi-hole-lite) | Clean browsing without browser extensions |
| Setup export/import | Share your exact config, DNS, and engine state via one string | "Send your perfect bypass setup to a friend" |
| LAN IP Cache sharing | Share a 40ms Cloudflare IP with neighbors over LAN | Skip the 2-minute scan |

### Phase 3: Antivirus & security hardening (1.5.x)

| Feature | What it does | Why it matters |
|---|---|---|
| File scanner | Scan files with Windows Defender / ClamAV from the CLI | "Scan this download before I open it" |
| VirusTotal integration | Calculate file hash and check 70+ AV engines via API | Zero-execution malware check |
| MAC Address Spoofer | Randomize Wi-Fi MAC to avoid tracking on public networks | Airport/Cafe privacy |
| Public Wi-Fi Honeypot | Open a fake port to detect if someone on the cafe Wi-Fi is scanning you | "192.168.1.14 is scanning your computer" |
| Malware network detection | Alert on suspicious outbound connections (C2 patterns, mining pools) | Catch malware by its network behavior |
| Phishing protection | DNS-level blocking of known phishing domains | Stop phishing before it reaches the browser |
| Network hardening audit | Check firewall rules, open ports, exposed services, weak configs | "Is my system actually secure?" |
| Secure DNS resolver | Built-in DoH/DoT with tamper detection and fallback | "Nobody is poisoning my DNS" |
| Process network monitor | Flag processes making unexpected connections | "Why is this app talking to Russia?" |
| Global Panic Button | Sever ALL network connections on the PC instantly | The ultimate killswitch |

### Phase 4: Pro & AI features (1.6.x+)

| Feature | What it does | Why it matters |
|---|---|---|
| AI Network Explainer | MCP tool: Claude reads your live network state to spot anomalies | "Claude, is any process acting suspicious?" |
| SSH Vault & Manager | Built-in SSH client using the existing AES-256 vault | Replace Termius/PuTTY |
| PCAP export | Export captures as `.pcap` for Wireshark | Interoperability with existing tools |
| Scriptable automation | Python/TOML automation rules for network events | "When X happens, do Y automatically" |
| Network simulation | Simulate latency/packet loss for testing | DevOps and QA use case |
| REST API | Expose all tools via a local REST API | Integration with other tools and dashboards |
| Web dashboard | Browser-based network monitoring UI | "See my whole network at a glance" |

---

## Technical improvements (Ongoing)

Before adding new features, the foundation must be reinforced:

1. **GUI Parity:** Bring the CustomTkinter GUI up to par with the CLI. Add `--russia`/`--iran` toggles, visual latency graphs, and a "hacker dashboard" aesthetic.
2. **Daemon IPC Rewrite:** Upgrade from simple files to named pipes or local gRPC for real-time daemon metrics (exact bytes/sec) without disk I/O.
3. **YARA Rules Engine:** Allow power users to write custom security rules for memory/file scanning.

---

## Design principles

1. **One tool, many purposes** — like a Swiss army knife, not 10 separate apps
2. **Terminal-first** — everything works from the CLI; GUI is a bonus
3. **Local-only** — no cloud, no telemetry, no phone home
4. **Honest** — never claim a feature does more than it does
5. **Fun to use** — NetworkChuck would want to make a video about it

---

## Version focus summary

| Version | Focus | Status |
|---|---|---|
| 1.1.x | VPN/bypass engines, stabilization, docs | Shipped |
| 1.2.x | Russia support: RU profile, presets, XHTTP, AmneziaWG, smart rotation, diagnostics | Shipped |
| 1.3.x | Network analysis: packet capture, port scanner, bandwidth monitor, connection table, DNS inspector | Next |
| 1.4.x | Traffic & downloads: download manager, traffic shaper, ad blocking, usage logging | Planned |
| 1.5.x | Antivirus & security: file scanner, malware detection, phishing protection, hardening audit | Planned |
| 1.6.x+ | Pro: PCAP export, automation, REST API, web dashboard | Future |

---

## Maintainer rule of thumb

A roadmap item ships only when:
1. The code path exists and works
2. The scope is explicit (what it does and doesn't do)
3. The docs describe it honestly
4. It's fun to use
