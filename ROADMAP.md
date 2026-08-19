# Blackout Kit — Roadmap

This roadmap reflects the **current codebase** including Russia support and the strategic shift toward cybersecurity features.

---

## Current release line: 1.2.x — Russia support shipped, cybersecurity next

### What just shipped (Russia support)

| Feature | Status | Notes |
|---|---|---|
| RU country profile | Done | Engine order: xray → hysteria2 → tuic → awg → warp/gdpi/tun → psiphon |
| `--russia` transport preset | Done | Temporary overrides, no saved settings writes, works in background |
| Country-aware routing | Done | XRay split-tunnel and TUN bypass domains are country-aware (RU: Yandex/VK/Ozon) |
| XHTTP transport | Done | `type=xhttp` and legacy `type=splithttp` in V2Ray URIs |
| Smart config rotation | Done | Daemon auto-rotates to next saved config when endpoint fails (blocked IP) |
| AmneziaWG engine | Done | `.conf` file parsing, sing-box `amnezia-wireguard` outbound, experimental |
| Whitelist awareness | Done | Doctor checks if proxy server IP is on Russian cellular whitelist |
| Data-phase drop detection | Done | Daemon detects "TCP open but HTTP dead" and triggers rotation |
| `blackout help russia` | Done | Dedicated help topic with field-verified transport notes |
| ISP country-code detection | Done | `IspInfo` carries `country_code` from ip-api.com |

### What shipped earlier (1.1.x)

| Feature | Status | Notes |
|---|---|---|
| Typer public CLI | Done | `blackoutkit/typer_cli.py` |
| Route recommendation dashboard | Done | Local-only ranking via `blackout route` |
| Local readiness checks | Done | `blackout ready [engine]` |
| Live status view | Done | `blackout status --watch` |
| Desktop GUI | Done | Windows-only CustomTkinter |
| MCP server | Done | Constrained stdio tool surface |
| XRay + REALITY | Done | VLESS REALITY on Windows and Linux |
| Hysteria2 / TUIC | Done | sing-box proxy mode via DLL or Linux runner |
| TUN mode | Done | Windows + Linux |
| GoodbyeDPI | Done | `legacy` default, `native` experimental |
| Linux endpoint-scoped kill switch | Done | nftables/iptables, endpoint-scoped |
| Targeted crash recovery | Done | Blackout-owned state cleanup only |
| Machine-bound encrypted vault | Done | AES-256-GCM, protects proxy URIs and secrets |
| Country profiles | Done | IR, RU, CN, IQ, GB, US, EU |
| Iran `--iran` preset | Done | Refactored to temporary env-based overrides |
| Preset mechanism refactor | Done | Both `--iran` and `--russia` are non-persistent |

---

## Strategic direction: cybersecurity pivot

**Decision (2026-08-19):** VPN/bypass features are complete. New development pivots to cybersecurity — which is more fun, more legal, and serves a bigger market.

Existing bypass capabilities stay as they are. No new bypass engines or protocols unless specifically requested.

### Next chapter: cybersecurity features

| Candidate | Why it matters | Current status |
|---|---|---|
| DNS security and poisoning detection | Iran and Russia both poison DNS — detection helps users understand what's happening | Not started |
| Malware/network anomaly detection | Real-time alerting on suspicious traffic patterns | Not started |
| Phishing protection | Block known phishing domains at the DNS level | Not started |
| Traffic analysis protection | Detect and warn about traffic fingerprinting | Not started |
| Secure DNS resolver | Built-in DoH/DoT with tamper detection | Not started |
| Network hardening audit | Check Windows/Linux network config for security weaknesses | Not started |
| Antivirus integration | Interface with Windows Defender / ClamAV for file scanning | Not started |

### Maintenance priorities (ongoing)

| Item | Status | Notes |
|---|---|---|
| Native GDPI parity | Open | Verify if native reaches functional parity with legacy |
| Documentation alignment | Active | Keep docs, help, and code in lockstep |
| Runtime provenance clarity | Active | Make it obvious which runtimes are repo-built vs external |
| Dependabot alerts | Open | 2 moderate vulnerabilities flagged on GitHub |

---

## Explicitly deferred or intentionally limited

| Area | Current stance |
|---|---|
| Windows kill switch | Intentionally unsupported; legacy rules removed |
| Full Linux parity with Windows engine catalog | Not a goal |
| New bypass engines/protocols | Not planned — VPN/bypass work is finished |
| Claims of anonymity or detection resistance | Avoid unless independently justified |
| "Country profile means it will work there" | Avoid; profiles are guidance only |
| Aggressive auto-repair of unrelated network state | Avoid; targeted recovery is the policy |

---

## Version focus summary

| Version line | Focus |
|---|---|
| 1.1.x | Stabilization, packaging, docs accuracy, Linux runtime (shipped) |
| 1.2.x | Russia support: RU profile, --russia preset, XHTTP, AmneziaWG, smart rotation, whitelist awareness, data-phase detection (shipped) |
| 1.3.x | Cybersecurity pivot: DNS security, malware detection, phishing protection, network hardening |

---

## Maintainer rule of thumb

A roadmap item should move from "candidate" to "shipped" only when all three are true:

1. the code path exists
2. the platform/runtime scope is explicit
3. the docs can describe it without hedging into fiction

That rule is especially important for a project like Blackout Kit, where inaccurate claims are themselves a security and trust problem.
