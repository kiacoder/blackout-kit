# Security Policy & Known Limitations

## Supported Versions

| Version | Status | Support Until |
|---------|--------|----------------|
| 1.1.1   | ✅ Current | 2027-09-04 |
| 1.1.0   | ⚠️ Maintenance | 2027-02-04 |
| 1.0.x   | ⚠️ End-of-Life | 2026-12-04 |

## Reporting Security Vulnerabilities

**Do not open public GitHub issues for security vulnerabilities.** Instead:

1. Email: security@kiacoder.dev
2. GitHub Security Advisory: https://github.com/kiacoder/blackout-kit/security/advisories
3. Response target: Within 48 hours

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Known Limitations & Advisories

### 🟡 Accepted Static-Analysis Findings (reviewed 2026-10-02)

A hardening pass fixed 34 of 39 static-scan findings (path validation, URL scheme/host validation, credential-shaped test literals, protocol-inappropriate randomness, vendored-code crypto annotations). The following 5 SSRF findings are **reviewed and accepted as by-design**, after multiple validation patterns were applied and the remaining flags resisted all of them:

| Site | Rationale |
|---|---|
| `blackoutkit/tools/download_manager.py` (×2) | The download manager's function is fetching user-specified HTTP(S) URLs. Every request sink validates scheme (http/https allowlist) and host presence before connecting. |
| `blackoutkit/doctor.py` | Connectivity probe against hard-coded public URLs (`cp.cloudflare.com`, `google.com/generate_204`), scheme-validated via `_validated_probe_url`. |
| `blackoutkit/scanner/proxy_tester.py` | Connectivity probes against hard-coded public test URLs, scheme-validated via `_validated_probe_url`. |
| `blackoutkit/engines/appsscript.py` | Posts to the user's own configured Google Apps Script relay, validated as https on `script.google.com` via `_validated_relay_url`. |

No site accepts arbitrary intranet access beyond what the user explicitly configures; Blackout Kit is a local network tool whose purpose is user-directed connections. The vendored `engine/warp/compat/pion-*` MD5/SHA-1 usages are protocol-mandated (DTLS 1.2 handshake registry, STUN RFC 5389 integrity) and annotated as such.

### 🔴 Pion WireGuard Advisory (Upstream CVE)

**Scope:** Affects WireGuard engine connections (WG profile, not IKEv2/Soft-ether)

**Status:** Patchable, not exploitable in default setup

**Mitigation:**
- Config rotation enabled by default (`config_rotation: true`)
- If WireGuard connection fails, daemon automatically tries next saved profile (XRay, Psiphon, etc.)
- Does NOT require user action or app restart
- Disable only if you have a single WireGuard endpoint and no fallback

**Workaround:** Use alternative engines (XRay VLESS/Reality, Psiphon, Hysteria2, TUIC) instead of WireGuard

### 🟡 AmneziaWG Experimental (Blocker: Outbound Type Missing)

**Status:** Cataloged as engine, blocker active, not selectable for connections

**Issue:** Bundled sing-box runtime exposes only standard WireGuard, not AmneziaWG outbound type

**Impact:** Connections using AmneziaWG profiles fail with "missing feature" blocker

**Timeline:** Awaiting sing-box upstream support; estimated Q1 2027

**Workaround:** Use standard WireGuard profiles or alternative transports

### 🟡 Linux Runtime Python-Optional (Core is Native)

**Scope:** Daemon and engine compiled as Go binary; optional Python for CLI tools

**Security Note:** Python dependencies (rich, httpx, typer) are only required for interactive setup/CLI. Daemon runs standalone with zero Python deps.

**Implication:** Vulnerabilities in Python dependencies do not affect background daemon operation or network isolation

### 🟢 Platform Scope: Windows & Linux Only

**Status:** By design, not a limitation

**macOS:** Not supported. No Darwin build or roadmap.

**Implication:** Use Windows executable or Linux runtime. Cloud/container deployments use Linux.

## Security Practices

### Code Integrity
- ✅ All releases built via GitHub Actions (reproducible)
- ✅ Windows executable signed with build certificate (v1.1.1+)
- ✅ Source code audited for resource leaks, injection flaws, unsafe concurrency
- ✅ CodeQL static analysis on every push
- ✅ Dependency pinning for reproducible builds

### Credential Safety
- ✅ Proxy credentials passed directly to native engines (no temp files)
- ✅ Settings encrypted at rest if vault enabled (`secrets_vault_enabled: true`)
- ✅ No credentials logged to daemon output (verified by smoke tests)
- ✅ SSH profile passwords excluded from JSON exports
- ✅ Config rotation isolates failed endpoints automatically

### Network Isolation
- ✅ Local proxy-only mode (no remote agent, no cloud sync)
- ✅ **Linux-only** kill switch (endpoint-scoped nftables/iptables) to stop network if the proxy disconnects; Windows kill-switch support is intentionally retired — legacy Windows Firewall rules are removed because block rules override the per-process allow rules they would need
- ✅ Loopback-only dashboard CORS (no external access)
- ✅ Optional Operator event stream binds to loopback only and is off unless explicitly started (`blackout events serve`); it is read-only with no control surface. It has **no authentication**: any local process or user session on this machine can connect and read sanitized events; remote peers cannot.
- ✅ DNS queries validated against upstream DoH proxy
- ✅ All transports support obfuscation (SNI spoofing, XRay fragmentation, XHTTP)

### Network Contact Disclosure (no silent telemetry)
Blackout Kit has no analytics or telemetry backend and never phones home on its own. It does contact external hosts when **you** invoke features that require it: update checks (GitHub releases), Cloudflare IP scanning, ISP/country detection (ip-api.com), DNS-over-HTTPS queries, engine traffic to servers you configure, and subscription imports you request. No results are reported anywhere.

### Operator Observability & Support Bundles
- Structured events, snapshots, and recommendations are **local only**; nothing is uploaded by Blackout Kit, ever.
- The event journal (`~/.blackout-kit/events.jsonl`) and MCP/event-stream consumers receive sanitized events: secret-bearing fields and proxy/VPN/SSH URIs are removed at publish time, before any observer or file sees them. The journal is best-effort across concurrent processes; a bounded rotation keeps it small.
- `blackout support-bundle` writes a debugging file **only where you save it** and refuses to include passwords, tokens, API keys, private keys, PSKs, proxy/VPN/SSH config URIs, vault contents, or environment variables. Values are removed, not partially masked. Run `blackout support-bundle --preview` to inspect exactly what will be written before exporting.

### Resource Management
- ✅ Thread-safe file locking for concurrent config access
- ✅ Atomic JSON persistence (fsync + replace, not truncate)
- ✅ Streaming file I/O for large YARA scans (not loaded into memory)
- ✅ Graceful daemon shutdown (no orphaned processes)
- ✅ Memory bounds for cache and buffer operations

## Local Data Inventory

Everything Blackout Kit persists lives under `~/.blackout-kit/` (plus runtime binaries in `bins/`). Depending on which features you use, some of these may not exist:

| File / directory | Contents | Sensitivity |
|---|---|---|
| `settings.json` | Typed local settings (ports, toggles, pinned country) | Secret-bearing keys written only if `secrets_vault_enabled` is off |
| `configs.enc` | Machine-bound AES-256-GCM vault of saved proxy configs/URIs | High — never included in support bundles |
| `secrets.enc` | Machine-bound encrypted settings secrets (when enabled) | High |
| `ssh_vault.json` | SSH profile metadata (`ssh` command) | Passwords excluded from JSON exports |
| `daemon.log`, `daemon.out` | Engine/daemon operational logs | Scrubbed of credentials by design; support bundles re-scrub line-by-line |
| `daemon_state.json` | Live daemon state (PID, engine, restart counters) | Low |
| `events.jsonl` | Sanitized structured event journal (Operator) | Bounded, secret-bearing fields removed at publish |
| `recovery_audit.jsonl` | Targeted-recovery history (redacted at write) | Low |
| `stability.json` | Per-engine latency/loss history used for local ranking | Low |
| `scan_cache.json`, `data/`, `neighbor_cache.json`, `split_tunnel.json` | Local caches: Cloudflare IPs, fake-SNI domains, LAN neighbors, bypass patterns | Low |
| `adblock_rules.json`, `automation_rules.json`, `threat-feeds/` | Feature state for ad blocking, automation, threat feeds | Low |
| `bins/` | Downloaded engine runtimes (Xray, sing-box, Tor, WARP DLL, …) | Binaries only |

Uninstalling means deleting `~/.blackout-kit/`; no data is stored elsewhere and nothing syncs anywhere.

## SBOM & Dependency Audit

See `SBOM.json` for complete software bill of materials (generated per release).

**Notable dependencies:**
- **httpx[socks,http2]** (0.27+): HTTP client for XRay/DoH
- **cryptography** (43.0+): TLS cert handling, SSH
- **click** (8.1.7–8.3.1): CLI framework (pinned for stability)
- **rich** (13.7.1–14.2): Terminal rendering (pinned for help text)
- **typer** (0.12+): CLI router
- **psutil** (6.0+): Process/network monitoring

## Compliance

- ✅ OWASP Top 10: Hardened against injection, authentication bypass, sensitive data exposure
- ✅ CWE-200: Credential safety verified
- ✅ CWE-90: Input validation hardened (SNI, DNS, URL parsing)
- ✅ CWE-362: Concurrent access protected via file locking

## Contact

- **Security:** security@kiacoder.dev
- **GitHub:** https://github.com/kiacoder/blackout-kit/security/advisories
- **Issues:** https://github.com/kiacoder/blackout-kit/issues (non-security only)
