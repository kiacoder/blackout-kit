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
- ✅ Kill-switch option to stop network if proxy disconnects
- ✅ Loopback-only dashboard CORS (no external access)
- ✅ DNS queries validated against upstream DoH proxy
- ✅ All transports support obfuscation (SNI spoofing, XRay fragmentation, XHTTP)

### Resource Management
- ✅ Thread-safe file locking for concurrent config access
- ✅ Atomic JSON persistence (fsync + replace, not truncate)
- ✅ Streaming file I/O for large YARA scans (not loaded into memory)
- ✅ Graceful daemon shutdown (no orphaned processes)
- ✅ Memory bounds for cache and buffer operations

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
