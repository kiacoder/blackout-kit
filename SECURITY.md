# Security Policy

Blackout Kit is a censorship circumvention toolkit. Its security directly
protects users in high-risk environments — we take this seriously.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.1.x   | ✅ Active support  |
| 1.0.x   | ✅ Security patches |
| < 1.0   | ❌ Unsupported     |

Only the latest minor release receives full updates. Critical patches are
backported to the previous minor for 30 days.

## Reporting a Vulnerability

**DO NOT open a public issue.** Vulnerabilities in circumvention tools can
put users at risk if disclosed before a fix is available.

### Private reporting (preferred)
- Use GitHub's [private vulnerability reporting](https://github.com/kiacoder/blackout-kit/security/advisories/new)
- Encrypt sensitive details with our [PGP key](#pgp-key)

### Anonymous reporting
- Email: base64-encode your report and send via an anonymous remailer
- Signal: available on request for verified reporters

### What to expect
- **Acknowledgment**: within 48 hours
- **Status update**: every 5 days until resolved
- **Fix timeline**: critical (7 days), high (14 days), medium (30 days)
- **Credit**: you'll be credited in the advisory (or remain anonymous if you prefer)

### Scope

| In scope | Out of scope |
|----------|-------------|
| SNI spoofing leaks (real IP exposure) | Theoretical attacks without a PoC |
| Kill switch bypass | Social engineering |
| Binary integrity / supply chain | `blackout doctor` false positives |
| DNS leak through any engine | DoS without privacy impact |
| Config encryption weaknesses | Vulnerabilities in external engines (report upstream) |
| Proxy authentication bypass | Vulnerabilities in outdated Go deps already flagged by Dependabot |

## Binary Integrity

All engine binaries are built from source in `engine/`. To verify:

```bash
# Build from source and compare hashes
cd engine
go build -buildmode=c-shared -o ../bins/blackout_core.dll .
cd warp
go build -buildmode=c-shared -o ../../bins/blackout_warp.dll .
```

Pre-built binaries are signed with SSH key attestation (coming soon).

SHA256 hashes of release binaries are published in the release notes.

## Dependency Management

- `golang.org/x/crypto`, `cloudflare/circl`, and other crypto deps are
  pinned to latest versions at release time
- Dependabot monitors all Go modules daily
- Critical crypto patches are applied within 48 hours
- Engine Go modules in `engine/` and `engine/warp/` are updated together

## Known Trade-offs

This tool intentionally trades some security for circumvention effectiveness:

- **allowInsecure = true** (SPEED/PRIVATE modes) — trusts self-signed certs
  to bypass DPI. Use LEGEND mode for strict cert validation.
- **Config encryption** is per-machine, not portable — prevents at-rest
  discovery but not offline brute-force.
- **Kill switch** uses Windows Firewall — a kernel-level adversary can
  bypass it. Defense in depth recommended.

## PGP Key

```
Not yet published — use GitHub private reporting for now.
```

## Hall of Fame

We maintain a list of researchers who have responsibly disclosed
vulnerabilities. Thank you for helping protect users worldwide.
