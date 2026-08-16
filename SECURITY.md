# Security Policy

Blackout Kit is a censorship circumvention toolkit. Its security directly
protects users in high-risk environments — we take this seriously.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.1.x   | Active support     |
| 1.0.x   | Security patches   |
| < 1.0   | Unsupported        |

Only the latest minor release receives full updates. Critical patches are
backported to the previous minor for 30 days.

## Threat Model

Blackout Kit assumes the following adversary capabilities:

| Adversary | Capabilities | Mitigation |
|-----------|-------------|------------|
| **ISP / DPI** | Packet inspection, SNI blocking, port blocking | Supported local engines and configured upstream proxy protocols; effectiveness varies by network and configuration |
| **National Firewall** | Active probing, protocol classification, IP blacklisting | XRay and compatible upstream configurations where available; no active-probing or detection-resistance guarantee |
| **Local Network Admin** | DNS poisoning, deep packet inspection, throttling | Optional DoH bootstrap, platform-specific kill switch, and encrypted proxy transports when configured |
| **Passive Eavesdropper** | Traffic correlation, metadata analysis | Encrypted transports and normal-TLS certificate policy; timing correlation remains out of scope |

**We do NOT protect against:**
- A state actor with physical device access
- Targeted malware/keylogger on the user's machine
- Traffic correlation via timing analysis at scale
- Compromise of upstream proxy/VPN servers

## Reporting a Vulnerability

**DO NOT open a public issue.** Vulnerabilities in circumvention tools can
put users at risk if disclosed before a fix is available.

### Preferred: GitHub Private Reporting
Use GitHub's [private vulnerability reporting](https://github.com/kiacoder/blackout-kit/security/advisories/new).

If private reporting is unavailable, contact the repository maintainer through the
GitHub account listed on the project page. Do not post exploit details or sensitive
configuration data in a public issue.

### What to expect

- **Acknowledgment**: within 48 hours
- **Status update**: every 5 days until resolved
- **Fix timeline**: critical (7 days), high (14 days), medium (30 days)
- **Credit**: you'll be credited in the advisory (or remain anonymous if you prefer)
- **CVE**: we will request a CVE ID for confirmed vulnerabilities

### Scope

| In scope | Out of scope |
|----------|-------------|
| SNI spoofing leaks (real IP exposure) | Theoretical attacks without a PoC |
| Kill switch bypass | Social engineering |
| Binary integrity / supply chain | `blackout doctor` false positives |
| DNS leak through any engine | DoS without privacy impact |
| Config encryption weaknesses | Vulnerabilities in external engines (report upstream) |
| Proxy authentication bypass | Dependabot-flagged Go dep vulns (transitive deps pinned by xray-core, sing-box, warp-plus — see Known Trade-offs) |

## Coordinated Disclosure

We follow a 90-day coordinated disclosure window:

1. **Report received** — we acknowledge within 48h
2. **Fix developed** — we aim for a patch within the fix timeline above
3. **Patch released** — a new version is published with a security advisory
4. **Public disclosure** — 90 days after the fix release, we publish details

We appreciate reporters who respect this window.

## Supply Chain Security

### Go Module Pinning
- All dependencies are pinned via `go.sum` in `engine/` and `engine/warp/`
- Dependabot monitors the Go module graphs for vulnerable transitive dependencies
- Patchable transitive dependencies are pinned at or above their fixed releases and verified in the Windows WARP DLL build
- Upstream forks (utls, quic-go) are reviewed before updating

### Release Artifacts
- CI builds the supported Windows and Linux native artifacts from repository sources.
- Verify the release asset, commit, and any published checksums before deploying it in a high-risk environment.
- Build the native artifacts locally when you need to inspect the exact source and toolchain inputs (see below).

### Dependency Audit
- `go mod verify` is run before every release
- `govulncheck` is run periodically to catch known CVEs
- We prioritize upgrading `golang.org/x/crypto` (the primary attack surface,
  a transitive dep of xray-core, sing-box, and warp-plus)

## Recent Security Improvements (v1.1.x)

- **Windows kill switch retired**: legacy Windows Firewall rules were removed
  because block rules override the per-process allow rules they require. The
  verified implementation is Linux-only, endpoint-scoped firewall protection.
- **Download integrity**: all downloaded binaries verified for valid PE
  headers (MZ + PE signature) before install. Corrupt/tampered files rejected.
- **Watchdog cleanup**: if the daemon is End-Tasked while kill switch is on,
  internet is no longer permanently blocked.
- **DLL crash detection**: engines that crash silently (segfault, deadlock)
  are now detected via TCP port probes and auto-restarted by the daemon.
- **Config isolation**: each engine writes to a unique temp directory
  instead of shared `bins/`, preventing cross-instance corruption.

## Native Runtime Build Scope

The repository builds Blackout Kit's Go wrappers in `engine/`; it does not build every third-party runtime or downloaded engine from source. Use the release checksums and upstream provenance for those dependencies.

```bash
# Windows native core (run with a Windows Go toolchain)
cd engine
go build -buildmode=c-shared -o ../bins/blackout_core.dll .

# Windows WARP/Psiphon wrapper
cd warp
go build -buildmode=c-shared -o ../../bins/blackout_warp.dll .

# Linux x86_64 managed runner (run with a Linux Go toolchain)
cd ..
go build -o ../dist/blackout-engine-linux-amd64 .
```

A successful local build demonstrates that the selected source and toolchain compile; it is not, by itself, a reproducible-build attestation or a substitute for validating release checksums.

## Data Privacy & Telemetry

Blackout Kit does not include a first-party analytics or telemetry service. It does make network requests when you invoke features that need them, including updates, subscription imports, scans, DNS resolution, certificate checks, speed tests, and unpinned ISP/country lookup.

Persistent local data can include:
- Settings and saved proxy configuration URIs; use `blackout config encrypt` for encrypted-at-rest config storage.
- Daemon logs, local stability history, certificate records created by TLS checks, and Windows system-proxy bypass rules.
- Engine binaries and local WARP/Psiphon identity or datastore caches generated at runtime.

Routine terminal and MCP settings views mask the stored IKEv2 password/PSK and
SoftEther password. Those values remain plaintext in `settings.json`; masking is
an output safeguard, not encryption at rest.

Protect this data as sensitive. A proxy URI can contain server credentials, and an upstream proxy/VPN operator can observe traffic routed through that server.

## Guidance for Recommendations

Do not describe Blackout Kit as universally safe, anonymous, undetectable, or more private than another product without an independent review of the current release and the user's threat model. It is a local coordinator for engines and user-supplied upstream configurations; it does not operate the proxy/VPN servers that carry tunneled traffic.

For high-risk use, evaluate the current source, release provenance, local-device security, upstream operator trust, platform constraints, and applicable law before relying on any engine or mode.

## Known Trade-offs

This tool intentionally trades some security for circumvention effectiveness:

- **Normal TLS `allowInsecure = true`** (SPEED/PRIVATE) — accepts unverified
  normal TLS certificates for compatibility. LEGEND rejects a known-bad normal
  TLS certificate unless explicitly allowed. VLESS REALITY instead relies on
  XRay's configured public-key handshake and does not use this certificate policy.
- **VLESS REALITY trust** — import REALITY URIs only from a trusted server
  operator. Blackout Kit does not discover servers, generate server keys, or
  validate the operator beyond XRay's configured handshake.
- **Config encryption** uses a machine-derived AES-256-GCM key. It protects
  local encrypted-at-rest config storage but is not portable and does not
  protect an already-compromised device.
- **Kill switch** is supported only on Linux using a Blackout Kit-owned
  nftables table (or iptables/ip6tables fallback). A kernel-level adversary can
  bypass it. It permits only validated upstream endpoint IPs, loopback,
  LAN/DHCP, and `BlackoutKit-TUN`; it refuses to enable if it cannot resolve a
  safe endpoint allowlist. Windows legacy rules are removed rather than treated
  as protection.
- **Linux system networking** requires `sudo` and supports XRay, TUN,
  Hysteria2, and TUIC on x86_64. Cleanup removes only `inet blackoutkit`,
  `BLACKOUTKIT_*`, the dedicated routing table `20220`, and the deterministic
  `BlackoutKit-TUN` interface; it never flushes system routes or manages
  third-party VPN interfaces.
- **ARP repair is explicit** — `blackout tools arp-flush` and
  `blackout fix --flush-arp` can briefly interrupt LAN neighbor discovery, so
  default recovery and daemon reconnects never run it.
- **Plaintext credentials** — IKEv2/SoftEther passwords are stored as plaintext
  in `settings.json`. `blackout config encrypt` protects only saved proxy URIs,
  not these settings; LEGEND mode does not encrypt either location.
- **Legacy Pion transitives** — Dependabot alerts #28
  (`GHSA-9f3f-wv7r-qc8r`, `github.com/pion/dtls/v2`) and #60
  (`GHSA-34rh-wp3j-6cxc`, unversioned `github.com/pion/stun`) remain open because
  their affected v2/v0 module lines have no patched release. They are required by
  the upstream `warp-plus → psiphon-tunnel-core` integration. The current Psiphon
  branch uses patched Pion v3 APIs but still retains the legacy compatibility
  modules, so upgrading to its unreleased pseudo-version would not resolve these
  alerts and would raise the required Go toolchain to 1.26. All other patchable
  WARP graph advisories are pinned at their fixed releases. We retain and monitor
  these alerts rather than dismissing them, and will update when a compatible
  upstream release removes the legacy module paths.

## Hall of Fame

We maintain a list of researchers who have responsibly disclosed
vulnerabilities. Thank you for helping protect users worldwide.

To be added, simply submit a valid report through the channels above and
let us know if you'd like to be credited.
