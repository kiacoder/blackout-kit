# Security Policy & Known Limitations

## Supported Versions

| Version | Status | Support Until |
|---------|--------|----------------|
| 1.1.1   | ✅ Current | 2027-09-04 |
| 1.1.0   | ⚠️ Maintenance | 2027-02-04 |
| 1.0.x   | ⚠️ End-of-Life | 2026-12-04 |

## Security Assurance & Verification Matrix

Every claim below is enforced by code plus a test, and each row names the mechanism an auditor
can run. Status is honest: 🟢 means implemented and verified, ⚪ means out of our control.

| Component / Claim | Verification Mechanism | Status |
| :--- | :--- | :--- |
| **Build Provenance** | GitHub Sigstore Attestation (`gh attestation verify`) | 🟢 Cryptographically Verified |
| **File Integrity** | SHA-256 digest matching (`checksums.txt`) | 🟢 Enforced in `install.ps1` |
| **MCP Authorization** | Fail-closed `hmac.compare_digest` with `BLACKOUT_MCP_TOKEN` | 🟢 Gated & Unit Tested |
| **Antivirus Safety** | Isolated `bins/windivert/` + explicit typed user opt-in | 🟢 Isolated |
| **Socket Exposure** | Strict `127.0.0.1` loopback binding default | 🟢 Enforced |
| **Remote Server Trust** | Upstream VPN / proxy nodes | ⚪ User-supplied (untrusted by default) |
| **Credential Redaction** | `RedactingFormatter` at log write time + bundle re-scrub | 🟢 Boundary-tested |
| **Egress Disclosure** | `NETWORK_PRIVACY.md`, row-by-row code references | 🟢 Documented, 0 telemetry |
| **Windows Authenticode / notarization** | — | 🔴 Not implemented (attestation is the current proof of origin) |

### Verify a release yourself

```powershell
# 1. Verify cryptographic provenance via GitHub Sigstore:
gh attestation verify blackout.exe --repo kiacoder/blackout-kit

# 2. Verify SHA-256 checksum. blackout.exe.sha256 holds "<hash>  blackout.exe", so take the first field:
$expected = ((Get-Content .\blackout.exe.sha256) -split '\s+')[0]
(Get-FileHash -Algorithm SHA256 .\blackout.exe).Hash -ieq $expected
```

`Get-FileHash` emits uppercase hex, while `.sha256` and `checksums.txt` use lowercase. Compare with
`-ieq` (or `.ToLowerInvariant()` on both sides). `-ceq` is case-sensitive and reports a false mismatch.

The same integrity check on Linux/macOS, and the machine-readable provenance statement:

```bash
sha256sum -c checksums.txt                       # verifies every published asset
shasum -a 256 blackout.exe | grep -f blackout.exe.sha256 || echo "MISMATCH"
gh attestation verify blackout.exe --repo kiacoder/blackout-kit --format json | jq '.[0].verificationResult'
```

What each verification actually establishes:

- `gh attestation verify` proves the file was produced by a run of this repository's
  `.github/workflows/build.yml`, for the commit the tag points at, on GitHub-hosted runners —
  a signature over the build's identity, not a claim by a maintainer. It requires GitHub CLI ≥ 2.22
  and network access to the Sigstore transparency log; it works for releases published from
  `v1.1.2` onward, because no attestation exists for earlier tags.
- The SHA-256 comparison proves the bytes you downloaded are the bytes the release job hashed.
  It does **not** prove who built them — that is the job of the attestation above, which is why
  both are published.
- `install.ps1` refuses to install without a checksum asset, and `blackout bins download` refuses an
  asset with no published digest; both delete the staged download and abort non-zero.

### Negative boundary tests

`tests/test_security_boundaries.py` is the executable form of this matrix: it drives the failure
paths (invalid, empty and missing MCP tokens; credential-bearing log lines and bundles; wildcard
bind attempts; checksum-mismatch installer aborts; a workflow that publishes without attesting)
and asserts the controls refuse, redact, unstage, or fail. Each test carries a control case, so
removing a defence turns the suite red instead of leaving it silently green.

## Reporting a Vulnerability

You can report security issues, bugs, or vulnerabilities through either of the following channels:
- **GitHub Issues:** Open an issue at [https://github.com/kiacoder/blackout-kit/issues](https://github.com/kiacoder/blackout-kit/issues)
- **Email:** kiacoder62@gmail.com

Please include:
- Description of the issue or vulnerability
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
- ✅ Every release asset carries a signed GitHub Sigstore build-provenance attestation (`actions/attest-build-provenance@v2`); verify with `gh attestation verify`
- ⚠️ Windows executables are not Authenticode-signed and Linux binaries are not notarized — provenance attestation is the available proof of origin, not a replacement for code signing
- ✅ Source code audited for resource leaks, injection flaws, unsafe concurrency
- ✅ CodeQL static analysis on every push
- ✅ Dependency pinning for reproducible builds

### Credential Safety
- ✅ Proxy credentials passed directly to native engines (no temp files)
- ✅ Settings encrypted at rest if vault enabled (`secrets_vault_enabled: true`)
- ✅ No credentials in daemon output: `blackoutkit/log_redaction.py` redacts at log write time and the support bundle re-scrubs at export; bearer tokens, URL userinfo credentials, and proxy/VPN/SSH URIs are covered by `tests/test_security_boundaries.py`
- ✅ SSH profile passwords excluded from JSON exports
- ✅ Config rotation isolates failed endpoints automatically

### Network Isolation
- ✅ Local proxy-only mode (no remote agent, no cloud sync)
- ✅ **Linux-only** kill switch (endpoint-scoped nftables/iptables) to stop network if the proxy disconnects; Windows kill-switch support is intentionally retired — legacy Windows Firewall rules are removed because block rules override the per-process allow rules they would need
- ✅ Loopback-only dashboard CORS (no external access)
- ✅ Optional Operator event stream binds to loopback only and is off unless explicitly started (`blackout events serve`); it is read-only with no control surface. It has **no authentication**: any local process or user session on this machine can connect and read sanitized events; remote peers cannot.
- ✅ DNS queries validated against upstream DoH proxy; the local DoH listener refuses any bind address outside `127.0.0.1`/`::1`, requires HTTPS upstream without embedded credentials, and re-validates redirect targets against the SSRF guard
- ✅ All transports support obfuscation (SNI spoofing, XRay fragmentation, XHTTP)

### Network Contact Disclosure (no silent telemetry)
The complete, row-by-row egress inventory lives in [`NETWORK_PRIVACY.md`](NETWORK_PRIVACY.md):
every endpoint, the command that reaches it, and how to confirm it. Nothing there runs on a timer.

Blackout Kit has no analytics or telemetry backend and never phones home on its own. It does contact external hosts when **you** invoke features that require it: update checks (GitHub releases), Cloudflare IP scanning, ISP/country detection (`https://ipapi.co/json/`, then `https://ipinfo.io/json` over HTTPS), DNS-over-HTTPS queries, engine traffic to servers you configure, and subscription imports you request. ISP lookup uses default TLS certificate verification and is best-effort: provider/network/HTTP-status (including rate-limit)/JSON/schema failures advance to the next provider, and returns no result if both fail. No results are reported anywhere.

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

## Trust Boundaries and Hardening

This section documents the controls for three areas that an external audit reviewed: the MCP
server, release verification, and the WinDivert driver with Windows Defender.

### MCP authorization

**Threat:** a local MCP client, or an agent manipulated by untrusted content, invokes state-changing
tools without the operator's consent. Those tools can change DNS, control the hotspot, run network
recovery, start TUN interfaces, and rewrite settings or saved configs.

**Control:** `blackoutkit/mcp_server.py` checks `auth_token` on every privileged call. The expected
value is the server process's `BLACKOUT_MCP_TOKEN` (or `BLACKOUT_MCP_SECRET`). The comparison uses
`hmac.compare_digest`. The check fails closed: no configured secret, a missing or non-string token,
or a mismatch denies the call. The token is consumed by the dispatcher and never reaches a tool
handler. Denial messages never echo the presented value, and denials are logged by tool name only.
A refused call is also reported as a failure in the JSON-RPC envelope (`result.isError`), so a client
that ignores prose cannot treat a denial as an executed operation; `blackoutkit/mcp_server.py` decides
this in one place (`call_failed`).
The privileged set and the read-only exemptions are listed in README.md under "MCP authorization".

**Residual risks:**

- The agent must hold the token to call privileged tools, so the token sits in that agent's context
  and in the MCP transcript. Use a dedicated random value and rotate it if it may have leaked.
- Read-only tools need no token. Any local process that can launch `blackout mcp` can read local
  state through them. `blackout_snapshot` and the support-bundle preview are sanitized, but
  `blackout_read_logs` is not separately filtered.
- The gate is a code constant (`_MCP_AUTH_ENABLED`), not a runtime switch, so it cannot be turned
  off from the environment. Tests disable it explicitly.

### Release verification (SHA-256)

Release jobs in `.github/workflows/build.yml` publish `blackout.exe`, `blackout-engine-linux-amd64`,
`blackout-source.zip`, `checksums.txt` (sha256sum format, all assets), and `blackout.exe.sha256`.
The release job runs `sha256sum -c` before publishing.

`install.ps1` verifies the download before anything else touches it:

1. It requires a checksum asset (`checksums.txt` preferred, otherwise `blackout.exe.sha256`). Without one it stops and installs nothing.
2. It stages the download beside the install target and does not overwrite the installed binary.
3. It computes the hash with `Get-FileHash -Algorithm SHA256` and compares it case-insensitively after trimming. A missing, ambiguous, or malformed checksum, or a mismatch, deletes the staged file and exits with status 1.
4. On a match it prints `[OK] SHA-256 checksum verified: <hash>` and moves the file into place.

Manual verification commands are in README.md under "Verify the release (SHA-256)".

**Limits:** the checksum and the file come from the same release, so digest matching alone protects
against corruption and substitution in transit, not against a compromised release. That second case is
what the build-provenance attestation closes: the release job attests `blackout.exe`,
`blackout-engine-linux-amd64`, `blackout-source.zip`, `checksums.txt`, and `blackout.exe.sha256`
immediately after the checksums are generated and before the release is published, so the signature
binds the exact bytes that ship.

**Chocolatey package:** `choco/tools/chocolateyinstall.ps1` carries a syntactically valid placeholder
digest (`0`×64) instead of the malformed non-hexadecimal value an audit previously flagged. The
placeholder cannot match any real binary, so the package fails closed rather than looking
installable: the maintainer must replace it with the published digest of the release being packaged
before the package is pushed.

### WinDivert driver isolation and Windows Defender

**Threat:** Defender exclusions widen what antivirus does not scan. A broad exclusion such as all of
`bins/` would exempt every executable placed there, which is why earlier builds were audited.

**Control:**

- WinDivert files live only in `bins/windivert/` (`blackoutkit/__init__.py`, `WINDIVERT_DIR`). They are
  installed only from SHA-256-verified release assets, and their provenance is recorded.
- The exclusion target is that folder alone. `blackoutkit/security.py` refuses to add an exclusion unless
  the folder is exactly `bins/windivert`, is not a symbolic link or junction, and contains exactly the two
  driver files.
- Adding or removing an exclusion is never automatic. `blackout doctor --fix` does not change Defender. The
  confirmed flow (`blackout config --setup-defender-exclusion`, `--remove-defender-exclusion`, or `doctor --fix-av`)
  needs an interactive terminal and a typed `yes`, and requests UAC only after that answer.
- The elevated command travels as `-EncodedCommand`, so the path cannot break out of it. Success is verified
  by reading Defender's exclusion list back with an exact, case-insensitive comparison.
- If the user declines, Blackout changes nothing and points to SOCKS5/HTTP modes, which do not use WinDivert.

**Residual risks:** Defender does not scan files placed in the excluded folder. The folder check limits what
can sit there, but it cannot verify the driver's contents beyond the install-time SHA-256 check. An exclusion
does not cover other executables such as `goodbyedpi.exe`, which Defender may still flag. Blackout does not
prove that a WinDivert detection is a false positive.

### Audit remediation status

| Finding | Status | Where |
|---|---|---|
| MCP authorization gate returned `True` unconditionally | Fixed: token gate, constant-time comparison, fail closed | `blackoutkit/mcp_server.py`, `tests/test_mcp_server.py` |
| `install.ps1` ran a downloaded `blackout.exe` without a checksum | Fixed: SHA-256 check before install; releases publish checksums | `install.ps1`, `.github/workflows/build.yml`, `tests/test_install_script.py` |
| Defender exclusion of all of `bins/`, silent via `doctor --fix`, with UAC | Fixed: narrow driver-folder exclusion, typed confirmation, UAC only afterwards | `blackoutkit/security.py`, `blackoutkit/doctor.py`, `blackoutkit/typer_cli.py`, `tests/test_security.py` |
| Security documentation did not describe the above | Updated | `README.md`, `SECURITY.md` |
| Release assets had no signed provenance | Fixed: GitHub Sigstore attestations for every release asset, in the build jobs and the release job | `.github/workflows/build.yml`, `tests/test_security_boundaries.py` |
| Denials reached MCP clients as ordinary text results | Fixed: failed tool calls carry `isError` in the JSON-RPC envelope | `blackoutkit/mcp_server.py`, `tests/test_security_boundaries.py` |
| Bearer tokens and URL userinfo credentials survived log scrubbing | Fixed: assignment values redact to end of line, URI credentials masked, redaction applied at log write time | `blackoutkit/log_redaction.py`, `blackoutkit/support_bundle.py`, `blackoutkit/recovery_audit.py`, `blackoutkit/daemon*/` |
| No documented egress inventory | Added `NETWORK_PRIVACY.md`, verified row by row against the code | `NETWORK_PRIVACY.md` |
| Dependency floors below advisory-patched versions | Raised (cryptography 50.0.0, Pillow 12.3.0, PyYAML 6.0.1, plus floor comments) | `pyproject.toml`, `requirements.txt`, `SBOM.json` |

---

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

`SBOM.json` is the maintained bill of materials, refreshed in-tree with the release it describes.
Its `versionInfo` fields record the **declared install floor** from `pyproject.toml` — the security
minimum, not a lockfile pin — and `tests/test_security_boundaries.py::test_declared_dependency_floors_match_the_sbom`
fails if the two ever drift apart.

**Notable dependencies and why their floors are where they are:**

| Package | Declared floor | Reason |
|---|---|---|
| **cryptography** | `>=50.0.0` | CVE-2026-69247 (PKCS#7 Bleichenbacher oracle), CVE-2026-69248/69249 (X.509 wildcard / chain handling), and the earlier wheel-bundled OpenSSL and `43.0.1` fixes underneath it |
| **certifi** | `>=2024.7.4` | TLS trust store used by httpx; removes the GLOBALTRUST root (CVE-2024-39689) and the e-Tugra root before it |
| **httpx[socks,http2]** | `>=0.28.0` | HTTP client for engine/DoH paths; above CVE-2021-41945 |
| **PyYAML** | `>=6.0.1` | Closes the remaining CVE-2020-1747 full-cover payload; only `safe_load` is used |
| **Pillow** (gui extra) | `>=12.3.0` | The 2026-07-20 batch (CVE-2026-59205/-59204/-59200/-59199 and friends) |
| **yt-dlp** (media extra) | `>=2026.7.4` | CVE-2026-55404 plus the 2026.6.9 aria2c/`--exec`/cookie-leak batch |
| **setuptools / wheel** (build system) | `>=83.0.0` / `>=0.46.2` | CVE-2026-59890, CVE-2025-47273, CVE-2024-6345, CVE-2026-24049 — build-time code is supply chain too |
| **scapy** (capture extra) | `>=2.5.0` | No fixed release exists for the untrusted-session pickle issue; Blackout never loads a `.session` file it did not create |
| **click**, **rich**, **typer**, **psutil**, **reportlab** | 8.1.7 / 13.7.1 / 0.12 / 6.0 / 4.0 | Above every published advisory for those projects; the CLI pair is kept low because help rendering is version-sensitive |

`requests` and `urllib3` are **not** dependencies and are deliberately not added: Blackout Kit imports
neither, so their advisory floors (`requests>=2.32.3`, `urllib3>=2.2.2`) do not apply, and pinning an
unused package would only widen the surface. HTTP paths use `httpx` or the standard library's
`urllib` + `ssl`.

## Compliance

- ✅ OWASP Top 10: Hardened against injection, authentication bypass, sensitive data exposure
- ✅ CWE-200: Credential safety verified
- ✅ CWE-90: Input validation hardened (SNI, DNS, URL parsing)
- ✅ CWE-362: Concurrent access protected via file locking

## Contact

- **Email:** kiacoder62@gmail.com
- **GitHub Issues:** [https://github.com/kiacoder/blackout-kit/issues](https://github.com/kiacoder/blackout-kit/issues)
