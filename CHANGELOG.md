# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **Documentation accuracy:** Aligned public and in-app documentation with the shipped Linux engine subset, local-only routing recommendations, Windows proxy-bypass scope, targeted recovery boundaries, VLESS REALITY trust model, security-mode behavior, and the MCP server's actual tool dispatch scope.
- **WARP dependency graph:** Raised all patchable transitive Go dependencies to their published security fixes, including the critical `golang.org/x/crypto` advisories. The native WARP/Psiphon DLL graph is now verified and compiled in Windows CI.
- **mhrv certificate-store claim:** Corrected documentation that incorrectly described the embedded HTTP relay as an HTTPS MITM engine that installs a CA. mhrv never modifies Windows certificate stores, so certificate cleanup is not applicable.
- **Daemon restart resilience:** Failed engine restarts now stay alive through a bounded, cancellable exponential-backoff cycle rather than terminating the daemon immediately. Daemon state consistently records the daemon PID, including for DLL-backed engines.

### Added
- **Client-side VLESS REALITY:** Added parsing and exact round-trip storage for standard VLESS REALITY URIs, including public-key aliases, short IDs, spider paths, flow, gRPC service names, and TCP/WebSocket/gRPC transport settings. XRay/TUN now generate REALITY outbounds without TLS certificate probes or TLS-only policy fields; CLI lists remain redacted.
- **Safe terminal UX bundle:** Added redacted friendly failure panels, interactive-only Rich prompts, `blackout status --watch`, local-only `blackout route` recommendations, and a persistent `blackout theme dark|light` Rich palette. These views never probe remote nodes, start engines, download components, repair networking, or change the host terminal/GUI theme.
- **Linux x86_64 TUN runtime:** Added the supported Linux XRay → sing-box system-tunnel path for Ubuntu/Debian, Fedora, and Arch. It uses the managed `blackout-engine` runner, requires `sudo`, routes DNS through the tunnel, and keeps Linux firewall and route-table state under Blackout Kit-owned names.
- **Linux kill switch:** Added endpoint-scoped nftables protection with an iptables/ip6tables fallback. It refuses activation without a validated proxy endpoint and removes only `inet blackoutkit` / `BLACKOUTKIT_*` rules on cleanup.
- **Explicit ARP-cache repair:** Added `blackout tools arp-flush` and `blackout fix --flush-arp`. ARP/neighbor cache clearing is never part of default recovery or daemon reconnects.
- **Dependabot residual-risk tracking:** Documented the only two remaining WARP graph advisories—legacy `pion/dtls/v2` and `pion/stun` lines with no upstream patch release—rather than treating them as resolved.
- **Daemon-safe targeted reconnect recovery:** After a failed restart, the daemon can repair only verified stale Blackout routes, loopback DNS, and Blackout-owned virtual adapters before retrying. It preserves the active system proxy and kill switch and never runs `route -f`, Winsock, TCP/IP, or DHCP resets.
- **Reconnect policy settings:** Added `reconnect_initial_delay` and `reconnect_max_delay` to tune capped automatic retry timing.
- **Targeted post-crash network recovery:** `blackout fix` and `blackout tools netfix` now clear stale Blackout proxy/routes, restore DHCP DNS only from loopback DNS on physical adapters, restart only the deterministic BlackoutKit-TUN adapter, and flush DNS without disturbing unrelated VPNs.
- **Explicit emergency resets:** `blackout fix --full-route-reset` runs `route -f` only when deliberately requested; `blackout fix --full-stack-reset` separately enables Winsock, TCP/IP, autotuning, and DHCP reset.

### Changed
- **Virtual adapter diagnostics:** `blackout doctor` distinguishes detected healthy TUN/TAP/Wintun/WireGuard adapters from stale post-crash state.

## [1.1.1] - 2026-08-14
### Fixed
- Packaged every `blackoutkit` subpackage and Typer runtime dependency so source installs and the standalone executable can start correctly.
- Restored documented Typer commands and options for diagnostics, logs, binaries, country profiles, emergency background mode, certificate overrides, help, and updates.
- Passed Hysteria2/TUIC configuration directly into the native sing-box DLL so proxy credentials are not written to a temporary file.
- Corrected the WARP/Psiphon Go module's invalid Pion DTLS version and stopped tracking generated WARP/Psiphon identity and datastore caches.

### Changed
- Added CI smoke tests for the Python wheel and frozen executable.
- Updated the roadmap and command documentation to reflect the actual v1.1 feature set.

### Added
- **Typer CLI rewrite:** Modernized the CLI routing using Typer, maintaining backward compatibility with the monolithic `cli.py` legacy dispatcher functions while improving command organization.
- **Iran TIC 2026 Evasion Flag:** Added `--iran` flag to `blackout connect` which automatically activates a specialized bypass profile (Private mode, Firefox fingerprinting, ArvanCloud SNI spoofing, and TLS record fragmentation).
- **Native GDPI runtime:** Added the experimental Go/WinDivert implementation with `StartGDPIC`, `StopGDPIC`, and `IsGDPIRunningC` exports through `blackout_core.dll`.
- **GDPI backend selection:** Added `gdpi_backend` with `legacy` as the stable default and `native` as an explicit experimental option.

### Fixed
- **Syntax and Lint Fixes:** Addressed severe `F821` undefined variable errors (like `os` in `elevate.py`), removed `F401` unused imports, fixed `F541` missing f-string placeholders, and cleared unused local variables.
- **Engine selection consistency:** `xray` is now exposed consistently across CLI choices, daemon startup, and settings validation.
- **QUIC engine routing:** `hysteria2` and `tuic` now use protocol-specific engine classes and refuse mismatched configs instead of silently picking the wrong sing-box config.
- **Status accuracy:** `blackout status` now derives HTTP/SOCKS checks from the active engine instead of assuming XRay ports for every engine.
- **Background health checks:** SOCKS-style proxy targets are normalized before heartbeat/health probes in foreground and daemon monitoring paths.
- **Binary updater stability:** `blackout bins update` no longer references an undefined `installed` variable.
- **CLI startup fallback:** missing-`rich` error handling in `blackout.py` now degrades to plain-text output without secondary crash loops in non-interactive mode.

### Changed
- **Dependencies Bump:** Upgraded `cryptography` to `>=43.0.0`, `httpx[http2]` to `>=0.27.0`, `rich` to `>=13.7.1`, and `psutil` to `>=6.0.0` across `pyproject.toml` and `requirements.txt` to clear Dependabot security alerts.
- **Theme setting behavior:** `color_theme` now takes effect in the CLI settings flow instead of being dead configuration.
- **GDPI product direction:** the stable legacy GoodbyeDPI path remains the default backend, while the native Go/WinDivert implementation is treated as experimental until it reaches parity.
- **Docs consistency:** README, roadmap, and metadata text now reflect the actual engine set, country profiles, current command surface, and GDPI backend split.

## [1.1.0] - 2026-07-25
### Added
- **Consolidated Test Suite:** Created a robust suite under `tests/` using `pytest`, testing VMess parsing (`_parse_vmess`), configuration saving, `is_sni_compatible`, and network utility diagnostics (`ping_stats`).

### Changed
- **Updated Go Engines & Rebuilds:** Upgraded Go engine modules to latest versions and cross-compiled the Windows binary assets (`blackout_core.dll`, `blackout_warp.dll`, `blackout-engine.exe`) using CGO toolchains.

### Fixed
- **IP Scan Cache Write:** Fixed a bug in `blackout scan` that bypassed the cache manager, causing it to fail saving Cloudflare IP results to `scan_cache.json` and triggering false preflight warnings.
- **Clean Proxy Stderr:** Overrode Google Apps Script connection handlers to suppress stdout/stderr stack traces when clients drop connections.
- **Robust Port Checking:** Improved `check_port_free` in the base engine class to use socket `bind` tests with `SO_REUSEADDR` rather than relying on socket connection probes.
- **Code Cleanup:** Removed unused Python imports (`Path`, `Panel`, `latency_color`) inside `tools.py` to optimize import times and code health.

## [1.0.1] - 2026-06-09
### Security & Hardening
- **Extensive Codebase Audit:** Ran 10 autonomous agents to audit all modules for security, logic, and concurrency bugs.
- **Fixed Path Traversal:** Fixed a critical Zip Slip vulnerability in `updater.py` that allowed rogue updates to escape the project directory.
- **Fixed Silent UAC Failures:** Core network operations (MTU, DNS) now proactively check for administrator privileges instead of failing silently.
- **Fixed Subprocess Deadlocks:** Redirected standard output to `DEVNULL` across all proxy engines, preventing silent daemon freezes caused by unread OS pipe buffers filling up.
- **Localization Bug Fixes:** Refactored `tools.py` to use `psutil` and `PowerShell` instead of scraping hardcoded English strings from `netsh`/`ipconfig`, ensuring full compatibility with non-English Windows setups.
- **Graceful Shutdowns:** Added `SIGINT`/`SIGTERM` handling to Go proxy wrappers (`xray`, `singbox`). Hard-kills no longer corrupt Windows routing tables or leave system proxy states mangled.
- **Concurrency Safety:** Applied safe file-writing patterns with temporary files and atomic replacements for the `ip_scanner` cache to prevent race conditions during concurrent IP tests.
- **Robust Updates:** Fixed a bug on Windows where update rollbacks would fail due to active Python file locks, corrupting the app directory.
- **HTTP Engine Stability:** Fixed body exhaustion and multi-value header mishandling in the Google Apps Script HTTP relay engine.
