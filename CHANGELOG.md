# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- **Native GDPI runtime:** Added the experimental Go/WinDivert implementation with `StartGDPIC`, `StopGDPIC`, and `IsGDPIRunningC` exports through `blackout_core.dll`.
- **GDPI backend selection:** Added `gdpi_backend` with `legacy` as the stable default and `native` as an explicit experimental option.

### Fixed
- **Engine selection consistency:** `xray` is now exposed consistently across CLI choices, daemon startup, and settings validation.
- **QUIC engine routing:** `hysteria2` and `tuic` now use protocol-specific engine classes and refuse mismatched configs instead of silently picking the wrong sing-box config.
- **Status accuracy:** `blackout status` now derives HTTP/SOCKS checks from the active engine instead of assuming XRay ports for every engine.
- **Background health checks:** SOCKS-style proxy targets are normalized before heartbeat/health probes in foreground and daemon monitoring paths.
- **Binary updater stability:** `blackout bins update` no longer references an undefined `installed` variable.
- **CLI startup fallback:** missing-`rich` error handling in `blackout.py` now degrades to plain-text output without secondary crash loops in non-interactive mode.

### Changed
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
