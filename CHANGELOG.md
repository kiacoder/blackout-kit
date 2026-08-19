# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Network analysis toolkit (Phase 1):** Eight new `blackout tools` commands for local network diagnostics — `subnet <cidr>` (subnet/broadcast/usable-range calculator), `connections [--established]` (live TCP/UDP connection table with process attribution via psutil), `scan-ports <host> [--ports ...]` (threaded TCP port scanner over a built-in common-services list or an explicit port list), `discover` (local /24 LAN sweep with ARP-table MAC lookup and reverse DNS), `dns-inspect` (compares system DNS resolution against a trusted DoH resolver to surface possible DNS interference, without false-positiving when the trusted resolver itself is unreachable), `speedtest-history` (terminal sparkline graph of past speedtest runs, now auto-recorded to a local JSON history on every `blackout tools speedtest`), `latency-monitor [host] [--interval]` (live-updating ping graph with rolling avg/jitter/loss, Ctrl+C to stop), and `bandwidth [--interval]` (live per-interface upload/download throughput via `psutil.net_io_counters`, Ctrl+C to stop).
- **Packet capture — `tools capture` (Phase 1 complete):** Live packet capture via `scapy`, with a scrolling protocol/source/destination view and a final protocol-breakdown + top-talkers summary on Ctrl+C. `blackout tools capture [iface] [--count N] [--filter "<bpf>"] [--host <ip>]`. Requires Npcap on Windows or libpcap on Linux — `blackout doctor` now checks for both, plus the `scapy` Python package, and reports actionable fixes instead of a raw traceback when either is missing. No deep protocol decoding (HTTP/TLS SNI) yet — deliberately out of scope for this pass.
- **Smart config rotation:** When a working endpoint fails (e.g. IP blocked), the daemon automatically rotates to the next saved proxy config instead of retrying the same dead endpoint. Controlled by `config_rotation` setting (default: enabled). Particularly useful in Russia where blocked IPs die instantly.
- **XHTTP transport support:** XRay now supports `type=xhttp` (and legacy `type=splithttp`) in V2Ray URIs, including `mode` parameter (auto/packet-up/stream-up). Works with REALITY.
- **Russia country profile:** Added `RU` as a first-class country profile with engine order `xray → hysteria2 → tuic → warp/gdpi/tun → psiphon`, recommended bypass DNS, and Russia-specific test URLs.
- **Russia transport preset:** Added `--russia` flag on `blackout connect` and `blackout start` that applies temporary local overrides (PRIVATE mode, DoH enabled, Iran-specific split-tunnel and fragmentation disabled) without rewriting saved settings. Overrides are forwarded into background daemon runs.
- **Country-aware routing:** XRay split-tunnel and TUN bypass domains are now country-aware — RU profile routes Yandex, VK, Ozon, and other Russian domestic domains direct instead of Iranian `.ir` domains. TUN direct DNS uses Yandex DNS (77.88.8.8) for RU.
- **`blackout help russia` topic:** Dedicated in-app help topic covering the RU profile, preset, field-verified transport notes, and known Russian filtering behavior.
- **ISP country-code detection:** `IspInfo` now carries `country_code` from ip-api.com, and `detect_country()` checks it before falling back to the country name.

### Changed
- **Preset mechanism refactor:** Converted `--iran` from persistent settings writes to temporary env-based overrides, matching the new `--russia` flow. Both presets now leave saved settings unchanged, even in background mode.
- **Documentation refresh:** Rewrote the public docs to align with the shipped 1.1.1 codebase, clarified platform scope, separated user and maintainer guides, expanded contributor templates, refreshed local project notes, and synchronized in-app help wording with the current command and runtime surface.

### Fixed
- **XRay TLS compatibility:** Removed the deprecated `allowInsecure` field from XRay `tlsSettings` that the current XRay runtime rejects with a config parse error.
- **Python TLS enum compatibility:** Added a fallback for `ssl.TLSVersion.TLS1_2` vs `TLSv1_2` in cert probing and SNI HTTP testing, which crashed on some Python builds.
- **Empty `xray_fragment` validation:** The Russia preset clears `xray_fragment` to disable Iran-specific fragmentation, but the validator rejected empty strings. Now accepts empty or `range,range`.

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
- **Typer CLI rewrite:** Modernized CLI routing using Typer while keeping compatibility with the monolithic dispatcher functions in `cli.py`.
- **Iran TIC 2026 profile:** Added `--iran` on `blackout connect` to apply a specialized local settings bundle.
- **Native GDPI runtime:** Added the experimental Go/WinDivert implementation exported through `blackout_core.dll`.
- **GDPI backend selection:** Added `gdpi_backend` with `legacy` as the stable default and `native` as an explicit experimental option.

## [1.1.0] - 2026-07-25

### Added
- **Consolidated test suite:** Added a `tests/` suite covering config parsing, saved configuration flows, engine helpers, and diagnostics-sensitive behavior.

### Changed
- **Go engine rebuilds:** Rebuilt the Windows and native runtime artifacts, including `blackout_core.dll`, `blackout_warp.dll`, and related assets.

### Fixed
- **IP scan cache writes:** Fixed a bug in `blackout scan` that bypassed the cache manager and failed to persist Cloudflare scan results correctly.
- **Cleaner relay logging:** Suppressed unnecessary Apps Script relay output when clients drop connections.
- **Port checking:** Improved `check_port_free` in the engine base class to use bind-based testing instead of connection probing.
- **Code cleanup:** Removed unused imports in `tools.py`.

## [1.0.1] - 2026-06-09

### Security & hardening
- **Codebase audit:** Ran an extensive audit across the project and fixed multiple security, logic, and concurrency issues.
- **Zip Slip fix:** Hardened `updater.py` against path traversal during archive extraction.
- **Privilege awareness:** Added proactive admin checks where Windows networking operations require elevation.
- **Subprocess deadlock prevention:** Redirected engine output away from blocking pipe setups that could freeze daemon paths.
- **Localization-safe Windows parsing:** Reworked network tooling to avoid brittle parsing of localized command output.
- **Graceful shutdowns:** Improved Go-engine shutdown handling so route and DNS state are less likely to be left behind.
- **Atomic cache writes:** Hardened scanner cache writes against corruption.
- **Update rollback stability:** Improved Windows update rollback behavior when files are locked.
- **HTTP relay robustness:** Fixed Apps Script relay issues around body exhaustion and header handling.
