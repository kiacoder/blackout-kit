# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.10.0] - 2026-10-19

### Added
- **`blackout update` — self-updater command.** Checks GitHub Releases for a
  newer build, shows the release notes, and installs in place with
  `--apply` (digest-verified download, backup/rollback, frozen-exe aware —
  the machinery existed since 1.8; it is now reachable from the modern CLI).

### Fixed
- **CodeQL High alerts cleared in the AmneziaWG core** — provable bounds
  validation at every flagged integer conversion (tun fd, fwmark, MTU, port)
  in `main.go`, `conn/mark_unix.go`, `tun/netstack/tun.go`.
- **`allowInsecure` is never emitted for Xray 25+** on desktop either — the
  bundled Xray 26.3.27 rejects the key outright, which broke every
  security=tls outbound (same fix the mobile builder received).

## [1.9.0] - 2026-10-19

### Added
- **HTTP CONNECT proxy for AmneziaWG.** Windows (WinINET) — and therefore Chrome/Edge — cannot
  use a SOCKS system proxy, so the daemon's `socks=127.0.0.1:11080` was a dead end for browsers
  even when the tunnel was healthy. The core now also serves **HTTP CONNECT** on
  `awg_http_port` (default **11081**) over the same netstack; the daemon advertises that as the
  system proxy while SOCKS5 stays available on `awg_socks_port`.
- **Dedicated `awg_socks_port` (default 11080) / `awg_http_port` (default 11081).** AmneziaWG no
  longer collides with an XRay/v2rayN instance holding `xray_socks_port` (10808); readiness
  checks and proxy details follow the new settings.

### Added
- **Native AmneziaWG engine (`blackout start awg`)** — replaces the sing-box stub with a real
  userspace core (`core/amneziawg-go`, built as `bins/awg-go.exe` / `bins/awg-go`). It parses
  standard AmneziaWG `.conf` files (Jc/Jmin/Jmax, S1–S4, H1–H4, I1–I5 and the AWG 2.0 extras),
  converts keys from base64 to the hex form the UAPI requires, forwards every obfuscation
  parameter to the device, terminates the tunnel in wireguard-go's in-process netstack and
  exposes a **local SOCKS5 proxy** — no TUN device, no admin rights, no sing-box outbound
  patchset. Accepts `awg_config_file` or an `awg://` URI (base64 payload or query parameters).
  **Verified end to end (2026-10-19):** handshake on the production server (1.5 MB transferred,
  784 packets on `awg0`), `curl` egress returning the server IP, and YouTube 200 through both the
  SOCKS5 and HTTP proxies.
  Registered in `blackout bins` as "AmneziaWG Core (awg-go)". Mobile bindings
  (`cmd/awg-mobile`: StartTunnel(configText, tunFd) / StopTunnel / GetTunnelStats) compile for
  linux/arm64 (Android) and darwin (iOS) via `gomobile bind`.
- **Roadmap Phase 10: Extreme Low-Spec, Potato Hardware & Embedded Architecture** — Documented sub-25MB memory architecture (`docs/POTATO_HARDWARE_SPEC.md`), C99/Lean-Go `blackout-microd`, non-AES-NI ChaCha20-Poly1305 hardware auto-negotiation, and static zero-allocation network rings.
- **Roadmap Phase 11: Black Series Hardware & High-Performance Interop** — Documented `Black-Surge` 0.5ms kernel timer integration (`docs/BLACK_TITAN_INTEGRATION.md`), Iris-style 32-byte packed bitstream IPC v2, Epic UE5.8-style async MCP handlers (`FResultCallback`), and proactive neural DPI detection.
- **Batch config checker (`python -m blackoutkit.config_check`)** — the same idea the mobile

  client uses: every saved config is started in its own short-lived core on a private port and
  asked to **fetch a real website** (`generate_204`), not just ping a port. Checks run in
  parallel, so all 8 configs take ~5s instead of 8× the wall time of a serial loop, and the
  output ranks them by latency with a "fastest" pick. `--json` for scripting, `--workers` to
  tune parallelism.
- **`tray_enabled` setting (default `false`)** — opt back into the daemon's system tray icon
  (with its Quit / Disconnect menu). The tray is off by default so the daemon runs silently in
  the background with no taskbar presence.

### Fixed
- **The DoH chain could never start on a filtered network.** The XRay DNS servers used
  `https+local://cloudflare-dns.com/dns-query` and `https+local://dns.google/dns-query` —
  `https+local` requires resolving the DoH hostname through the **local resolver first**,
  which on filtered networks returns poisoned or empty answers for exactly those names.
  Both DoH entries were therefore dead on arrival and every lookup fell through to the
  poisoned local resolver. The chain now starts with IP-literal endpoints
  (`https://1.1.1.1/dns-query`, `https://8.8.8.8/dns-query`) that need no name resolution.
  Regression-tested (`tests/test_xray_dns_bootstrap.py`).
- **Engine processes no longer flash a console window on every start.** The daemon runs
  console-free (`pythonw.exe`), but the shared `Engine.start_process` spawned engine binaries
  without `CREATE_NO_WINDOW` — so on Windows every engine start, restart and config rotation
  made Windows allocate a brand-new console window (reported live as empty windows repeatedly
  opening and closing while working). The spawn now passes the flag on Windows like the
  engines that already did; regression-tested.
- **`set_system_proxy` reported success without checking the write.** It wrote the WinINET keys,
  called `_notify_proxy_change()` and returned True — even when another VPN client (Hotspot
  Shield keeps its own WinINET settings) or a policy swallowed the write. That is how
  "System proxy set to 127.0.0.1:10809" landed in the log while `blackout status` read the
  registry back as Off and every browser bypassed the tunnel. The write is now verified by
  reading it back, and a swallowed write returns False with the exact reason.
- **The daemon now keeps the system proxy pointing at the tunnel.** Its heartbeat re-applies the
  proxy when it is not ours, and says plainly which manager is overriding it instead of leaving
  the tunnel up and unused.
- **The heartbeat reported a meaningless latency.** `Heartbeat OK — proxy latency: 0ms` used a
  localhost TCP connect; it now reports the data probe's real latency.
- **The daemon rotated away from healthy engines until it gave up.** The startup data-phase probe
  fetched a real URL with a 0.2s timeout (needs ~1s), so it failed every time; two failures
  rotated, three exhausted the budget. Budget is now 15s/2s/5s, a listener that has not opened
  yet counts as "still booting" rather than "rotate", and XRay — which already proves the tunnel
  carries traffic — is not re-probed (`Engine.verified`).
- **`blackout status` claimed "● Connected" over two closed listeners.** It now says
  "● Starting (listeners not open yet)" until one is actually open, and a dead engine is
  reported with its exit code instead of a bare "proxy port stopped responding".

### Fixed
- **XRay treated "port opened" as "connected", so one dead config meant total failure.** The engine selected a single config (by rotation offset), waited for its listening port, and called that success. A config that opens its ports and then rejects every request — a REALITY server that closes the handshake with `EOF` is the common case — therefore looked perfectly healthy, and the other configs in the vault were never tried. The engine now verifies the tunnel with a **real request through its own proxy** (`http://www.gstatic.com/generate_204`, then Cloudflare's) and, when it picked the config itself, **fails over to the next stored config** (up to 6, in rotation order) instead of giving up. An explicitly supplied `proxy_config` is still honoured as-is, with a single attempt.
- **Restarting an engine instance crashed with `FileNotFoundError`.** `stop()` removes the engine's temporary config directory, but a restart on the same instance (the daemon's restart path, or a failover attempt) then failed to write `xray_config.json`. The directory is now recreated before use.
- **The core's error log was disabled, hiding every failure.** Generated configs set `"error": "none"`, so a rejected handshake left no trace at all. The core now writes to `xray_error.log` in the engine's config directory.
- **The cert monitor could never see a line.** It read the core's stderr, but the process is spawned with `stderr=DEVNULL` (so a chatty core cannot fill a pipe and stall). It now tails the core's error log file instead.
- **Failures and skips are reported honestly.** "No engines could start" now carries the per-config reasons, and a successful connect says which configs it had to skip and why.

### Added
- `tests/test_xray_failover.py` — 5 tests covering failover order, first-success short-circuit, total-failure reporting, the explicit-config rule, and the attempt cap.

## [1.8.0] - 2026-10-16

**Highlights:** Roadmap **Phase 7** (Enterprise & Team: RBAC, centralized policy, multi-device dashboard, GDPR/HIPAA/SOC 2 compliance) and **Phase 8** (Developer Ecosystem: Python SDK, plugin system, REST API v2, community marketplace) — plus a crash-safety pass that stops a Go panic or an unclean exit from blackholing the machine's network.

### Added
- **Self-heal + VM safety (`blackoutkit/self_heal.py`):** the new `blackout tools vmcheck` reports VM detection (hypervisor fingerprinting), leftover Blackout-owned state, and the recovery steps to take — plus the recommendation to snapshot a VM before testing. `blackout tools netfix` now also heals the owned firewall rules and leftover TUN, and preview mode lists those steps.
- **Enterprise & Team — RBAC + centralized policy (`blackoutkit/enterprise/`, Roadmap Phase 7):** a permission vocabulary with viewer/operator/admin roles, a distributable JSON **policy document** (roles + principals + default role), and an optional **HMAC signature** so a device can prove the policy it loaded was not tampered with in transit. CLI `blackout enterprise [roles|policy|assign]`.
- **Multi-device dashboard (Phase 7):** `blackoutkit/enterprise/devices.py` — a device registry with heartbeats and an online/offline dashboard aggregation. CLI `blackout enterprise [devices|device-add]`.
- **Compliance checks — GDPR/HIPAA/SOC 2 (Phase 7):** `blackoutkit/enterprise/compliance.py` turns the effective settings + access policy into a scored control checklist (explicitly *technical evidence, not certification*). It surfaces the GDPR data-minimization vs HIPAA audit-control tension instead of pretending one setting satisfies both. CLI `blackout enterprise compliance`, SDK `bk.compliance()`, API `/api/v2/devices` + `/api/v2/compliance`.
- **Plugin system (`blackoutkit/plugins.py`, Roadmap Phase 8):** load user plugins that add custom **rules**, **analyzers**, and **exporters** from `~/.blackout-kit/plugins` (or `$BLACKOUT_PLUGIN_DIR`). Gated behind the new `plugins_enabled` setting (default **off**) because importing a plugin executes arbitrary Python; a broken plugin is isolated (reported, never fatal). CLI: `blackout tools plugins [list|run]`.
- **Community marketplace (`blackoutkit/marketplace.py`, Roadmap Phase 8):** search/list a plugin catalog and install plugins with mandatory **SHA-256 verification** (a mismatch aborts before anything is written). Network egress only on explicit `refresh`/`install`. CLI: `blackout tools marketplace [list|search|refresh|install|remove]`.
- **REST API v2 (`blackoutkit/webhooks.py` + `blackoutkit/api.py`, Roadmap Phase 8):** `/api/v2/events`, `/api/v2/webhooks` (GET/POST/DELETE), `/api/v2/plugins`, and a `/api/v2/ws/events` **WebSocket** live event stream. Webhooks POST JSON with an optional HMAC-SHA256 signature (`X-Blackout-Signature`); the loopback-only guard now covers the WebSocket endpoint too.
- **Python SDK (`blackoutkit.sdk`, Roadmap Phase 8):** a stable, thin facade for embedding Blackout Kit — `from blackoutkit.sdk import Blackout`. Covers settings, engine capabilities, readiness, doctor diagnostics, daemon control (`connect`/`disconnect`/`status`), and observability (metrics, connections, bandwidth, anomalies, threat-feed stats, recommendations, benchmarks, reports). It delegates to the same internals the CLI uses, so the SDK and CLI can never disagree; typed exceptions (`BlackoutError` + `NotConnectedError`/`EngineError`/`SettingsError`/`DependencyError`). No optional dependencies required.

### Fixed
- **A Go panic in `blackout_core.dll` killed the entire host process.** The core is loaded into the Python process via ctypes, and there was **zero `recover()` anywhere in the Go code** — so a panic in any of the 13 goroutines (or a cgo-exported entry point) was fatal, terminating the CLI instantly and skipping every Python cleanup handler (`finally`, `atexit`, the console close handler), stranding whatever system state was held. Added `engine/recover.go` with `safeGo` (goroutine wrapper) and `safeCall` (converts a panic into an error so an entry point returns a failure code), applied to every cgo-exported function and every goroutine across `sni.go`, `mhrv.go`, `neighbor.go`, `scanner.go`, `gdpi_windows.go`, `wireguard.go`, and `exports.go`. A panic is now a logged, recoverable error. Verified by Go tests that would crash the test binary if recovery failed, plus `go vet`.
- **Daemon startup never healed leftover system state.** A new daemon inherited a dead system proxy, owned firewall rules, or a leftover TUN from a hard-killed predecessor — startup only cleaned stale *records*, not system state, so a restarted daemon ran on top of a blackholed network stack. The daemon now clears its own leftovers at startup. Every heal operation is owned-only (it removes only what Blackout created and named), which makes running it unconditionally safe; the broader route/DNS recovery stays a user action via `blackout netfix`. (+15 tests)
- **System proxy left pointing at a dead local port after a crash — blackholes every app on the machine.** Reported live: a tester's VM lost all internet the moment the app crashed. Three exit paths never restored the owned proxy: (1) `typer_cli.main()` caught `KeyboardInterrupt`/`Exception` and exited without cleanup, (2) `install_console_close_handler()` only handled console events 2/5/6 — missing Ctrl+C (0) and Ctrl+Break (1), (3) there was no `atexit` safety net, and the daemon installed neither handler. Fixed by recording the **owning PID** in the proxy-ownership record and adding `install_atexit_proxy_restore()` plus a PID-scoped `cleanup_owned_system_proxy(owner_pid=...)`, now installed in **both** the CLI and the daemon — scoped so a short-lived CLI process can never tear down a proxy the daemon still owns. The watchdog now logs why it bails instead of silently exiting with no protection. (+9 tests)
- **CodeQL `py/stack-trace-exposure` in the REST API (3 alerts, medium):** the `/api/metrics`, `/api/connections`, and `/api/bandwidth` collectors embedded the raw exception text (`f"...: {exc}"`) in the JSON response, exposing internal detail to clients. They now log the detail server-side and return a stable, generic `reason`; no exception text reaches the response.

## [1.7.0] - 2026-10-15

### Added
- **Phase 6 — Advanced Automation & Insights, completed (2026-10-15):** the four Phase 6 engines (anomaly detection, predictive optimization, threat-intel feeds, advanced reporting) already existed as libraries with CLI commands and tests; this closes the **live-integration** gap that made them query-only:
  - **Live security monitoring** — new `blackoutkit/security_observer.py` (`SecurityObserver`) feeds each sampled connection to the `AnomalyDetector` and checks the remote endpoint against the `ThreatFeedsManager` IP/domain blocklists, returning anomaly/threat hits. The daemon's `TrafficMonitor` gained an injectable `observer` hook (failure-isolated) and runs the observer when the new `security_monitor_enabled` setting is on — with or without the audit log (detection without persisting the per-connection trail).
  - **Predictive auto-tune** — `blackout tools predict --apply` now applies the recommendations that map to a global setting (`config_rotation`); `transport`/`dns` are reported as manual because they are per-config/transport choices with no global setting.
- **Read-only REST API (`blackoutkit/api.py`, Roadmap Phase 5):** `GET /api/health`, `/api/metrics`, `/api/connections?process=&port=&established=`, and `/api/bandwidth` expose the same local data the CLI already reads. The collectors have no FastAPI dependency and are independently unit-tested; endpoints degrade gracefully (return `available: false` + a reason) instead of erroring when a source is unavailable. Optional dependency: `pip install "blackout-kit[api]"`, then `uvicorn blackoutkit.api:app`.
- **`blackout bench` command (`blackoutkit/benchmarks.py`, Roadmap Phase 5):** measures daemon RSS (budget < 80 MB) and IPC round-trip p99 (budget < 10 ms) against the local core, reporting "unavailable" rather than guessing when the daemon is stopped. Read-only — it starts no engines and changes no networking. `--json` supported.
- **`xray_system_proxy_mode` setting (`http` / `mixed`):** the XRay-family engines (sni, xray, legend) can now serve the system proxy from a `mixed` HTTP+SOCKS inbound on `xray_socks_port` instead of the plain HTTP listener on `xray_http_port`. The engine config switches the `socks-in` inbound protocol to `mixed` in that mode, capability listener text describes both options, and readiness still checks both listener ports. Default remains `http`, so existing setups are unchanged.
- **Canonical TUN engine-stack builder (`blackoutkit/engine_stack.py`):** one shared stack definition for the TUN target — Windows starts SNI → XRay → TUN sequentially, Linux starts XRay → TUN — consumed by both the foreground CLI path and the active daemon. A failed TUN start stops the already-started upstream engines in reverse order, and normal daemon shutdown now also stops the active engines in reverse. Linux's managed-runner, direct saved-config behavior is untouched.

### Fixed
- **Second self-audit pass — Phase 5 + 6 (2026-10-15):**
  - **Live threat hits were computed and thrown away.** `SecurityObserver` returned blocklist hits but the daemon discards `observe()`'s return value, so a live match produced no output. Hits are now logged (`WARNING`).
  - `security_observer.split_endpoint("host:")` returned `"host:"` (with the colon) as the host instead of `"host"`.
  - The observer fed the anomaly detector an empty destination for peer-less (listening) samples, seeding the detector's per-destination stats with an empty key — now skipped.
  - The REST API loopback guard denied IPv4-mapped IPv6 loopback (`::ffff:127.0.0.1`) — now allowed.
  - `blackout bench` now attempts a best-effort IPC handshake before pinging (some core builds reject requests until handshaken).
  - `blackout tools predict --apply` output is now markup-escaped (a failing apply's exception text could contain a `[...]` token).
  - A broken `SecurityObserver` no longer disables the daemon's monitor — it degrades to "no observer", preserving audit logging.
- **Phase 5 self-audit fixes (2026-10-15):**
  - **Daemon RSS/state was identified by process name**, which is wrong in both directions: a frozen CLI is `blackout.exe` (a "blackout" name match made `blackout bench` / `/api/metrics` report the CLI itself as the daemon), and a dev daemon is `pythonw.exe` (the match missed it). Both now resolve the daemon via its PID lease (`daemon.get_pid()`).
  - **Dynamic text was interpolated into Rich markup unescaped**, so an exception message containing a `[...]` token (e.g. `failed to open [socks] proxy`) was silently swallowed or injected colour. `cli_error_handler.format_error` and the benchmark renderer now `escape()` summary/reason/hint text.
  - **`blackout bench` no longer runs a ~2 s IPC connect loop when no daemon is running** — the IPC probe is gated on the daemon lease, so the no-daemon case is instant.
  - **The REST API now denies non-loopback clients by default** (HTTP 403) because it has no authentication and exposes local process/connection data; set `BLACKOUT_API_ALLOW_REMOTE=1` to opt in. It also logs a warning when launched with a non-loopback `--host`.
- **The recurring daemon health probe no longer mis-protocols SOCKS endpoints.** The heartbeat kept only the host/port from `get_engine_proxy_details()` and always ran the HTTP-proxy tester, so healthy SOCKS-only engines (Psiphon, Tor, WARP, socks-tunnel, Hysteria2, TUIC — and the XRay family in `mixed` mode) accumulated false data-phase failures and could be restarted with config rotation even though the proxy worked. The probe now preserves the `socks=` marker and tests SOCKS endpoints with the SOCKS5 tester (mirroring the startup probe). A genuinely unusable endpoint still fails twice and rotates. Regression-tested end to end with local fake HTTP and SOCKS5 proxies — no live network in tests.
- **The active daemon honors `fallback_enabled`.** Initial engine selection in `blackoutkit/daemon/__init__.py` now goes through `start_initial_engine`, which tries the selected engine and only walks platform-filtered fallback candidates when the setting allows it; the chosen engine (primary or fallback) is what receives the system proxy, tray, and health monitoring. The legacy flat `blackoutkit/daemon.py` is not on the shipped path and was left alone. The old "integration" test that never exercised the daemon was replaced with entrypoint behavior tests for the enabled, disabled, and skip-failed-candidate cases.

### Changed
- **Auto-wrapping tables (Roadmap Phase 5):** `theme.make_table` now folds long cells (`overflow="fold"`) so `tools connections`, `tools discover`, and the media/torrent tables wrap long remote addresses, process paths, and titles instead of overflowing the terminal. Pass `wrap=False` for fixed-width token columns.
- **Standardized CLI errors wired in (Roadmap Phase 5):** the existing `cli_error_handler.format_error` (reason + hint format) is now used on the bins-download, media-start, and torrent-start failure paths. `theme.spinner` now wraps the media/torrent start paths.
- **Regional preset files validated (Roadmap Phase 5):** `configs/presets/{ru,ir,cn}.yaml` (with routing docs) already shipped; a schema test now locks them.
- **TUN capability metadata is truthful about what TUN is.** TUN is documented as a network tunnel — `local_proxy` off, no HTTP/SOCKS listener claims, no system-proxy side effect — instead of reserving the XRay proxy ports as its own listeners; readiness no longer treats those upstream ports as TUN prerequisites. The capability notes state explicitly that WinTUN driver availability is not independently verified (a bundled `wintun.dll` is not proof the kernel driver is loaded) and that sing-box startup remains the final prerequisite check.

### Tests
- Phase 6 coverage (21 new tests): `test_security_observer.py` (SecurityObserver + TrafficMonitor observer hook) and `test_phase6_integration.py` (daemon monitor gating, `security_monitor_enabled` registration/coercion, predictor `--apply`).
- Phase 5 coverage (29 new tests): REST API collectors + endpoints (`test_api.py`), benchmark math + IPC measurement (`test_benchmarks.py`), standardized-error formatting (`test_cli_error_handler.py`), responsive-table wrapping (`test_responsive_tables.py`), regional-preset schema (`test_regional_presets.py`), and spinner helpers (`test_progress_spinners.py`).
- New `tests/test_tun_stack.py` covers platform stack composition, sequential startup, foreground- and daemon-wrapper rollback ordering, and reverse-order shutdown with fake engines only.
- Daemon probe tests drive the heartbeat with local fake HTTP and SOCKS5 proxy fixtures (protocol dispatch, healthy-SOCKS-no-rotation, genuine-failure-rotates); readiness/capability regressions pin the truthful TUN metadata and the mixed-mode listener checks; fallback entrypoint tests cover enabled/disabled/skipped candidates without starting real engines.


## [1.6.0] - 2026-10-11

### Added
- **`blackout-core` ships as a release asset.** CI now builds the v2 daemon into `dist/` on both platforms (`blackout-core-windows-amd64.exe`, `blackout-core-linux-amd64`), attests it with Sigstore provenance, covers it in `checksums.txt`, and publishes it with every release. A `blackout bins download blackout-core` registry entry (self-hosted, SHA-256-verified, structural PE check) installs it, so the socks-tunnel engine no longer requires a local Go toolchain. Readiness reports a `Runtime: blackout-core` check for the engine, and `blackout doctor` gains a fixable bins check via the generic registry loop.
- **CI action pins refreshed:** `actions/checkout` v4 → v5 (Node 20 deprecation warning on every run).


## [1.5.0] - 2026-10-11

> This release ships the carried pre-release hardening batch that had been accumulating
> under "Unreleased" (provenance, MCP auth, redaction, dependency floors, installer
> checksums, boundary tests, the xray-core advisory bump), plus the new v2 socks-tunnel
> CLI wiring below.

### Added
- **The Python CLI can now launch and manage the v2 socks-tunnel.** New engine `socks-tunnel` (registered in `ENGINE_REGISTRY`, `ALL_ENGINE_CHOICES`, and the daemon engine map) supervises the Go `blackout-core` daemon: it spawns the binary, connects over the v2 named-pipe/Unix-socket control channel (`blackoutkit/v2_ipc.py` client speaking the BKV2 framed protocol), performs the handshake, starts the loopback SOCKS5 tunnel on the new `v2_tunnel_port` setting (default 18080), applies `sni_fake_sni` as a best-effort `tune`, and maps the tunnel port into system-proxy setup. Stop goes through IPC `stop` (force-closing live sessions) before the process kill. The binary is discovered via `BLACKOUT_CORE_BIN`, `bins/`, or `dist/`; when absent, start fails with the exact build command. Verified live: real `blackout-core` handshake, running status with telemetry, and clean stop.

### Security
- **`xray-core` bumped past GHSA-5wf9-h793-w73c:** `engine/go.mod` moves from `v1.260327.0` to the patched commit `64fada32b5b9` (`v1.260327.1-0.20260710210335-64fada32b5b9`). `go.sum` is regenerated for the patched commit.
- **CI security scanning:** a `security-scan` job in `.github/workflows/build.yml` runs Bandit (`-lll`, fail on HIGH — the ~261 accepted LOW findings are documented as out of the gate) and pip-audit (`--skip-editable`) on every push and pull request. Both verified green locally before landing.
- **Privilege model and egress documentation:** README gains a Security & Privilege Model section (userspace proxying needs no admin, drivers, or Defender exclusions), `NETWORK_PRIVACY.md` §12 records five remediation candidates and confirms the unwired `adblock_auto_update_interval_hours` setting, and the PowerShell SHA-256 check now parses the `<hash>  blackout.exe` format and compares case-insensitively.
- **Signed build provenance for every release asset:** `build-windows`, `build-linux`, `package-smoke`, and the `release` job in `.github/workflows/build.yml` now request an OIDC token (`id-token: write`, `attestations: write`, `contents: write`) and run `actions/attest-build-provenance@v2` immediately after the artifacts are produced — `dist/blackout.exe`, the Linux runtimes, the wheel/sdist, `checksums.txt`, `blackout.exe.sha256`, and `blackout-source.zip`. Users and auditors verify with `gh attestation verify blackout.exe --repo kiacoder/blackout-kit`. Attestation steps are skipped on `pull_request` (a fork's token cannot mint a certificate) rather than weakened.
- **Credential redaction now fails closed at log write time:** new `blackoutkit/log_redaction.py` is the single authority used by both daemon log handlers and by `blackoutkit/support_bundle.py`. Fixed three real leaks it exposed: an `Authorization: Bearer <jwt>` value leaked past the first word (assignment values now redact to end of line), URL userinfo credentials in `scheme://user:pass@host` (including passwords containing `@`) are replaced by the marker, and `recovery_audit.redact()` did not know `authorization`/`bearer`/`passphrase`/`api_key`/`cookie` keys at all.
- **MCP denials are protocol-level failures:** a refused or failed tool call now carries `result.isError` in the JSON-RPC envelope, so a client that does not parse prose cannot treat a denial as an executed operation.
- **DoH listener bind allow-list made explicit:** `DOH_PROXY_ALLOWED_BINDS` (`127.0.0.1`, `::1`) now drives the guard, hostnames are refused, and `NeighborShareEngine.bind_address` exposes the loopback-vs-LAN decision the native forwarder receives.
- **Dependency floors raised to advisory-patched versions** (`cryptography>=50.0.0`, `certifi>=2024.7.4`, `PyYAML>=6.0.1`, `Pillow>=12.3.0`, `yt-dlp>=2026.7.4`, plus build-system `setuptools>=83.0.0` / `wheel>=0.46.2`), each with the CVE reason recorded in `pyproject.toml`. `requests`/`urllib3` are not imported anywhere, so no unused dependency was added to pin their advisories; `requirements.txt` says so explicitly.
- **`choco/tools/chocolateyinstall.ps1` checksum sanitized:** the malformed non-hexadecimal `checksum64` is replaced by a parser-safe 64-character placeholder (`'0' * 64`) with an optional `--package-parameters="checksum=<64 hex>"` override that is validated as SHA-256. The placeholder aborts before any download, so the package cannot install an unverified binary.
- **Added negative security-boundary tests:** `tests/test_security_boundaries.py` (45 tests) drives the failure paths — invalid/empty/absent MCP tokens across 14 privileged operations with zero-subroutine-execution assertions, credential-bearing log lines and support bundles, default-bind and wildcard-bind attempts for Neighbor/SNI/XRay/sing-box/DoH/dashboard/event-bridge, installer checksum aborts (including a PowerShell harness that runs `install.ps1`'s own `Stop-Install`/`Get-ExpectedSha256` and asserts unlinking plus exit code 1), and the CI provenance/permissions/pin consistency. Each carries a control case, verified by mutation.
- **MCP authorization enforced:** the gate that returned `True` unconditionally now requires an `auth_token` argument that matches `BLACKOUT_MCP_TOKEN` (or `BLACKOUT_MCP_SECRET`), compared with `hmac.compare_digest`. It fails closed when no secret is configured. DNS changes, hotspot control, network recovery, engine and TUN starts, and other state-changing calls are denied without a valid token. Read-only calls are unchanged.
- **`install.ps1` verifies SHA-256 before installing:** the download is staged, checked against the release checksum with `Get-FileHash`, and moved into place only on a match. Releases now publish `checksums.txt` and `blackout.exe.sha256`.
- **Defender exclusions are narrow and confirmed:** `blackout doctor --fix` no longer adds an exclusion. The exclusion covers only `bins/windivert`, the WinDivert driver folder, and only after a warning and a typed `yes`. UAC is requested only after that. Use `blackout config --setup-defender-exclusion` or `--remove-defender-exclusion`. Declining keeps the SOCKS5/HTTP modes available.
- **Changed:** the WinDivert driver now lives in `bins/windivert/`. Run `blackout bins download goodbyedpi` once after upgrading; it removes the old driver copies from `bins/`.

### Added

- **Interactive carrier picker:** bare `blackout connect` in an interactive terminal now offers a keyboard-navigable ISP selection screen (Irancell / MCI / RighTel / TCI / Shatel / Auto-Detect via ASN — numbers jump, arrows move, Enter selects, Esc skips). A selection applies that carrier's transient profile and launches the recommended engine without any flags; auto-detect matches the current network's ASN against the profile registry and says so when nothing matches. Never triggered for background/GUI flows, presets, explicit engines, `--sni-spoof`, or `--profile`.
- **Clean-IP → fragment tuning pairing (`blackout tune fragment`):** resolves a target clean IP (explicit `--ip` → cached best → quick scan), then measures TLS record fragmentation candidates against it by completing a real TLS handshake through a short-lived Xray per candidate (ClientHello actually fragmented, from this network, right now). Ranked report with `--json` support; `--apply` binds the winning `sni_connect_ip` + `xray_fragment` pair so the normal connect pipeline picks both up. Honest scope: a snapshot measurement, not a bypass guarantee. Certificate verification stays on — current Xray removed `allowInsecure` entirely.
- **Connection bootstrap hardening:** any exception during engine/daemon bootstrap now surfaces as a transaction failure (`daemon_start_failed` / `engine_start_failed`) with `BLACKOUT_*` temporary overrides strictly restored by the surrounding context manager — never a raw crash mid-connection with a polluted environment (regression-tested).
- **`--sni-spoof` validation hardening:** rejects hostnames with ports (`example.com:443`), raw IPv4/IPv6, and invalid label characters with specific, actionable messages.
- **`--profile` suggestions:** unknown carrier codes produce "Did you mean: …" matches by code similarity and carrier-name tokens (`--profile mci` → ir-mci), on both connect/start errors and `blackout isp show`.
- **Iranian ISP sub-profiles (`blackoutkit/isp_profiles.py`):** carrier-specialized presets for MCI, Irancell, Rightel, TCI (fixed), and Shatel (fixed), each carrying ASN hints for detection, a preferred engine order, and baseline SNI/fragment/fingerprint values. Inspect with `blackout isp list` / `blackout isp show <code>` (`--json` supported). Apply transiently with `blackout connect --profile <code>` or `blackout start --profile <code>` — overrides ride the same temporary env mechanism as `--iran`/`--russia`, so saved settings are never rewritten, including in background-daemon mode. Per-carrier values are documented starting points, not field-tested claims; detection matches the ISP lookup's ASN against profile hints. `--profile` cannot be combined with `--iran`/`--russia` (it implies the Iran profile).
- **`--sni-spoof <domain>` transient flag on `connect` and `start`:** use a specific fake SNI for one connection without touching `sni_fake_sni` — e.g. `blackout connect sni --sni-spoof www.example.com`. Bare hostnames only (scheme/path/credential inputs are rejected with actionable errors); when no engine is named, an explicit spoof resolves straight to the SNI path; on engines that do not read the fake-SNI setting, Blackout says so instead of silently ignoring it. Composes with `--iran`, `--russia`, and `--profile` (the explicit spoof wins for that connection).
- **Blackout Operator foundation (local observability for AI agents and humans):**
  - `blackout snapshot [--json]` — one canonical structured snapshot of local state (daemon, system proxy, vault health, per-engine readiness summary, stability, recent events, recovery hints) with explicit local-vs-remote scope flags.
  - `blackout operator status [--watch]`, `blackout operator recommend`, `blackout operator actions` — deterministic (non-AI) recommendations derived from local evidence, each with a safety class (READ_ONLY, SAFE_REVERSIBLE, PRIVILEGED_REVERSIBLE, DISRUPTIVE, DESTRUCTIVE) and confirmation requirements; nothing is ever auto-executed.
  - `blackoutkit/events.py` — typed local event bus: sanitized at publish (secrets and proxy/VPN/SSH URIs removed), thread-safe, observer-failure-isolated, with a bounded local JSONL journal (`~/.blackout-kit/events.jsonl`).
  - `blackout events recent` and `blackout events serve` — inspect the journal or stream sanitized events over SSE; the bridge is opt-in, binds to 127.0.0.1 only, and has no control surface.
  - `blackout support-bundle [--preview] [--output]` — sanitized bug-report bundles; credentials, tokens, private keys, PSKs, and proxy/VPN/SSH config URIs are removed (not masked), vault contents are never read, and nothing is uploaded.
  - MCP: new read-only tools `blackout_snapshot`, `blackout_recommend`, `blackout_recent_events`, `blackout_support_bundle_preview`; `hotspot-shield` added to the MCP engine surface.
  - Structured events now flow from connection start/stop/failure, daemon reconnect/recovery, and doctor runs.
- Added `blackout help operator` topic documenting the whole surface.

### Fixed
- **Vault unreadable after Windows updates that removed `wmic`** (recent Windows 11 builds): the machine-bound vault key silently fell back to the hostname, making saved configs unreadable and blocking all engine starts. The identity chain now reads the same SMBIOS UUID through PowerShell CIM, and decryption tries documented historical identities (hostname fallback and old constant fallbacks, decrypt-only) so vaults written under any earlier behavior open again. Vault-related test coverage added.
- `blackout start`/`blackout connect` no longer exit silently when local readiness blocks the engine; they now print which checks failed and how to inspect them.
- `blackout doctor` no longer reports "Config Encryption OK" for a vault it cannot decrypt; vault health is now part of the check.

### Added (docs)
- **`NETWORK_PRIVACY.md`:** full egress matrix — 0 telemetry/analytics/phone-home, GitHub API release checks only under `blackout update`, DoH targets and when they are queried, GeoIP/ISP/diagnostic lookups per command, every local listener with its bind address, third-party binary downloads with their verification, and the MCP server's stdio-only scope. `SECURITY.md` gained a **Security Assurance & Verification Matrix** with copy-paste verification commands, a dependency-floor table, and an updated remediation ledger; the stale "no attestations published" and "do not publish the choco package" notes are replaced by what now exists.
- SECURITY.md: Linux-only kill-switch qualifier, network-contact disclosure (no silent telemetry), local data inventory, Operator/support-bundle redaction policy. README/ROADMAP/user-guide/CONTRIBUTING aligned with the Operator layer and current engine catalog.
- **Keyboard settings and config editors:** Bare `blackout settings` and `blackout config` now open Typer-backed keyboard workflows in interactive terminals. Settings are grouped and typed values are validated and saved through the existing APIs; config URIs can be added, safely replaced, removed, imported, exported, and protected without showing credentials in menu labels. Long lists use a keyboard-only bounded viewport; mouse scrolling and clicks do not select items.
- **Keyboard-navigable terminal launcher:** Running `blackout` with no arguments now always opens a terminal chooser — **Terminal CLI**, **Windows App**, or **Exit** — fully navigable with all four arrow keys (Space/Enter/→ to select, ←/Esc to go back, Ctrl+C to quit) and a persistent on-screen control guide. New reusable `blackoutkit/terminal_menu.py` module backs this and the existing action/engine menus, replacing the old Windows-only, Up/Down-only `msvcrt` handling with cross-platform (Windows + POSIX) raw-key reading. Backing out of the Terminal CLI or closing the Windows App window now returns to the chooser instead of exiting the process.
- **Wi-Fi MAC privacy controls:** New Windows-only `blackout tools mac status`, `randomize`, and `restore` commands for deliberate public-Wi-Fi privacy changes. The tool targets only an active physical Wi-Fi adapter, requires confirmation (or explicit non-interactive `--force`), accepts only locally administered unicast addresses, restarts only the selected adapter, preserves its first pre-Blackout `NetworkAddress` override, and restores that exact prior setting or hardware-default behavior. It never rotates automatically or changes firewall, DNS, proxy, routes, VPNs, or unrelated adapters.
- **Download manager:** New `blackout download` commands for multi-threaded HTTP(S) downloads with resume, queue, and speed limiting. Queue is persistent across restarts. Supports HTTP 206 Range requests for smart resume (detects Accept-Ranges header, falls back to restart if unsupported). Commands: `add` (queue download), `list` (view queue), `start` (begin downloads), `cancel` (pause), `clear` (remove from queue), `watch` (live progress). Speed limit and parallel download count configurable in settings.
- **Setup export/import:** New `blackout config export` and `blackout config import-setup <string>` commands to serialize and share your entire Blackout Kit configuration (all saved proxy configs + selected engine, security mode, DNS settings, etc.) as a single portable base64-encoded string. Export to stdout or a file (`--output`), import on any machine with an optional confirmation prompt (skip with `--force`). No passphrase encryption in v1 (unencrypted, like v2ray subscription links); can be added in a follow-up if needed for sharing over untrusted channels.
- **Network analysis toolkit (Phase 1):** Eight new `blackout tools` commands for local network diagnostics — `subnet <cidr>` (subnet/broadcast/usable-range calculator), `connections [--established]` (live TCP/UDP connection table with process attribution via psutil), `scan-ports <host> [--ports ...]` (threaded TCP port scanner over a built-in common-services list or an explicit port list), `discover` (local /24 LAN sweep with ARP-table MAC lookup and reverse DNS), `dns-inspect` (compares system DNS resolution against a trusted DoH resolver to surface possible DNS interference, without false-positiving when the trusted resolver itself is unreachable), `speedtest-history` (terminal sparkline graph of past speedtest runs, now auto-recorded to a local JSON history on every `blackout tools speedtest`), `latency-monitor [host] [--interval]` (live-updating ping graph with rolling avg/jitter/loss, Ctrl+C to stop), and `bandwidth [--interval]` (live per-interface upload/download throughput via `psutil.net_io_counters`, Ctrl+C to stop).
- **Packet capture — `tools capture` (Phase 1 complete):** Live packet capture via `scapy`, with a scrolling protocol/source/destination view and a final protocol-breakdown + top-talkers summary on Ctrl+C. `blackout tools capture [iface] [--count N] [--filter "<bpf>"] [--host <ip>]`. Requires Npcap on Windows or libpcap on Linux — `blackout doctor` now checks for both, plus the `scapy` Python package, and reports actionable fixes instead of a raw traceback when either is missing. No deep protocol decoding (HTTP/TLS SNI) yet — deliberately out of scope for this pass.
- **Smart config rotation:** When a working endpoint fails (e.g. IP blocked), the daemon automatically rotates to the next saved proxy config instead of retrying the same dead endpoint. Controlled by `config_rotation` setting (default: enabled). Particularly useful in Russia where blocked IPs die instantly.
- **XHTTP transport support:** XRay now supports `type=xhttp` (and legacy `type=splithttp`) in V2Ray URIs, including `mode` parameter (auto/packet-up/stream-up). Works with REALITY.
- **Russia country profile:** Added `RU` as a first-class country profile with engine order `xray → hysteria2 → tuic → warp/gdpi/tun → psiphon`, recommended bypass DNS, and Russia-specific test URLs.
- **Russia transport preset:** Added `--russia` flag on `blackout connect` and `blackout start` that applies temporary local overrides (PRIVATE mode, DoH enabled, Iran-specific split-tunnel and fragmentation disabled) without rewriting saved settings. Overrides are forwarded into background daemon runs.
- **Country-aware routing:** XRay split-tunnel and TUN bypass domains are now country-aware — RU profile routes Yandex, VK, Ozon, and other Russian domestic domains direct instead of Iranian `.ir` domains. TUN direct DNS uses Yandex DNS (77.88.8.8) for RU.
- **`blackout help russia` topic:** Dedicated in-app help topic covering the RU profile, preset, field-verified transport notes, and known Russian filtering behavior.
- **ISP country-code detection:** `IspInfo` now carries `country_code` from ip-api.com, and `detect_country()` checks it before falling back to the country name.
- **LAN neighbor cache:** `blackout neighbor` now caches discovered peers in `~/.blackout-kit/neighbor_cache.json` with a 10-minute TTL. On startup, the `connect` command checks cache first (skips 2-min scan if fresh). Daemon periodically broadcasts cached neighbors via multicast so other LAN devices benefit. New CLI commands: `blackout neighbor cache-list` (view cached peers), `cache-refresh` (force discovery), `cache-clear` (delete cache).
- **Bandwidth caps (Phase 2):** New `blackout tools bandwidth-cap` command suite to track daily/monthly per-interface throughput against user-set quotas. Commands: `set <interface> --daily MB --monthly MB` (configure limits), `list` (view all caps with current usage), `stats <interface>` (detailed breakdown), `remove <interface>` (delete cap). Tracks 90-day rolling history atomically in JSON. Alerts at 80% usage threshold (configurable). Useful for users on metered data plans.
- **Traffic logging (Phase 2):** New `blackout tools traffic-log` command suite for persistent per-connection audit trail stored in JSONL format. Commands: `list [--app NAME] [--protocol TCP|UDP] [--hours N]` (query recent traffic), `stats [--by app|protocol]` (aggregate usage), `hourly [--hours N]` (bucket traffic by hour), `clear` (purge log), `prune [--older-than DAYS]` (cleanup aged entries), `info` (log statistics). Captures process name, protocol, source/destination, bytes transferred, and connection status. Useful for understanding "where did my bandwidth go?" and throttling decisions.
- **Network-level ad blocking (Phase 2):** New `blackout tools adblock` command suite implementing Pi-hole-lite functionality for DNS-level ad/tracker blocking. Commands: `sources` (list blocklists), `sources-add <name> <url>` (add blocklist), `sources-remove <name>` (remove blocklist), `custom-add <domain>` (manual block), `custom-remove <domain>`, `whitelist-add <domain>` (bypass all blocks), `whitelist-remove <domain>`, `status` (quick summary), `stats` (detailed stats + top blocked), `log [--blocked-only] [--hours N]` (audit DNS queries), `update` (force re-download all lists). Stores rules in cache files, matches domains via suffix-based comparison. Integrates with existing daemon for background processing. Supports standard hosts-file blocklist format from adaway.org, malware-blocklist.org, and others.
- **Monitor-only QoS (Phase 2):** New `blackout tools qos` command suite for persisting and inspecting local per-app, per-protocol, per-port, and per-interface rule metadata. Commands: `rules list/add/remove/enable/disable` (stored rule management), `stats` (stored configuration with intentional zero-value throughput placeholders), `mode [off|monitor]`, and `violations` (stored violation records). Priority and rate-limit values are metadata only and do not control live traffic. QoS does not activate WinDivert, load packet drivers, intercept packets, throttle traffic, or apply rate limits.
- **Media downloader (Phase 2):** New `blackout media` command suite for downloading videos from YouTube, TikTok, and similar platforms using yt-dlp wrapper. Commands: `add <url> [--format FORMAT | --best-audio-video]` (queue with format selection), `list` (view queue), `watch [id]` (live progress), `cancel <id>` (stop), `clear` (remove completed). Downloads saved to `~/Downloads/blackout-media/`. Persistent JSON queue survives daemon restart. It does not depend on QoS for live traffic control.
- **Torrent manager (Phase 2):** New `blackout torrent` command suite for downloading torrents and magnets using the libtorrent wrapper. Commands: `add <magnet|.torrent>` (queue torrent), `list` (view queue with peer/seed counts), `watch [id]` (live progress with upload/download speeds), `cancel <id>` (stop), `seed <id> [--ratio N]` (set seed ratio, default 1.0 for 1:1), `clear` (remove completed). Downloads saved to `~/Downloads/blackout-torrents/`. Persistent JSON queue survives restart. Real-time peer/seed tracking and bandwidth display. It does not depend on QoS for live traffic control.

### Changed
- **Zero-argument entry point:** `blackout` with no arguments no longer silently tries to launch the desktop GUI first. It now always shows the terminal chooser described above; the GUI opens only when **Windows App** is explicitly selected from it.
- **Preset mechanism refactor:** Converted `--iran` from persistent settings writes to temporary env-based overrides, matching the new `--russia` flow. Both presets now leave saved settings unchanged, even in background mode.
- **Documentation refresh:** Rewrote the public docs to align with the shipped 1.1.1 codebase, clarified platform scope, separated user and maintainer guides, expanded contributor templates, refreshed local project notes, and synchronized in-app help wording with the current command and runtime surface.

### Fixed
- **Engine-selection menu crash:** The interactive "Engine" menu item called `msvcrt.getch()` without importing `msvcrt` in its own scope, raising `NameError` on Windows every time it was opened from the main menu. It now shares the same cross-platform menu primitive as the rest of the launcher.
- **XRay TLS compatibility:** Removed the deprecated `allowInsecure` field from XRay `tlsSettings` that the current XRay runtime rejects with a config parse error.
- **Python TLS enum compatibility:** Added a fallback for `ssl.TLSVersion.TLS1_2` vs `TLSv1_2` in cert probing and SNI HTTP testing, which crashed on some Python builds.
- **Empty `xray_fragment` validation:** The Russia preset clears `xray_fragment` to disable Iran-specific fragmentation, but the validator rejected empty strings. Now accepts empty or `range,range`.


## [1.4.0] - 2026-10-10

### Added
- **The v2 dialer primitives now have a live outbound path.** New Go package `engine/v2/pkg/tunnel` is a loopback-only SOCKS5 CONNECT forwarder: it sniffs the client's first record, and when it is a TLS ClientHello it writes that record upstream through `dialer.WriteHello` — fake-SNI rewriting plus randomized SNI-boundary segmentation with configured chunk/delay bounds — then relays everything else bidirectionally with byte counters. Plain non-TLS first bytes pass through unshaped. This is pure userspace TCP relaying: no raw packets, no forged TCP flags, no zero-window packets, and no FEC frames on the wire.
- **blackout-core can start and stop the tunnel over IPC.** `start {"engine":"socks-tunnel","listen":"127.0.0.1:18080"}` opens the forwarder (non-loopback binds are refused at both the IPC and tunnel layers), `StartResult.Listen` carries the bound address, relayed bytes flow into `Telemetry.bytes_in`/`bytes_out`, `tune` takes effect without a restart, and `stop` force-closes live sessions (a TCP relay only ends when a peer hangs up, so graceful draining would stall). Honest scope: the tunnel is reachable through the v2 control channel only; the Python CLI does not yet launch or manage it.

### Fixed
- **IPC server race caught by `-race`:** `ipc.Server.Serve` assigned the listener handle while `Shutdown` read it without a shared lock; both sides are now guarded.
- **Tunnel hardening from the pre-release review:** a session whose opening bytes are not a clean ClientHello kept a stale 10-second read deadline that later killed mid-stream relays (fixed — the deadline is cleared on every fallback path, and a record that promises bytes it never delivers now tears the session down instead of silently truncating it); a `Close` racing the accept loop could strand a live untracked session (fixed — sessions register synchronously in the accept loop and `Close` waits for `Serve` to exit before its force-close sweep); an unexpected accept-loop death no longer leaves `status=running` pointing at a dead tunnel; and `tune` now mirrors `ipc.MemController` semantics, treating zeroed fields as "keep current" so tuning only the fake SNI cannot reset chunking to the minimum.

### Not in scope (unchanged from 1.3.0)
- TCP-flag spoofing and zero-window manipulation remain unimplemented: they require raw packet injection (WinDivert/NFQUEUE), which the userspace v2 architecture deliberately does not perform.
- HyperPulse FEC is still a standalone codec/policy; no peer wire protocol exists, so nothing transmits parity shards.

## [1.3.0] - 2026-10-10

### Security
- ISP inspection now uses HTTPS-only `ipapi.co` with `ipinfo.io` fallback; redirects are rejected, TLS verification stays enabled, and failed lookups remain best-effort.
- DoH bootstrap accepts only an allow-listed HTTPS resolver override, rejects query/fragment injection and redirects, and falls back through Cloudflare, Quad9, and Google.

### Added
- Go v2 dialer can segment ClientHello data so a parser-identified SNI hostname is split at a seeded, randomized offset within configured chunk bounds. The v2 daemon remains a policy/IPC scaffold; this primitive is not wired into a live outbound connection loop.
- Standalone HyperPulse GF(256) parity encoding, recovery, and bounded adaptive parity policy. These primitives are not transmitted to proxy peers and do not claim compatible wire framing.
- Early local HTTP/SOCKS proxy health probes run during the first five seconds after engine start at 100 ms cadence, with a 200 ms total request deadline; two consecutive local failures can trigger config rotation.

## [1.1.1] - 2026-09-04

### 🔒 Security Hardening
- **Atomic JSON persistence:** Transactional writes using `tempfile.mkstemp()` + `os.fsync()` + `os.replace()` prevent corruption on interrupted writes
- **Thread-safe file locking:** Concurrent config access protected via `threading.Lock()` context managers
- **DoH proxy validation:**
  - HTTPS-only enforcement for upstream URLs
  - Redirect scheme checking (no open redirects)
  - Transaction ID verification (data[:2] == response[:2])
  - Response size bounds (12–65,535 bytes)
  - Content-Type validation (application/dns-message)
- **SFTP command injection safety:** Batch commands use `shlex.quote()` for shell-safe argument escaping
- **WinDivert driver verification:** DLL file checks + sys file checks + `sc query` service verification
- **Streaming file I/O for YARA:** 64KB chunks with 2× max signature overlap for safe large-file scanning
- **Loopback-only CORS:** Dashboard restricted to `http://127.0.0.1:8080` (no wildcard)
- **Daemon metrics cleanup:** Removed duplicate return statement; now returns single clean dict

### ✨ Features & Improvements
- **Phase 1–4 network toolkit complete:** SNI spoofing, XRay, Psiphon, WireGuard, Tor, IKEv2, Soft-ether, OpenVPN, TUIC, Hysteria2
- **AmneziaWG engine:** Obfuscated VPN via sing-box (cataloged experimental; awaiting outbound type support)
- **Russia-first support:** Country profiles, whitelist awareness, data-phase drop detection, smart IP rotation
- **Network analysis:** Latency monitor, bandwidth monitor, packet capture, IP scanning, DNS analysis
- **Media & torrent tools:** YouTube downloader (yt-dlp), torrent manager (libtorrent)
- **Terminal CLI:** Full tool menu, connection lifecycle, daemon process monitor
- **Web dashboard:** Live metrics, traffic visualization, Chart.js SSE streaming

### 🐛 Bug Fixes (Audit Waves)
- **CRITICAL:** PowerShell RCE, deadlock in daemon startup, state corruption, unsafe singleton patterns
- **HIGH:** File lock race conditions, IndexError on empty ZIP, ValueError in daemon config, Unicode decode
- **MEDIUM:** Resource leaks (socket/file/cache), subprocess timeout protection, registry cleanup
- **LOW:** Encoding edge cases, resource lifecycle, daemon recovery

### 📦 Distribution & CI
- **Windows executable:** PyInstaller-built standalone `blackout.exe` (no Python required)
- **Linux runtime:** Go-compiled native engine x86_64; Python optional
- **Multi-distro smoke tests:** Debian, Fedora, Arch validation
- **715 passing tests** with CodeQL static analysis

### ⚠️ Known Limitations
- **Pion advisory:** Upstream CVE in forked WireGuard; patchable via config rotation
- **AmneziaWG experimental:** sing-box runtime lacks AmneziaWG outbound type (blocker active)
- **macOS unsupported:** Linux and Windows only
- **Python 3.10+ required** for full toolkit (daemon/core is Go-native)

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
