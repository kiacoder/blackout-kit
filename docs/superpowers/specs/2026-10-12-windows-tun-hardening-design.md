# Windows TUN Hardening Design

**Status:** Draft for user review; no implementation approved by this document alone.

## Goal

Harden the existing `blackout connect tun` path on Windows so it has an explicit working SOCKS upstream, refuses startup when required TUN prerequisites are unavailable, and recovers only Blackout-owned routes, DNS, and adapter state after failure.

## Current behavior

- TUN already exists as `TUNEngine` in `blackoutkit/engines/tun.py`; it generates a sing-box TUN inbound with `auto_route`, `strict_route`, a named Blackout interface, DNS hijacking, direct bypass routes, and a SOCKS outbound.
- The TUN engine's default SOCKS upstream is `127.0.0.1:xray_socks_port`.
- Windows foreground `blackout connect tun` currently builds `(SNIEngine, XRayEngine, TUNEngine)`, so XRay may provide that local SOCKS endpoint.
- Windows elevated/daemon startup also currently builds `(SNIEngine, XRayEngine, TUNEngine)` in `blackoutkit/daemon/__init__.py`, but another legacy engine map in `blackoutkit/daemon.py` maps Windows `tun` to only `(TUNEngine,)`. These paths must be consolidated or proven unused before changing them.
- Windows TUN needs Administrator privileges and WinTUN. The engine requests elevation and starts embedded sing-box through the native DLL. Current readiness lists the core DLL runtime and an admin warning but does not establish that the WinTUN driver is installed and usable.
- Existing Windows recovery discovers the exact `BlackoutKit-TUN` adapter, scopes route removal by its interface index, restores loopback DNS only on connected physical adapters, and preserves a live daemon. The watchdog's TUN-specific owned-interface recovery is Linux-only.
- Existing tests cover pure config fields and portions of stale-route recovery, but not Windows TUN stack alignment, startup rollback, driver detection, or complete owned-resource cleanup.

## Approved direction

Harden the existing TUN target; do not create a second command, replace proxy mode, or change mixed-proxy behavior.

### 1. Explicit Windows upstream and consistent engine stack

- Establish one canonical engine-stack builder used by foreground and daemon/elevated startup.
- On Windows TUN, start the XRay/SNI upstream required by the TUN SOCKS outbound before starting TUN, and stop already-started upstream engines if TUN fails.
- On Linux TUN, preserve the existing managed runner and direct saved-config behavior unless a separate Linux defect is demonstrated by tests.
- Do not make the Windows TUN path silently use an unrelated local proxy just because something happens to listen on `xray_socks_port`; the stack must own the upstream it starts.

### 2. Windows prerequisite readiness

- Keep readiness local-only and non-mutating.
- Add an explicit blocking check for Administrator privileges before system routes are modified; an ordinary foreground command may use the existing UAC/elevation handoff before reaching this check.
- Detect the WinTUN prerequisite using stable local evidence suitable for the embedded sing-box DLL/runtime. Do not treat any generic TAP/TUN/WireGuard adapter as proof that WinTUN is usable.
- A bundled `wintun.dll` is not evidence that the WinTUN kernel driver is loaded. If no reliable read-only driver probe is available, report that limitation explicitly; do not claim the driver is ready. In that case, sing-box startup is the final prerequisite check and any start failure must roll back before owned routes/DNS remain active.
- Preserve the project privacy policy: do not download or install WinTUN automatically. A diagnostic may show the user the existing official download guidance.

### 3. Owned-resource lifecycle and rollback

- Define which interface name, routes, and DNS assignments belong to Blackout TUN before startup.
- On partial startup failure, roll back only resources created by that attempt, using exact interface/route identity and snapshots where needed.
- On normal stop or daemon failure, remove only Blackout-owned TUN routes/interface state and restore DNS only on physical interfaces where Blackout changed DNS.
- Never flush the entire route table, reset Winsock/TCP/IP, or change unrelated adapters as an implicit TUN cleanup action.
- Keep the existing explicit `blackout fix` full reset options opt-in and separate from routine TUN cleanup.

### 4. Capability and readiness truthfulness

- TUN capability metadata must describe its actual local surface and upstream requirement. It is a network tunnel, not an HTTP/SOCKS system proxy.
- On Windows, readiness must reflect the local XRay/SOCKS upstream that the selected Windows stack will start; on Linux it must continue to require the direct saved config used by its runner.
- Advertise privilege and driver requirements consistently in `capabilities`, `ready`, and `doctor` without making `ready` perform network probes.

## Test requirements

- Pure config tests for TUN interfaces, routes, DNS, bypasses, and SOCKS upstream selection.
- Windows foreground and daemon stack tests asserting XRay/SNI upstream ordering and that all started engines roll back when TUN startup fails.
- Readiness tests for missing/admin/driver-present and driver-absent states using injected local probes; no real driver install or route mutation in unit tests.
- Recovery tests proving cleanup targets only exact Blackout-owned interface/route/DNS state, preserves unrelated adapters/proxies, and does not run broad resets by default.
- Integration/manual verification must be separately identified for a Windows host with WinTUN and Administrator permission; unit-test success alone does not prove real route safety.

## Non-goals

- Replacing the selectable HTTP/mixed system proxy from Stage 1.
- Automatically switching from system proxy to TUN when a website fails.
- Changing DNS, Chrome settings, ECH, TLS fingerprint, fragmentation, or XRay routing as part of this TUN hardening.
- Installing WinTUN, adding Defender exclusions, or making unprompted Windows network changes.
