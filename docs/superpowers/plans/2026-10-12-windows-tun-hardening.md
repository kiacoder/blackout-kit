# Windows TUN Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden the existing `blackout connect tun` Windows path so its SOCKS upstream is reliably owned, missing privileges/WinTUN prerequisites are detected before route changes, and failure cleanup is limited to Blackout-owned networking state.

**Architecture:** Keep TUN a separate engine from HTTP/mixed system-proxy mode. Consolidate the foreground and elevated/daemon stack composition so Windows TUN starts its required XRay SOCKS upstream before sing-box TUN and rolls back in reverse order. Add local, non-mutating driver/admin readiness evidence and explicit ownership-scoped TUN lifecycle cleanup; do not install WinTUN or alter unrelated host networking.

**Tech Stack:** Python 3, sing-box through `blackout_core.dll` on Windows, existing daemon and network-recovery code, pytest.

**Spec:** `docs/superpowers/specs/2026-10-12-windows-tun-hardening-design.md`

## Global Constraints

- Keep TUN opt-in and separate from HTTP/mixed system-proxy mode.
- Never download/install WinTUN, add Defender exclusions, or modify unrelated adapters/routes/DNS automatically.
- Do not run a live TUN test or change host routes in unit tests.
- Windows startup must use an XRay SOCKS upstream owned by the same stack; do not trust an arbitrary process merely because it listens on `xray_socks_port`.
- Run only ownership-scoped cleanup; never flush the complete route table or reset Winsock/TCP/IP as routine TUN cleanup.
- Preserve current Linux runner and direct saved-config behavior unless a focused test demonstrates a Linux defect.
- Preserve existing user changes in `data/configs.lock`, `bins/.provenance.json`, and other unrelated files.

---

### Task 1: Align TUN engine-stack composition

**Files:**
- Modify: `blackoutkit/cli.py`
- Modify: `blackoutkit/daemon/__init__.py`
- Modify or retire only the proven legacy duplicate map: `blackoutkit/daemon.py`
- Test: `tests/test_engines.py` or a new `tests/test_tun_stack.py`
- Test: `tests/test_daemon_lifecycle.py`

**Interfaces:**
- One canonical platform-specific TUN stack definition is consumed by foreground and elevated/daemon startup.
- Windows stack order: SNI upstream, XRay SOCKS provider, TUN consumer.
- Linux stack order and runner behavior remain unchanged.

- [ ] **Step 1: Trace the actual entrypoints and add failing composition tests**

Test the CLI foreground stack factory for Windows and Linux without starting real engines: inject/patch the platform and engine classes, and assert Windows returns SNI, XRay, then TUN while Linux returns XRay then TUN. Test the daemon stack builder similarly, and assert the Windows elevated path selects the same Windows stack. If `daemon.py` is not used by the shipped CLI/daemon path, record its call-site evidence and leave it out of production edits.

- [ ] **Step 2: Run the focused tests and confirm the daemon mismatch fails**

Run: `python -m pytest tests/test_tun_stack.py tests/test_daemon_lifecycle.py -q`
Expected: the test for the legacy Windows daemon map fails because it currently starts only TUN; Linux ordering remains passing.

- [ ] **Step 3: Implement a canonical stack factory**

Use the smallest shared factory the existing CLI and daemon modules can import without introducing a circular import. Ensure that the factory returns XRay/SNI upstream instances before TUN on Windows, and XRay before TUN on Linux. Reuse it in both foreground and elevated/daemon flows; do not start engines concurrently when ordering is a dependency.

- [ ] **Step 4: Test rollback on downstream startup failure**

Add a unit test with fake engines where upstream engines start, TUN returns false, and stop calls are recorded. Assert all successfully started upstream engines are stopped in reverse startup order and no external state mutation callback is called.

- [ ] **Step 5: Run focused stack and rollback tests**

Run: `python -m pytest tests/test_tun_stack.py tests/test_daemon_lifecycle.py tests/test_connection_service.py -q`
Expected: PASS; Linux order is preserved, Windows order includes its SOCKS provider, and partial startup rolls back owned engines.

---

### Task 2: Add explicit Windows TUN prerequisite checks

**Files:**
- Modify: `blackoutkit/capabilities.py`
- Modify: `blackoutkit/readiness.py`
- Modify: `blackoutkit/doctor.py` only if it can share a small, deterministic local driver probe
- Test: `tests/test_readiness.py`
- Test: `tests/test_capabilities.py`
- Test: `tests/test_doctor.py`

**Interfaces:**
- Add a pure local WinTUN readiness probe that returns an explicit available/unavailable result; it must not download, install, elevate, or change network state.
- Windows TUN readiness reports admin/driver requirements and validates the saved XRay upstream used by the selected Windows stack.
- Existing non-TUN readiness remains unchanged; Linux TUN still uses `/dev/net/tun` and the managed runner checks.

- [ ] **Step 1: Define and test the local WinTUN probe**

Inspect the embedded sing-box/Wintun loading mechanism and bundled API availability. The repository packages `wintun.dll`, but DLL presence alone does not prove the kernel driver is loaded. Prefer a non-mutating call to Wintun's `GetRunningDriverVersion` only if the bundled DLL/API can be safely loaded in the readiness process without creating an adapter or changing state. Otherwise use a narrowly scoped installed-driver/service query only if its identity is deterministic and covered by a Windows fixture. Do not accept generic TAP/TUN/WireGuard adapters as evidence. Add injected tests for available/unavailable results. If no reliable probe exists, readiness must report that driver availability is unverified; it must not report WinTUN ready based only on the bundled DLL. Treat sing-box start as the final prerequisite check and test that a failed start performs no unowned route/DNS cleanup.

- [ ] **Step 2: Add failing readiness tests**

Parameterize Windows readiness for TUN with admin true/false, WinTUN evidence present/absent, compatible upstream present/absent, and assert each missing prerequisite blocks startup before `TUNEngine.start()` or any route mutation. Keep the checks local-only; patch remote DNS/connection functions to raise.

- [ ] **Step 3: Implement truthful capability and readiness metadata**

Update TUN's Windows runtime/required-setting metadata to match the actual DLL, WinTUN prerequisite and XRay/SOCKS upstream. Remove HTTP/SOCKS proxy listener claims from the TUN capability; TUN is a network tunnel. Keep administrator readiness blocking for direct execution while preserving the existing UAC handoff before daemon-owned routing begins.

- [ ] **Step 4: Run readiness and capability tests**

Run: `python -m pytest tests/test_readiness.py tests/test_capabilities.py tests/test_doctor.py -q`
Expected: PASS; no test starts a driver, writes routes, or accesses remote hosts.

---

### Task 3: Make TUN startup rollback and shutdown ownership-scoped

**Files:**
- Modify: `blackoutkit/engines/tun.py`
- Modify: `blackoutkit/tools.py` only where a shared ownership-scoped recovery primitive is needed
- Modify: `blackoutkit/daemon/__init__.py`
- Modify: `blackoutkit/watchdog.py` only if it can safely reuse the ownership-scoped TUN cleanup
- Test: `tests/test_tools.py`
- Test: `tests/test_daemon_lifecycle.py`
- Test: `tests/test_tun_stack.py`

**Interfaces:**
- A TUN launch attempt records the identity of its interface, routes and DNS changes before applying them.
- Cleanup accepts that ownership record and removes only resources created/changed by the current Blackout TUN generation.
- Existing explicit recovery options remain explicit; routine stop/rollback never invokes full-route or full-stack reset.

- [ ] **Step 1: Add pure ownership and rollback tests**

Add tests with synthetic adapter/route/DNS snapshots plus a launch-generation ownership record. Prove cleanup selects the exact `BlackoutKit-TUN` adapter only when its recorded interface identity matches the launch generation, selects routes by the recorded interface index and created-route identities, restores DNS only on physical adapters recorded as changed by that generation, and preserves pre-existing Blackout adapters, unrelated VPN interfaces, and proxy settings. Add failure-path tests for TUN startup after upstream start, before adapter creation, after route creation, and after DNS assignment.

- [ ] **Step 2: Verify tests fail against current behavior**

Run: `python -m pytest tests/test_tools.py tests/test_daemon_lifecycle.py tests/test_tun_stack.py -q`
Expected: failures identify missing per-generation ownership/rollback behavior; existing targeted stale-route tests remain passing.

- [ ] **Step 3: Implement narrow TUN ownership tracking**

Record only the resources the TUN start path actually creates or changes, tied to the existing daemon generation/lease identity. Capture the affected physical adapters' pre-change DNS values if the TUN path changes DNS. Avoid broad snapshots as authorization to delete resources: require Blackout interface identity plus matching route ownership.

- [ ] **Step 4: Implement rollback and normal stop using the ownership record**

On partial startup failure, stop sing-box, remove only routes recorded as created by this launch generation, close only the adapter handle created/opened by this generation according to sing-box/Wintun ownership semantics, restore only DNS values recorded as changed by this generation, then stop upstream engines in reverse order. Do not delete a pre-existing Blackout adapter merely because its name matches. On normal stop or watchdog cleanup, use the same ownership-aware cleanup and be idempotent. Never clear an unrelated proxy or reset all routes.

- [ ] **Step 5: Run focused ownership/rollback tests**

Run: `python -m pytest tests/test_tools.py tests/test_daemon_lifecycle.py tests/test_tun_stack.py -q`
Expected: PASS; unrelated adapters, routes, DNS and proxies remain unchanged in every synthetic failure case.

---

### Task 4: Verify Stage 2 integration and document safe operation

**Files:**
- Modify: `blackoutkit/help_text.py` and/or `docs/user-guide.md` only where existing `tun` guidance is inaccurate
- Test: `tests/test_typer_cli.py`

**Interfaces:**
- `blackout ready tun` accurately reports local prerequisites without performing network or route changes.
- `blackout help tun` (or the existing relevant help topic) tells users that Windows TUN is system-wide, requires elevated privileges and WinTUN, and does not install the driver automatically.
- HTTP/mixed proxy mode and existing XRay startup behavior are unchanged.

- [ ] **Step 1: Add help/readiness regression tests**

Assert the TUN help or setup output describes system-wide impact, elevation, WinTUN and manual driver installation, while keeping the HTTP/mixed setting described separately. Assert `ready tun` does not launch a process or change system proxy/DNS/routes.

- [ ] **Step 2: Run the complete Stage 2 suite**

Run: `python -m pytest tests/test_tun_stack.py tests/test_tools.py tests/test_daemon_lifecycle.py tests/test_readiness.py tests/test_capabilities.py tests/test_doctor.py tests/test_connection_service.py tests/test_typer_cli.py -q`
Expected: PASS; document unrelated baseline failures separately.

- [ ] **Step 3: Review the final Stage 2 diff and verify full repository tests**

Run: `python -m pytest -q`
Expected: all tests pass, with only the repository's platform-specific skips/deselections and any pre-existing warnings explicitly reported.

## Out of Scope

- Automatic WinTUN download/install, Defender exclusions, or any external driver acquisition.
- Any change to the mixed HTTP/SOCKS proxy mode or its default.
- Full route-table flush, Winsock reset, TCP/IP reset, or DHCP release as a routine TUN action.
- Automatic switching into TUN when a URL fails.
- Running TUN against the user's live network during automated implementation tests.
