# V2RayN-Style Mixed Proxy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in V2RayN-style HTTP+SOCKS mixed inbound for Xray without changing Blackout's current HTTP-default behavior or removing existing listeners.

**Architecture:** Add a validated `xray_system_proxy_mode` setting (`http` by default, `mixed` opt-in). XRayEngine selects the protocol for its existing SOCKS-port inbound from that setting; the existing dedicated HTTP listener stays present in both modes. `get_engine_proxy_details()` selects the matching endpoint so Xray, SNI+Xray, and Legend+Xray use the correct port consistently. TUN remains a separate later stage.

**Tech Stack:** Python 3, Xray JSON config, pytest, existing Blackout settings/connection service.

**Spec:** `docs/superpowers/specs/2026-10-12-v2rayn-mixed-proxy-design.md`

## Global Constraints

- Keep `xray_system_proxy_mode` defaulting to `http`.
- Preserve the SOCKS listener at `xray_socks_port` and HTTP listener at `xray_http_port` in both modes.
- In mixed mode only, make the existing SOCKS-port listener `mixed` and set the Windows system proxy to its plain host:port endpoint, without a `socks=` prefix.
- Preserve loopback binding, sniffing, routes, outbounds, TLS, and proxy-ownership cleanup behavior.
- Do not claim mixed mode fixes Chrome; previous mixed-inbound testing did not prove that.
- Do not edit pre-existing uncommitted files `data/configs.lock` and `bins/.provenance.json`.
- Do not implement TUN changes in this plan.

---

### Task 1: Add the selectable proxy-mode setting

**Files:**
- Modify: `blackoutkit/settings.py`
- Test: `tests/test_engine_fallback.py`
- Test: `tests/test_typer_cli.py`

**Interfaces:**
- Setting key `xray_system_proxy_mode`, string enum values `http` and `mixed`, default `http`.
- Existing `validate`, `validate_all`, `set_value`, `iter_setting_groups`, and settings-list output handle the new setting through current metadata mechanisms.

- [ ] **Step 1: Add failing settings metadata/validation tests**

In `tests/test_engine_fallback.py`, add four focused tests using the module's existing local-import pattern:

```python
def test_xray_system_proxy_mode_defaults_to_http():
    from blackoutkit import settings
    assert settings.DEFAULTS["xray_system_proxy_mode"] == "http"


def test_xray_system_proxy_mode_accepts_http_and_mixed_only():
    from blackoutkit import settings
    assert settings.validate("xray_system_proxy_mode", "http")[0] is True
    assert settings.validate("xray_system_proxy_mode", "mixed")[0] is True
    assert settings.validate("xray_system_proxy_mode", "socks")[0] is False


def test_xray_system_proxy_mode_is_in_xray_group():
    from blackoutkit import settings
    assert "xray_system_proxy_mode" in dict(settings.SETTING_GROUPS)["XRay"]


def test_xray_system_proxy_mode_has_description():
    from blackoutkit import settings
    assert "mixed" in settings.describe("xray_system_proxy_mode").lower()
```

- [ ] **Step 2: Run the focused tests and verify the new assertions fail**

Run: `python -m pytest tests/test_engine_fallback.py tests/test_interactive.py -q`
Expected: failures because the mode key/choice/validator are not yet present.

- [ ] **Step 3: Implement the setting metadata**

In `blackoutkit/settings.py`, add `xray_system_proxy_mode: "http"` to `DEFAULTS`, add it to the `XRay` setting group, add a `SETTING_CHOICES` entry with `("http", "mixed")`, and add a validator requiring one of those values. Add a concise description beside the other XRay settings.

- [ ] **Step 4: Run settings tests**

Run: `python -m pytest tests/test_engine_fallback.py tests/test_interactive.py -q`
Expected: PASS for the new default, choice validation, group visibility, and existing settings tests.

---

### Task 2: Generate mixed Xray inbound while preserving both existing listeners

**Files:**
- Modify: `blackoutkit/engines/xray.py`
- Test: `tests/test_engines.py`

**Interfaces:**
- `XRayEngine.generate_config()` reads `xray_system_proxy_mode`.
- `http` mode returns the existing SOCKS and HTTP inbounds unchanged.
- `mixed` mode changes only the SOCKS-port inbound protocol to `mixed`; HTTP remains at `xray_http_port`.

- [ ] **Step 1: Add failing configuration tests**

In `tests/test_engines.py`, add a helper that copies `settings.DEFAULTS`, sets `country=""`, and patches `blackoutkit.engines.xray.cfg.load` for each case. Build `XRayEngine(proxy_config=ProxyConfig(protocol="vless", address="example.com", port=443))`, then call `generate_config()` without starting a process. Assert the generated two inbounds exactly match these stable fields:

```python
assert [(item["tag"], item["protocol"], item["port"], item["listen"]) for item in config["inbounds"]] == [
    ("socks-in", "socks", 10808, "127.0.0.1"),
    ("http-in", "http", 10809, "127.0.0.1"),
]
```

For `http` and missing mode, assert that list remains unchanged. For `mixed`, expect only the first protocol to become `mixed`. In both cases assert inbound settings and sniffing are unchanged and `config["outbounds"]` plus `config["routing"]` match the same baseline across modes.

- [ ] **Step 2: Run the focused tests and verify the mixed assertion fails**

Run: `python -m pytest tests/test_engines.py -q`
Expected: the mixed inbound protocol assertion fails; HTTP-mode compatibility assertions pass.

- [ ] **Step 3: Implement protocol selection at inbound construction**

Read `xray_system_proxy_mode` once in `generate_config()`. Set the SOCKS-port inbound `protocol` to `mixed` only when the setting equals `mixed`; otherwise leave it as `socks`. Do not change its tag, port, `listen`, settings, or sniffing fields. Keep the dedicated HTTP inbound unchanged.

- [ ] **Step 4: Run the Xray configuration tests**

Run: `python -m pytest tests/test_engines.py tests/test_country_routing.py tests/test_reality.py -q`
Expected: PASS; legacy config, routing, and REALITY settings remain unchanged.

---

### Task 3: Select the matching system-proxy endpoint

**Files:**
- Modify: `blackoutkit/settings.py`
- Test: `tests/test_connection_service.py`

**Interfaces:**
- `get_engine_proxy_details(engine_name, settings)` returns `(proxy_host, xray_http_port)` in `http` mode and `(proxy_host, xray_socks_port)` in `mixed` mode for `xray`, `sni`, and `legend`. The mixed system-proxy value is plain host:port, matching V2RayN; it is not marked `socks=`.
- Unrelated engine proxy mappings remain unchanged.

- [ ] **Step 1: Add failing endpoint-selection tests**

Import `get_engine_proxy_details` from `blackoutkit.settings` in `tests/test_connection_service.py`. Add parameterized cases for `xray`, `sni`, and `legend`. With settings copied from `DEFAULTS` and mode omitted/`http`, assert the result is `("127.0.0.1", configured_http_port)`. With mode `mixed`, assert the result is `("127.0.0.1", configured_socks_port)`. Add one regression assertion that `hysteria2` still returns its existing SOCKS endpoint.

- [ ] **Step 2: Run endpoint tests and verify mixed cases fail**

Run: `python -m pytest tests/test_connection_service.py -q`
Expected: mixed endpoint cases fail while all existing endpoint and proxy ownership tests pass.

- [ ] **Step 3: Implement endpoint selection**

Update only the XRay/SNI/Legend branch in `get_engine_proxy_details()`: in mixed mode return the plain configured proxy host and `xray_socks_port`; otherwise retain the current HTTP endpoint. Do not change `proxy_manager.py` registry encoding or ownership cleanup.

- [ ] **Step 4: Run endpoint and proxy ownership tests**

Run: `python -m pytest tests/test_connection_service.py tests/test_proxy_manager.py -q`
Expected: PASS; proxy snapshot/restore and cleanup behavior remains unchanged.

---

### Task 4: Keep readiness and capability metadata consistent

**Files:**
- Modify: `blackoutkit/capabilities.py` only if listener descriptions need a mode-neutral clarification
- Modify: `blackoutkit/readiness.py` only if the existing two XRay ports are not already checked in both modes
- Test: `tests/test_capabilities.py`
- Test: `tests/test_readiness.py`

**Interfaces:**
- Both `xray_socks_port` and `xray_http_port` remain required listeners in both modes.
- Readiness remains local-only and checks both ports; it does not probe remote reachability.

- [ ] **Step 1: Add tests for both listener ports in either mode**

Parameterize the existing checks in `tests/test_readiness.py` over `http` and `mixed`. In each case, patch `readiness.cfg.load` to return `DEFAULTS` with the mode set, use `_port_free` to record checked ports, and assert both configured values `10808` and `10809` were checked. Keep the existing occupied-port assertion blocking. In `tests/test_capabilities.py`, change listener wording only if the current description falsely promises SOCKS-only behavior in mixed mode.

- [ ] **Step 2: Run focused tests and identify whether production changes are needed**

Run: `python -m pytest tests/test_readiness.py tests/test_capabilities.py -q`
Expected: PASS if existing behavior already checks both ports; otherwise only the newly identified gap fails.

- [ ] **Step 3: Make the smallest correction only if a test exposed a gap**

Keep both ports in readiness checks in both modes. Clarify capability text only if it currently implies that port `10808` is always SOCKS-only. Do not add a third port and do not make readiness perform network probes.

- [ ] **Step 4: Re-run focused tests**

Run: `python -m pytest tests/test_readiness.py tests/test_capabilities.py -q`
Expected: PASS.

---

### Task 5: Verify CLI discoverability and backward compatibility

**Files:**
- Test: `tests/test_typer_cli.py`
- Modify: `blackoutkit/settings.py` descriptions/grouping only if settings-list output needs explicit user guidance

**Interfaces:**
- `blackout settings list` exposes `xray_system_proxy_mode` with valid values and the HTTP default.
- `blackout ready xray` remains a read-only local readiness check.

- [ ] **Step 1: Add CLI regression tests**

In `tests/test_typer_cli.py`, call `typer_cli._render_settings(dict(typer_cli.settings.DEFAULTS))` with `typer_cli.console.print` captured, then assert captured rendered output contains `xray_system_proxy_mode`, `http`, `mixed`, and the setting description. Keep readiness read-only coverage in `tests/test_readiness.py`, where the existing test already patches remote resolution and connection attempts to raise.

- [ ] **Step 2: Run the focused CLI tests and verify the renderer assertion passes**

Run: `python -m pytest tests/test_typer_cli.py -q`
Expected: the settings renderer includes the setting metadata added in Task 1; readiness remains read-only.

- [ ] **Step 3: Add only missing CLI help text if an assertion exposed a gap**

Rely on generated settings metadata when it already lists the key and choices. Do not duplicate setting documentation in multiple help modules.

- [ ] **Step 4: Run the complete affected suite**

Run: `python -m pytest tests/test_engine_fallback.py tests/test_interactive.py tests/test_engines.py tests/test_country_routing.py tests/test_reality.py tests/test_connection_service.py tests/test_proxy_manager.py tests/test_readiness.py tests/test_capabilities.py tests/test_typer_cli.py -q`
Expected: PASS; report unrelated baseline failures distinctly.

- [ ] **Step 5: Verify default settings and read-only readiness via CLI**

Run:

```bash
blackout settings list
```

```bash
blackout ready xray
```

Expected: default mode remains `http`; readiness reports the existing `10808` and `10809` ports without starting Xray or modifying proxy/DNS settings.

## Out of Scope

- TUN code, TUN driver/readiness/rollback fixes, routing changes, and elevated daemon stack changes; these require a separate Stage 2 plan.
- Changing Chrome DNS, ECH, TLS fingerprint, sniffing, fragmentation, or bypass rules.
- Making mixed mode the default.
- Automatically switching modes based on Chrome detection or silently falling back when a mixed listener fails.
- Starting, stopping, or reconfiguring the user's live VPN during implementation or tests.
