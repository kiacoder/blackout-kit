"""
Blackout Kit - Security module.

Three user-selectable local configuration presets:
  SPEED   (default) — compatibility-focused XRay settings.
  PRIVATE — random XRay fingerprint and XRay MUX.
  LEGEND  — 🔥 The legendary mode. Applies strict handling for known-bad
             normal TLS certificates in addition to its XRay settings.
             It does not guarantee anonymity, traffic obfuscation, or multi-hop routing.

Also handles:
  - Config file obfuscation (protect server credentials at rest)
  - Windows Defender exclusion, limited to the isolated WinDivert driver folder
  - Kill switch with DoH/DoT leak protection (port 853 TCP+UDP)
  - Stability tracking with reset, bulk query, and alert helpers
  - Mode enforcement verification
  - Defender exclusion verification and listing
"""
import hashlib
import json
import logging
import math
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

from . import elevate
from . import settings as cfg

_log = logging.getLogger(__name__)

from . import APP_DATA_DIR, BINS_DIR, DATA_DIR, WINDIVERT_DIR, WINDIVERT_DRIVER_FILES

CONFIGS_FILE  = DATA_DIR / "configs.txt"
ENC_CONFIGS   = APP_DATA_DIR / "configs.enc"

# ─────────────────────────── Security modes ──────────────────────

MODES = {
    "speed": {
        "xray_fingerprint":  "chrome",
        "xray_log_level":    "none",
        "xray_mux_enabled":  False,
        "gdpi_flags":        "-9",
        "description": "Max speed, minimal overhead. Default for blackouts.",
    },
    "private": {
        "xray_fingerprint":  "random",
        "xray_log_level":    "none",
        "xray_mux_enabled":  True,
        "gdpi_flags":        "-9",
        "description": "Random TLS fingerprint + DNS-over-HTTPS. Slower but harder to fingerprint.",
    },
    "legend": {
        "xray_fingerprint":  "random",
        "xray_log_level":    "none",
        "xray_mux_enabled":  True,
        "gdpi_flags":        "-9",
        "description": (
            "🔥 LEGENDARY MODE — random XRay fingerprint and MUX with "
            "strict handling for known-bad normal TLS certificates. "
            "Kill switch and config encryption remain separate opt-in features."
        ),
    },
}


def apply_mode(mode_name: str):
    """Apply a security mode by updating the relevant settings."""
    mode = MODES.get(mode_name)
    if not mode:
        raise ValueError(f"Unknown mode '{mode_name}'. Choices: {', '.join(MODES)}")
    s = cfg.load()
    for key, value in mode.items():
        if key != "description" and key in cfg.DEFAULTS:
            s[key] = value
    s["security_mode"] = mode_name
    cfg.save(s)


def get_current_mode() -> str:
    return cfg.load().get("security_mode", "speed")


def mode_description(mode_name: str) -> str:
    return MODES.get(mode_name, {}).get("description", "Unknown mode")


def is_mode_enforced() -> tuple[bool, list[str]]:
    """
    Check whether the current settings actually match the declared security mode.

    Returns (True, []) if everything is aligned.
    Returns (False, [mismatch_descriptions]) if settings drifted from the mode.
    """
    s         = cfg.load()
    mode_name = s.get("security_mode", "speed")
    mode      = MODES.get(mode_name, {})
    mismatches: list[str] = []

    for key, expected in mode.items():
        if key == "description":
            continue
        actual = s.get(key)
        if actual != expected:
            mismatches.append(
                f"{key}: expected={expected!r}, actual={actual!r}"
            )

    return (len(mismatches) == 0, mismatches)


# ─────────────────────────── Kill switch ─────────────────────────

# Thread lock to prevent races on rapid enable/disable
import threading as _ks_th ; _ks_lock = _ks_th.Lock()

# All rule names managed by the kill switch (kept in sync across enable/disable)
_KS_RULES = [
    "BlackoutKit-KillSwitch-Block",
    "BlackoutKit-KillSwitch-Allow-Proxy",
    "BlackoutKit-KillSwitch-Allow-LAN",
    "BlackoutKit-KillSwitch-Allow-DNS",
    "BlackoutKit-KillSwitch-Allow-DNS-TCP",
    "BlackoutKit-KillSwitch-Allow-DHCP",
    "BlackoutKit-KillSwitch-Block-DoH",
    "BlackoutKit-KillSwitch-Block-DoT",
]


def _remove_legacy_windows_kill_switch_rules() -> bool:
    """Remove unsafe legacy Windows rules whose block action overrides allow rules."""
    ps = r"""
$names = @(
    "BlackoutKit-KillSwitch-Block",
    "BlackoutKit-KillSwitch-Allow-Proxy",
    "BlackoutKit-KillSwitch-Allow-LAN",
    "BlackoutKit-KillSwitch-Allow-DNS",
    "BlackoutKit-KillSwitch-Allow-DNS-TCP",
    "BlackoutKit-KillSwitch-Allow-DHCP",
    "BlackoutKit-KillSwitch-Block-DoH",
    "BlackoutKit-KillSwitch-Block-DoT"
)
foreach ($n in $names) {
    try { Remove-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue } catch {}
}
for ($i = 0; $i -lt 50; $i++) {
    try { Remove-NetFirewallRule -DisplayName "BlackoutKit-KillSwitch-Allow-Proxy-$i" -ErrorAction SilentlyContinue } catch {}
}
Write-Output "OK"
"""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return "OK" in result.stdout
    except (OSError, subprocess.SubprocessError) as exc:
        _log.warning("Could not remove legacy Windows kill-switch rules: %s", exc)
        return False


import threading

_linux_endpoint_cache: dict[tuple[str, int], list[tuple[str, int]]] = {}
_linux_endpoint_cache_lock = threading.Lock()


def _linux_kill_switch_endpoints(engine_name: str | None = None) -> list[tuple[str, int]]:
    """Resolve and cache literal endpoint allow rules before Linux firewall changes."""
    if not sys.platform.startswith("linux"):
        return []
    try:
        from . import linux_network
        from .config.manager import load_configs

        settings = cfg.load()
        selected = (engine_name or settings.get("selected_engine", "auto")).lower()
        supported = {"auto", "xray", "tun", "hysteria2", "tuic"}
        if selected not in supported:
            return []
        protocols = {"hysteria2"} if selected == "hysteria2" else ({"tuic"} if selected == "tuic" else {"vless", "trojan"})
        for proxy in load_configs():
            if proxy.protocol not in protocols or not proxy.address or not proxy.port:
                continue
            key = (proxy.address, proxy.port)
            with _linux_endpoint_cache_lock:
                if key in _linux_endpoint_cache:
                    return _linux_endpoint_cache[key]
            endpoints = linux_network.resolve_proxy_endpoints([key])
            if endpoints:
                with _linux_endpoint_cache_lock:
                    _linux_endpoint_cache[key] = endpoints
            return endpoints
    except Exception as exc:
        _log.warning("Could not resolve Linux kill-switch endpoint: %s", exc)
    return []


def prepare_linux_kill_switch(engine_name: str) -> bool:
    """Resolve the endpoint before firewall rules can prevent DNS access."""
    return bool(_linux_kill_switch_endpoints(engine_name))


def linux_cached_endpoint(host: str, port: int) -> str | None:
    """Return a prevalidated Linux endpoint IP for an exact proxy host and port."""
    with _linux_endpoint_cache_lock:
        endpoints = _linux_endpoint_cache.get((host, port), [])
    return endpoints[0][0] if endpoints else None


def clear_linux_kill_switch_endpoint(_engine_name: str | None = None) -> None:
    with _linux_endpoint_cache_lock:
        _linux_endpoint_cache.clear()


def _get_proxy_processes() -> list[str]:
    """Return full paths to known proxy binaries in the bins/ folder."""
    candidates = [
        "xray.exe", "sni-spoofing.exe", "sni-spoof.exe", "sni.exe",
        "tor.exe", "goodbyedpi.exe", "warp-plus.exe",
        "psiphon-tunnel-core-x86_64.exe", "psiphon-tunnel-core.exe",
        "sing-box.exe", "blackout-engine.exe",
        "wireguard.exe", "openvpn.exe", "softether.exe",
        "mhrv.exe", "mhrv-rs.exe",
    ]
    results = []
    for name in candidates:
        path = (BINS_DIR / name).resolve()
        if path.exists():
            results.append(str(path))
    return results


def enable_kill_switch(engine_name: str | None = None) -> bool:
    with _ks_lock:
        return _enable_kill_switch_impl(engine_name)


def _enable_kill_switch_impl(engine_name: str | None = None) -> bool:
    """Enable the verified Linux kill switch or retire unsafe Windows legacy rules."""
    if sys.platform.startswith("linux"):
        from . import linux_network

        endpoints = _linux_kill_switch_endpoints(engine_name)
        ok, detail = linux_network.enable_kill_switch(endpoints)
        if not ok:
            _log.warning("Linux kill switch was not enabled: %s", detail)
        return ok

    if sys.platform != "win32":
        return False

    _remove_legacy_windows_kill_switch_rules()
    _log.warning(
        "Windows kill switch is unavailable: Windows Firewall block rules override "
        "per-process allow rules. Legacy Blackout Kit rules were removed."
    )
    return False


def test_kill_switch() -> tuple[bool, str]:
    """Verify that Blackout Kit's kill-switch rules are active."""
    if sys.platform.startswith("linux"):
        if not kill_switch_is_active():
            return False, "Linux kill switch is not active. Enable it with: sudo blackout killswitch on"
        return True, "Linux kill switch is active in the Blackout Kit-owned firewall table."
    if sys.platform == "win32":
        return False, (
            "Kill switch is unavailable on Windows because Windows Firewall block rules "
            "override the required per-process allow rules."
        )
    return False, "Kill switch is unavailable on this platform"


def disable_kill_switch() -> bool:
    with _ks_lock:
        return _disable_kill_switch_impl()


def _disable_kill_switch_impl() -> bool:
    """Remove only Blackout Kit-owned kill-switch firewall rules."""
    if sys.platform.startswith("linux"):
        from . import linux_network

        ok, detail = linux_network.remove_owned_firewall()
        if not ok:
            _log.warning("Linux kill switch cleanup failed: %s", detail)
        return ok
    if sys.platform != "win32":
        return False

    # ── Remove via PowerShell (handles both netsh & PowerShell-created rules) ──
    ps = r"""
$prefix = "BlackoutKit-KillSwitch"
Get-NetFirewallRule -DisplayGroup "$prefix-*" -ErrorAction SilentlyContinue | ForEach-Object {
    try { Remove-NetFirewallRule -DisplayName $_.DisplayName -ErrorAction SilentlyContinue } catch {}
}
# Also catch netsh rules (they don't have a display group)
$names = @(
    "BlackoutKit-KillSwitch-Block",
    "BlackoutKit-KillSwitch-Allow-Proxy",
    "BlackoutKit-KillSwitch-Allow-LAN",
    "BlackoutKit-KillSwitch-Allow-DNS",
    "BlackoutKit-KillSwitch-Allow-DNS-TCP",
    "BlackoutKit-KillSwitch-Allow-DHCP",
    "BlackoutKit-KillSwitch-Block-DoH",
    "BlackoutKit-KillSwitch-Block-DoT"
)
foreach ($n in $names) {
    try { Remove-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue } catch {}
}
# Remove per-process Allow-Proxy-N rules
for ($i = 0; $i -lt 50; $i++) {
    try { Remove-NetFirewallRule -DisplayName "BlackoutKit-KillSwitch-Allow-Proxy-$i" -ErrorAction SilentlyContinue } catch {}
}
Write-Output "OK"
"""
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps],
        capture_output=True, text=True, timeout=15,
    )
    return "OK" in result.stdout


def kill_switch_is_active() -> bool:
    """Return whether the verified platform kill-switch implementation is active."""
    if sys.platform.startswith("linux"):
        from . import linux_network

        return linux_network.kill_switch_is_active()
    return False


# ─────────────────────────── Config encryption (AES-256-GCM) ─────
# AES-256-GCM with PBKDF2-derived key tied to machine hardware ID.
# File format: b"BKAE01:" + base64(nonce[12] + ciphertext)
# Falls back to XOR read for files encrypted with the old format.

_AES_HEADER    = b"BKAE01:"
_PBKDF2_SALT   = b"blackout-kit-aes256gcm-2026"
_PBKDF2_ITERS  = 100_000


def _get_machine_id() -> bytes:
    """Return raw machine identifier bytes (SMBIOS UUID on Windows, hostname elsewhere).

    Delegates to the vault's candidate chain so obfuscated files stay readable
    on Windows builds where the wmic binary was removed. The chain cache is
    reset first: this path runs rarely, and callers may patch probing inputs.
    """
    try:
        from . import vault as vault_module

        vault_module.reset_machine_id_cache()
        return vault_module.machine_id_candidates()[0]
    except Exception:
        uid = platform.node()
        return uid.encode() if uid else b"blackout-kit-unknown-machine"


def _derive_aes_key(machine_id: bytes) -> bytes:
    """Derive a 32-byte AES-256 key via PBKDF2-HMAC-SHA256."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_PBKDF2_SALT,
        iterations=_PBKDF2_ITERS,
    )
    return kdf.derive(machine_id)


def _get_machine_key() -> bytes:
    """Legacy helper: SHA256 of machine ID (used for XOR fallback read)."""
    return hashlib.sha256(_get_machine_id()).digest()


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write bytes atomically: temp file → os.replace(). Prevents corrupt files on crash."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp_")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def obfuscate_configs():
    """Encrypt proxy URIs and supported VPN secrets using authenticated storage."""
    from . import vault

    raw_configs = CONFIGS_FILE.read_bytes() if CONFIGS_FILE.exists() else None
    if raw_configs is not None:
        vault.write_config_bytes(raw_configs, encrypted_path=ENC_CONFIGS)
    cfg.activate_secret_vault()
    if raw_configs is not None:
        vault.secure_remove_plaintext(CONFIGS_FILE)


def deobfuscate_configs() -> bool:
    """Explicitly restore encrypted proxy URIs and credentials to plaintext files."""
    from . import vault

    try:
        plaintext_configs = vault.read_config_bytes(ENC_CONFIGS) if ENC_CONFIGS.exists() else None
        had_secrets = vault.ENC_SECRETS_FILE.exists()
        if had_secrets:
            vault.read_secrets()
        if plaintext_configs is not None:
            vault.atomic_write(CONFIGS_FILE, plaintext_configs)
        if had_secrets:
            cfg.deactivate_secret_vault()
        if plaintext_configs is not None:
            ENC_CONFIGS.unlink(missing_ok=True)
        return plaintext_configs is not None or had_secrets
    except vault.VaultError:
        return False


def configs_are_obfuscated() -> bool:
    """Return whether saved proxy configurations are encrypted at rest."""
    from . import vault

    return vault.config_vault_active(ENC_CONFIGS)


def vault_is_active() -> bool:
    """Return whether either proxy config or supported secret vault data is active."""
    from . import vault

    return vault.config_vault_active(ENC_CONFIGS) or vault.secrets_vault_active()


# ─────────────────────────── AV exclusion ────────────────────────
#
# Windows Defender exclusions are limited to the isolated WinDivert driver folder
# (WINDIVERT_DIR). Nothing here runs automatically or silently. Adding or removing an
# exclusion needs an explicit typed confirmation, and UAC is requested only after it.
# The folder must hold nothing but the driver files, so the exclusion cannot widen to
# bins/, to other executables, or to a parent folder.

DEFENDER_WARNING = """
==============================================================================
  WINDOWS DEFENDER EXCLUSION FOR THE WINDIVERT DRIVER - READ BEFORE CONTINUING
==============================================================================
Blackout's GoodbyeDPI engine uses WinDivert, a packet-capture driver. Windows
Defender and other antivirus products often flag WinDivert, and tools built on
it, as "hacking tools" or potentially unwanted software. For this use these
detections are usually FALSE POSITIVES, but Blackout cannot verify them.

If you confirm, Windows will show a UAC prompt to add ONE exclusion:
    {folder}
That folder must hold only the WinDivert driver files. The rest of bins\\ is still
scanned, and Defender stays on. Remove the exclusion at any time with:
    blackout config --remove-defender-exclusion

Declining is safe: nothing changes, and you can keep using the SOCKS5/HTTP
proxy modes (for example xray), which do not need the WinDivert driver.
==============================================================================
"""

DEFENDER_FALLBACK_HINT = (
    "Continue without the WinDivert driver: use a SOCKS5/HTTP mode that does not need it, "
    "for example 'blackout connect xray' (SOCKS5 127.0.0.1:10808, HTTP 127.0.0.1:10809)."
)


def _normalize_windows_path(value) -> str:
    return os.path.normcase(os.path.normpath(str(value))).rstrip("\\/")


def same_windows_path(left, right) -> bool:
    """Exact, case-insensitive path comparison. Substring matches never count."""
    return _normalize_windows_path(left) == _normalize_windows_path(right)


def path_listed(exclusions, path) -> bool:
    return any(same_windows_path(item, path) for item in exclusions)


def windivert_folder_excluded(exclusions=None) -> bool:
    """Return True when Defender lists exactly the WinDivert driver folder."""
    if exclusions is None:
        exclusions = list_defender_exclusions()
    return path_listed(exclusions, WINDIVERT_DIR)


def _is_link_or_junction(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(os.path, "isjunction", None)  # Python 3.12+ on Windows
    return bool(is_junction and is_junction(str(path)))


def windivert_folder_problem() -> str | None:
    """Return why the WinDivert folder may not be excluded, or None when it is isolated."""
    folder = WINDIVERT_DIR
    if folder.name != "windivert" or folder.parent.resolve() != BINS_DIR.resolve():
        return "the WinDivert folder is not bins/windivert"
    if _is_link_or_junction(folder):
        return "the WinDivert folder is a symbolic link or junction"
    if not folder.is_dir():
        return "the WinDivert folder does not exist (run: blackout bins download goodbyedpi)"
    found = sorted(entry.name for entry in folder.iterdir())
    expected = sorted(WINDIVERT_DRIVER_FILES)
    if found != expected:
        return (
            "the WinDivert folder must contain only " + ", ".join(expected)
            + " (found: " + (", ".join(found) or "nothing") + ")"
        )
    for name in WINDIVERT_DRIVER_FILES:
        entry = folder / name
        if _is_link_or_junction(entry) or not entry.is_file():
            return f"{name} is not a regular file"
    return None


def _defender_exclusion_script(cmdlet: str, folder: Path) -> str:
    """PowerShell that applies one exclusion change to exactly `folder`."""
    quoted = str(folder).replace("'", "''")
    return f"$ErrorActionPreference = 'Stop'\n{cmdlet} -ExclusionPath '{quoted}'\n"


def _apply_defender_exclusion_change(cmdlet: str, want_present: bool) -> bool:
    """Run Add-/Remove-MpPreference for the WinDivert folder. Callers must have confirmed.

    The script travels as -EncodedCommand, so no path quoting can break out of it. A
    non-elevated attempt runs first; UAC is requested only if that attempt did not
    change the state, and the result is always re-read from Defender.
    """
    import base64
    import ctypes

    script = _defender_exclusion_script(cmdlet, WINDIVERT_DIR)
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    args = ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded]
    try:
        subprocess.run(["powershell", *args], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        _log.info("Defender exclusion attempt without elevation failed: %s", exc)
    if windivert_folder_excluded() == want_present:
        return True

    _log.info("Defender change needs administrator rights; requesting UAC after confirmation.")
    handle, _pid = elevate.launch_elevated("powershell.exe", args)
    if handle:
        ctypes.windll.kernel32.WaitForSingleObject(handle, 60000)
        ctypes.windll.kernel32.CloseHandle(handle)
    return windivert_folder_excluded() == want_present


def add_windivert_exclusion(*, confirmed: bool = False) -> bool:
    """Add the exclusion for bins/windivert only.

    Refuses unless `confirmed` is True and the folder passes windivert_folder_problem().
    Nothing calls this without an explicit user confirmation.
    """
    if not confirmed or sys.platform != "win32":
        return False
    if windivert_folder_problem() is not None:
        return False
    if windivert_folder_excluded():
        return True
    return _apply_defender_exclusion_change("Add-MpPreference", want_present=True)


def remove_windivert_exclusion(*, confirmed: bool = False) -> bool:
    """Remove the exclusion for bins/windivert only. Requires explicit confirmation."""
    if not confirmed or sys.platform != "win32":
        return False
    if not windivert_folder_excluded():
        return True
    return _apply_defender_exclusion_change("Remove-MpPreference", want_present=False)


def run_windivert_exclusion_setup(*, confirm, emit, remove: bool = False) -> str:
    """Confirmation-gated setup or removal. Returns a status code and changes nothing unconfirmed.

    `confirm()` must return True only for an explicit affirmative answer. It is called
    before any UAC prompt. Status codes: unsupported, unsafe-folder, already-present,
    not-present, declined, added, removed, failed.
    """
    if sys.platform != "win32":
        emit("Defender exclusions are available only on Windows. No changes were made.")
        return "unsupported"

    if remove:
        if not windivert_folder_excluded():
            emit("The WinDivert folder has no Defender exclusion. No changes were made.")
            return "not-present"
        emit(f"This removes the Defender exclusion for {WINDIVERT_DIR}. Defender will scan it again.")
        if not confirm():
            emit("Cancelled. No changes were made.")
            return "declined"
        if remove_windivert_exclusion(confirmed=True):
            emit("Defender exclusion removed.")
            return "removed"
        emit("The exclusion could not be removed (UAC was cancelled or Defender refused).")
        return "failed"

    problem = windivert_folder_problem()
    if problem is not None:
        emit(f"Refusing to add a Defender exclusion: {problem}. No changes were made.")
        return "unsafe-folder"
    if windivert_folder_excluded():
        emit("The WinDivert driver folder is already excluded. No changes were made.")
        return "already-present"

    emit(DEFENDER_WARNING.format(folder=WINDIVERT_DIR))
    if not confirm():
        emit("Declined. No changes were made.")
        emit(DEFENDER_FALLBACK_HINT)
        return "declined"
    if add_windivert_exclusion(confirmed=True):
        emit(f"Defender exclusion added for {WINDIVERT_DIR} only.")
        return "added"
    emit("Windows did not confirm the exclusion (UAC was cancelled or Defender refused it).")
    emit(DEFENDER_FALLBACK_HINT)
    return "failed"


def verify_exclusion_added(path: Path | None = None) -> bool:
    """Return True only if Defender lists exactly `path` (default: the WinDivert folder)."""
    if sys.platform != "win32":
        return False
    try:
        return path_listed(list_defender_exclusions(), path or WINDIVERT_DIR)
    except Exception:
        return False


def list_defender_exclusions() -> list[str]:
    """
    Return the list of paths currently excluded from Windows Defender scanning.
    Returns an empty list on non-Windows or if the query fails.
    """
    if sys.platform != "win32":
        return []
    try:
        ps = "(Get-MpPreference).ExclusionPath"
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True, text=True, timeout=15,
        )
        lines = [ln.strip() for ln in result.stdout.splitlines() if ln.strip()]
        return lines
    except Exception:
        return []


# ─────────────────────────── Stability tracking ──────────────────

import threading as _threading
import time as _time

_STABILITY_FILE = APP_DATA_DIR / "stability.json"
_MAX_HISTORY    = 20  # Keep last N latency measurements per engine
_stability_lock = _threading.Lock()


def record_latency(engine_name: str, latency_ms: float | None):
    """Record a latency sample for an engine."""
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
    with _stability_lock:
        try:
            data = json.loads(_STABILITY_FILE.read_text()) if _STABILITY_FILE.exists() else {}
        except Exception:
            data = {}

        samples = data.get(engine_name, [])
        samples.append({"ts": _time.time(), "ms": latency_ms})
        samples = samples[-_MAX_HISTORY:]
        data[engine_name] = samples
        _STABILITY_FILE.write_text(json.dumps(data, indent=2))


def reset_stability(engine_name: str | None = None):
    """
    Clear stability history.
    Pass engine_name to clear one engine only, or None to reset all.
    """
    with _stability_lock:
        if not _STABILITY_FILE.exists():
            return
        try:
            data = json.loads(_STABILITY_FILE.read_text())
        except Exception:
            data = {}

        if engine_name is None:
            data = {}
        else:
            data.pop(engine_name, None)

        _STABILITY_FILE.write_text(json.dumps(data, indent=2))


def get_stability_score(engine_name: str) -> dict:
    """
    Return stability statistics for an engine.
    {avg_ms, loss_pct, trend, stable}
    """
    try:
        data    = json.loads(_STABILITY_FILE.read_text())
        samples = data.get(engine_name, [])
    except Exception:
        return {"avg_ms": None, "loss_pct": 100, "trend": "unknown", "stable": False}

    if not isinstance(samples, list) or not samples:
        return {"avg_ms": None, "loss_pct": 100, "trend": "unknown", "stable": False}

    timeouts = 0
    valid = []
    for sample in samples:
        if not isinstance(sample, dict):
            timeouts += 1
            continue
        value = sample.get("ms")
        if value is None:
            timeouts += 1
            continue
        try:
            value = float(value)
        except (TypeError, ValueError):
            timeouts += 1
            continue
        if math.isfinite(value) and value >= 0:
            valid.append(value)
        else:
            timeouts += 1
    loss_pct = 100 * timeouts / len(samples)
    avg_ms   = sum(valid) / len(valid) if valid else None

    # Trend: compare first half vs second half latency
    trend = "stable"
    if len(valid) >= 4:
        half   = len(valid) // 2
        first  = sum(valid[:half]) / half
        second  = sum(valid[half:]) / (len(valid) - half)
        if second > first * 1.5:
            trend = "degrading"
        elif second < first * 0.8:
            trend = "improving"

    stable = loss_pct < 20 and (avg_ms is None or avg_ms < 500)
    return {"avg_ms": avg_ms, "loss_pct": loss_pct, "trend": trend, "stable": stable}


def get_recent_latencies(engine_name: str) -> list:
    """Return raw list of recent latency measurements (float or None)."""
    try:
        data = json.loads(_STABILITY_FILE.read_text()) if _STABILITY_FILE.exists() else {}
        return [s.get("ms") for s in data.get(engine_name, [])]
    except Exception:
        return []


def all_stability_scores() -> dict:
    """
    Return stability scores for every engine that has recorded data.
    Keys are engine names; values are the same dicts as get_stability_score().
    """
    try:
        data = json.loads(_STABILITY_FILE.read_text()) if _STABILITY_FILE.exists() else {}
    except Exception:
        return {}
    return {name: get_stability_score(name) for name in data}


def stability_alert(
    engine_name: str,
    threshold_loss_pct: float = 30.0,
    threshold_avg_ms: float   = 800.0,
) -> tuple[bool, str]:
    """
    Check whether an engine has crossed degradation thresholds.

    Returns (True, reason) if the engine needs attention,
    or (False, "") if everything looks fine.

    threshold_loss_pct: packet-loss % that triggers an alert (default 30%)
    threshold_avg_ms:   average latency that triggers an alert (default 800ms)
    """
    score = get_stability_score(engine_name)

    if score["loss_pct"] >= threshold_loss_pct:
        return True, (
            f"{engine_name} has {score['loss_pct']:.0f}% packet loss "
            f"(threshold {threshold_loss_pct:.0f}%)"
        )

    if score["avg_ms"] is not None and score["avg_ms"] >= threshold_avg_ms:
        return True, (
            f"{engine_name} average latency {score['avg_ms']:.0f}ms "
            f"exceeds {threshold_avg_ms:.0f}ms threshold"
        )

    if score["trend"] == "degrading":
        return True, f"{engine_name} latency trend is degrading"

    return False, ""
