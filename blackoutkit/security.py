"""
Blackout Kit - Security module.

Three layers (user chooses):
  SPEED   (default) — zero extra overhead. Just connect, fast. No logging.
  PRIVATE — random TLS fingerprint, DoH DNS, no system proxy footprint.
  LEGEND  — 🔥 The legendary mode. Multi-hop onion routing, encrypted
             configs, randomized timing, full traffic obfuscation.
             Default: OFF. Enable only if you want max privacy.

Also handles:
  - Config file obfuscation (protect server credentials at rest)
  - Windows Defender exclusion for bins/
  - Kill switch with DoH/DoT leak protection (port 853 TCP+UDP)
  - Stability tracking with reset, bulk query, and alert helpers
  - Mode enforcement verification
  - Defender exclusion verification and listing
"""
import base64
import hashlib
import json
import logging
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

from . import settings as cfg
from . import elevate

_log = logging.getLogger(__name__)

from . import PROJECT_ROOT, APP_DATA_DIR, BINS_DIR, DATA_DIR
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
            "🔥 LEGENDARY MODE — Multi-hop routing (SNI→XRay→Tor), "
            "randomized packet timing, encrypted config storage, "
            "kill-switch enabled. SLOW but near-untraceable."
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
    "BlackoutKit-KillSwitch-Block-DoH",   # TCP port 853 (DoH/DoT leaks)
    "BlackoutKit-KillSwitch-Block-DoT",   # UDP port 853 (DNS-over-TLS leaks)
]

# Minimum rules that MUST exist for the kill switch to be considered active.
_KS_REQUIRED_RULES = [
    "BlackoutKit-KillSwitch-Block",
    "BlackoutKit-KillSwitch-Allow-Proxy",
    "BlackoutKit-KillSwitch-Allow-DNS",
    "BlackoutKit-KillSwitch-Allow-DNS-TCP",
    "BlackoutKit-KillSwitch-Allow-DHCP",
]


def _get_proxy_processes() -> list[str]:
    """Return full paths to known proxy binaries in the bins/ folder."""
    candidates = [
        "xray.exe", "sni-spoofing.exe", "sni-spoof.exe", "sni.exe",
        "tor.exe", "goodbyedpi.exe", "warp-plus.exe",
        "psiphon-tunnel-core-x86_64.exe", "psiphon-tunnel-core.exe",
        "sing-box.exe", "blackout-engine.exe", "blackout_core.dll",
        "wireguard.exe", "openvpn.exe", "softether.exe",
        "mhrv.exe", "mhrv-rs.exe",
    ]
    results = []
    for name in candidates:
        path = (BINS_DIR / name).resolve()
        if path.exists():
            results.append(str(path))
    return results


def enable_kill_switch() -> bool:
    with _ks_lock:
        return _enable_kill_switch_impl()


def _enable_kill_switch_impl() -> bool:
    """
    Block all internet traffic unless it goes through our proxy.
    Uses Windows Firewall with per-process allow rules (requires admin).

    The key design improvement over the old version:
    - OLD: used 'localport=10808,10809,...' which FAILED because proxy
           outbound connections use random source ports, not the listen port
    - NEW: allows proxy EXECUTABLES by path, so their outbound connections
           are always permitted regardless of source port

    Also allows: DNS (port 53), DHCP (port 67/68), LAN IP ranges.
    Also blocks: DoH/DoT (port 853) to prevent encrypted DNS leaks.
    """
    if sys.platform != "win32":
        return False

    proxy_paths = _get_proxy_processes()
    proxy_allow_rules = ""
    for i, p in enumerate(proxy_paths):
        safe_path = p.replace("'", "''")
        proxy_allow_rules += (
            f'New-NetFirewallRule -DisplayName "BlackoutKit-KillSwitch-Allow-Proxy-{i}" '
            f'-Direction Outbound -Action Allow -Program \'{safe_path}\' -Profile Any | Out-Null\n'
        )
    if not proxy_allow_rules:
        # No proxy binaries found — create a generic TCP allow rule as fallback
        # This is less secure but prevents complete internet loss
        proxy_allow_rules = (
            'New-NetFirewallRule -DisplayName "BlackoutKit-KillSwitch-Allow-Proxy" '
            '-Direction Outbound -Action Allow -Profile Any | Out-Null\n'
        )

    ps = f"""
# ── Remove old-style rules if they exist (pre-v2.0 format) ──
$oldRules = @("BlackoutKit-KillSwitch-Allow-Proxy", "BlackoutKit-KillSwitch-Allow-LAN")
foreach ($r in $oldRules) {{
    try {{ netsh advfirewall firewall delete rule name="$r" 2>$null | Out-Null }} catch {{}}
}}
# Remove old Allow-Proxy-N rules if they exist
for ($i = 0; $i -lt 50; $i++) {{
    try {{ netsh advfirewall firewall delete rule name="BlackoutKit-KillSwitch-Allow-Proxy-$i" 2>$null | Out-Null }} catch {{}}
}}

# ── Block all outbound traffic ──
New-NetFirewallRule -DisplayName "BlackoutKit-KillSwitch-Block" -Direction Outbound -Action Block -Profile Any | Out-Null

# ── Allow proxy processes (per-process rules) ──
{proxy_allow_rules}

# ── Allow LAN traffic (SMB, printer, local services) ──
New-NetFirewallRule -DisplayName "BlackoutKit-KillSwitch-Allow-LAN" -Direction Outbound -Action Allow `
    -RemoteIP 192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,169.254.0.0/16,127.0.0.0/8,::1/128,fe80::/10,fc00::/7 | Out-Null

# ── Allow DNS (port 53) — needed for name resolution ──
New-NetFirewallRule -DisplayName "BlackoutKit-KillSwitch-Allow-DNS" -Direction Outbound -Action Allow `
    -Protocol UDP -RemotePort 53 | Out-Null
New-NetFirewallRule -DisplayName "BlackoutKit-KillSwitch-Allow-DNS-TCP" -Direction Outbound -Action Allow `
    -Protocol TCP -RemotePort 53 | Out-Null

# ── Allow DHCP (port 67/68) — needed for IP address renewal ──
New-NetFirewallRule -DisplayName "BlackoutKit-KillSwitch-Allow-DHCP" -Direction Outbound -Action Allow `
    -Protocol UDP -RemotePort 67,68 | Out-Null

# ── Block DoH/DoT (port 853) — prevents encrypted DNS leaks ──
New-NetFirewallRule -DisplayName "BlackoutKit-KillSwitch-Block-DoH" -Direction Outbound -Action Block `
    -Protocol TCP -RemotePort 853 | Out-Null
New-NetFirewallRule -DisplayName "BlackoutKit-KillSwitch-Block-DoT" -Direction Outbound -Action Block `
    -Protocol UDP -RemotePort 853 | Out-Null

Write-Output "OK:kill_switch_enabled"
"""
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps],
        capture_output=True, text=True, timeout=30,
    )
    if "OK" not in result.stdout:
        _log.warning("Kill switch enable failed. stdout=%s stderr=%s", result.stdout.strip(), result.stderr.strip())
        return False
    return kill_switch_is_active()


def test_kill_switch() -> tuple[bool, str]:
    """
    Verify the kill switch actually blocks non-proxy traffic.
    Connects to an external host DIRECTLY (not through proxy) and
    expects the connection to FAIL.

    Returns (passed: bool, details: str).
    """
    if sys.platform != "win32":
        return True, "Not on Windows — kill switch is N/A"
    if not kill_switch_is_active():
        return False, "Kill switch is NOT active. Enable it first: blackout killswitch on"

    import socket
    test_hosts = ["8.8.8.8", "1.1.1.1", "google.com"]
    for host in test_hosts:
        try:
            with socket.create_connection((host, 443), timeout=3.0):
                return False, (
                    f"Kill switch FAILED! Direct connection to {host}:443 succeeded.\n"
                    "Traffic can bypass the proxy — your real IP is exposed."
                )
        except (OSError, socket.timeout):
            continue  # Expected — kill switch blocked it

    # Try DNS as well (should be allowed via our DNS allow rules)
    try:
        import socket as _s
        _s.setdefaulttimeout(3.0)
        _s.getaddrinfo("google.com", 443)
        dns_status = "DNS: ALLOWED (can resolve names)"
    except Exception:
        dns_status = "[WARN] DNS: BLOCKED (cannot resolve names — DoH must be enabled in XRay)"
    finally:
        _s.setdefaulttimeout(None)

    return True, (
        f"Kill switch VERIFIED: all direct outbound connections blocked.\n"
        f"{dns_status}\n"
        f"Proxy traffic is ALLOWED via per-process firewall rules."
    )


def disable_kill_switch() -> bool:
    with _ks_lock:
        return _disable_kill_switch_impl()


def _disable_kill_switch_impl() -> bool:
    """Remove all kill-switch firewall rules (including DoH/DoT blocks + per-process proxy rules)."""
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
    """
    Query Windows Firewall to verify ALL required kill-switch rules exist.
    Required: Block + Allow-Proxy + Allow-DNS + Allow-DHCP.
    """
    if sys.platform != "win32":
        return False

    # PowerShell can query by display name regardless of how the rule was created
    ps = r"""
$required = @(
    "BlackoutKit-KillSwitch-Block",
    "BlackoutKit-KillSwitch-Allow-DNS",
    "BlackoutKit-KillSwitch-Allow-DNS-TCP",
    "BlackoutKit-KillSwitch-Allow-DHCP"
)
# Check per-process proxy rules OR generic Allow-Proxy
$proxyRules = Get-NetFirewallRule -DisplayName "BlackoutKit-KillSwitch-Allow-Proxy-*" -ErrorAction SilentlyContinue
$genericProxy = Get-NetFirewallRule -DisplayName "BlackoutKit-KillSwitch-Allow-Proxy" -ErrorAction SilentlyContinue
$proxyOk = ($proxyRules.Count -gt 0) -or ($genericProxy -ne $null)
$allOk = $proxyOk
foreach ($r in $required) {
    $rule = Get-NetFirewallRule -DisplayName $r -ErrorAction SilentlyContinue
    if ($rule -eq $null) { $allOk = $false }
}
if ($allOk) { Write-Output "ACTIVE" } else { Write-Output "INACTIVE" }
"""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True, text=True, timeout=15,
        )
        return "ACTIVE" in result.stdout
    except Exception:
        return False


# ─────────────────────────── Config encryption (AES-256-GCM) ─────
# AES-256-GCM with PBKDF2-derived key tied to machine hardware ID.
# File format: b"BKAE01:" + base64(nonce[12] + ciphertext)
# Falls back to XOR read for files encrypted with the old format.

_AES_HEADER    = b"BKAE01:"
_PBKDF2_SALT   = b"blackout-kit-aes256gcm-2026"
_PBKDF2_ITERS  = 100_000


def _get_machine_id() -> bytes:
    """Return raw machine identifier bytes (UUID on Windows, hostname elsewhere)."""
    try:
        if sys.platform == "win32":
            result = subprocess.run(
                ["wmic", "csproduct", "get", "UUID"],
                capture_output=True, text=True,
            )
            # Skip the "UUID" header line — take the first non-empty, non-header line
            lines = [l.strip() for l in result.stdout.splitlines()
                     if l.strip() and l.strip().upper() != "UUID"]
            uid = lines[0] if lines else ""
        else:
            uid = platform.node()
        return uid.encode() if uid else b"blackout-kit-unknown-machine"
    except Exception:
        return b"blackout-kit-default-machine-id"


def _derive_aes_key(machine_id: bytes) -> bytes:
    """Derive a 32-byte AES-256 key via PBKDF2-HMAC-SHA256."""
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
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
    """
    Encrypt configs.txt with AES-256-GCM, save to configs.enc.
    Then securely wipe configs.txt.
    Falls back to XOR if the cryptography library is not installed.
    """
    if not CONFIGS_FILE.exists():
        return
    raw = CONFIGS_FILE.read_bytes()
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        key    = _derive_aes_key(_get_machine_id())
        aesgcm = AESGCM(key)
        nonce  = os.urandom(12)                         # 96-bit random nonce
        ct      = aesgcm.encrypt(nonce, raw, None)       # includes 16-byte GCM tag
        payload = _AES_HEADER + base64.b64encode(nonce + ct)
        _atomic_write_bytes(ENC_CONFIGS, payload)
    except ImportError:
        # cryptography not installed — fall back to XOR
        key   = _get_machine_key()
        xored = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
        _atomic_write_bytes(ENC_CONFIGS, base64.b64encode(xored))

    # Securely wipe plaintext before deleting
    CONFIGS_FILE.write_bytes(b"\x00" * len(raw))
    CONFIGS_FILE.unlink()


def deobfuscate_configs() -> bool:
    """
    Decrypt configs.enc → configs.txt.
    Auto-detects AES-256-GCM (new) vs XOR (legacy) format.
    Returns True on success.
    """
    if not ENC_CONFIGS.exists():
        return False
    try:
        raw_file = ENC_CONFIGS.read_bytes()

        if raw_file.startswith(_AES_HEADER):
            # ── AES-256-GCM format ──
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            blob   = base64.b64decode(raw_file[len(_AES_HEADER):])
            nonce  = blob[:12]
            ct     = blob[12:]
            key    = _derive_aes_key(_get_machine_id())
            aesgcm = AESGCM(key)
            plain  = aesgcm.decrypt(nonce, ct, None)
        else:
            # ── Legacy XOR format ──
            xored = base64.b64decode(raw_file)
            key   = _get_machine_key()
            plain = bytes(b ^ key[i % len(key)] for i, b in enumerate(xored))

        CONFIGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        CONFIGS_FILE.write_bytes(plain)
        return True
    except Exception:
        return False


def configs_are_obfuscated() -> bool:
    return ENC_CONFIGS.exists() and not CONFIGS_FILE.exists()


# ─────────────────────────── AV exclusion ────────────────────────

def add_defender_exclusion(path: Path | None = None) -> bool:
    """
    Add the bins/ folder to Windows Defender exclusions.
    Prevents Defender from flagging WinDivert, sni-spoofing.exe, etc.
    Auto-elevates via UAC if not running as admin.
    """
    if sys.platform != "win32":
        return False
    target = str(path or BINS_DIR.resolve())
    env = {**os.environ, "BLACKOUT_EXCL_PATH": target}
    ps = 'Add-MpPreference -ExclusionPath $env:BLACKOUT_EXCL_PATH; Write-Output "OK"'
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps],
        capture_output=True, text=True, timeout=20, env=env,
    )
    if "OK" in result.stdout:
        return True

    _log.info("Defender exclusion needs admin — requesting elevation via UAC…")
    import tempfile
    import os
    fd, path = tempfile.mkstemp(suffix=".txt")
    os.close(fd)
    marker = Path(path)
    ps_elevated = (
        f'Add-MpPreference -ExclusionPath "{target}"; '
        f'Write-Output "OK" | Out-File -FilePath "{marker}" -Encoding UTF8'
    )
    handle, pid = elevate.launch_elevated(
        "powershell.exe",
        ["-NoProfile", "-Command", ps_elevated],
    )
    if handle is None:
        return False
    import ctypes
    ctypes.windll.kernel32.WaitForSingleObject(handle, 30000)
    ctypes.windll.kernel32.CloseHandle(handle)
    ok = marker.exists() and "OK" in marker.read_text()
    marker.unlink(missing_ok=True)
    return ok


def remove_defender_exclusion(path: Path | None = None) -> bool:
    if sys.platform != "win32":
        return False
    target = str(path or BINS_DIR.resolve())
    env = {**os.environ, "BLACKOUT_EXCL_PATH": target}
    ps = 'Remove-MpPreference -ExclusionPath $env:BLACKOUT_EXCL_PATH; Write-Output "OK"'
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps],
        capture_output=True, text=True, timeout=20, env=env,
    )
    if "OK" in result.stdout:
        return True

    _log.info("Defender exclusion removal needs admin — requesting elevation via UAC…")
    import tempfile
    import os
    fd, path = tempfile.mkstemp(suffix=".txt")
    os.close(fd)
    marker = Path(path)
    ps_elevated = (
        f'Remove-MpPreference -ExclusionPath "{target}"; '
        f'Write-Output "OK" | Out-File -FilePath "{marker}" -Encoding UTF8'
    )
    handle, pid = elevate.launch_elevated(
        "powershell.exe",
        ["-NoProfile", "-Command", ps_elevated],
    )
    if handle is None:
        return False
    import ctypes
    ctypes.windll.kernel32.WaitForSingleObject(handle, 30000)
    ctypes.windll.kernel32.CloseHandle(handle)
    ok = marker.exists() and "OK" in marker.read_text()
    marker.unlink(missing_ok=True)
    return ok


def verify_exclusion_added(path: Path | None = None) -> bool:
    """
    Query Windows Defender to confirm the exclusion actually exists —
    not just whether add_defender_exclusion() returned True.
    Returns True if the path appears in the active exclusion list.
    """
    if sys.platform != "win32":
        return False
    target = str(path or BINS_DIR.resolve()).lower()
    try:
        ps = "(Get-MpPreference).ExclusionPath -join '|'"
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True, text=True, timeout=15,
        )
        exclusions = result.stdout.strip().lower()
        return target in exclusions
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

    if not samples:
        return {"avg_ms": None, "loss_pct": 100, "trend": "unknown", "stable": False}

    timeouts = [s for s in samples if s["ms"] is None]
    valid    = [s["ms"] for s in samples if s["ms"] is not None]
    loss_pct = 100 * len(timeouts) / len(samples)
    avg_ms   = sum(valid) / len(valid) if valid else None

    # Trend: compare first half vs second half latency
    trend = "stable"
    if len(valid) >= 4:
        half   = len(valid) // 2
        first  = sum(valid[:half]) / half
        second = sum(valid[half:]) / (len(valid) - half)
        if second > first * 1.5:
            trend = "degrading"
        elif second < first * 0.8:
            trend = "improving"

    stable = loss_pct < 20 and (avg_ms is None or avg_ms < 500)
    return {"avg_ms": avg_ms, "loss_pct": loss_pct, "trend": trend, "stable": stable}


def all_stability_scores() -> dict[str, dict]:
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
