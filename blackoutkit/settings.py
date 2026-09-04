"""
Blackout Kit - User settings and customization.

Features:
  - Type + bounds validation on every set_value() call
  - Environment variable overrides: BLACKOUT_<KEY>=value
  - validate_all() for startup sanity check
"""
import json
import logging
import os
import re
import sys
import tempfile
import threading
from pathlib import Path

from . import vault

_log = logging.getLogger(__name__)
_settings_lock = threading.Lock()

APP_DATA_DIR  = Path.home() / ".blackout-kit"
SETTINGS_FILE = APP_DATA_DIR / "settings.json"

SENSITIVE_KEYS = frozenset({
    "ikev2_password",
    "ikev2_psk",
    "softether_password",
})

SETTINGS_SCHEMA_VERSION = 1
_SETTINGS_SCHEMA_KEY = "_schema_version"


def display_value(key: str, value):
    """Return a safe representation for settings shown in routine output."""
    if key in SENSITIVE_KEYS and value:
        return "[hidden]"
    return value


DEFAULTS = {
    # Network ports
    "sni_listen_port":      40443,
    "xray_socks_port":      10808,
    "xray_http_port":       10809,
    "psiphon_http_port":    8081,
    "psiphon_socks_port":   1081,

    # SNI Engine
    "sni_connect_ip":       "104.19.229.21",
    "sni_connect_port":     443,
    "sni_custom_fakes":      [],         # Custom fake SNI hostnames to test
    "sni_fake_sni":         "www.hcaptcha.com",
    "sni_always_test_all_ips": False,   # If True, runs full TLS tests on all scanned IPs in auto mode
    "sni_custom_ips":       [],         # Custom user-defined IPs to test first

    # XRay Engine
    "xray_log_level":       "warning",   # debug / info / warning / error / none
    "xray_mux_enabled":     False,
    "xray_fingerprint":     "chrome",    # chrome / firefox / safari / random

    # GoodbyeDPI
    "gdpi_backend":        "legacy",   # legacy = stable goodbyedpi.exe path, native = experimental Go/WinDivert path
    "gdpi_flags":           "auto",      # auto = try all modesets, or specify e.g. -1 -2 -5
    "gdpi_always_test_all": False,      # If True, auto-detection tests all modesets on every launch

    # Psiphon
    "psiphon_country":      "DE",        # Country code for exit node

    # MHRV
    "mhrv_direct":          False,       # Run mhrv in direct transparent mode without Google Apps Script relay

    # System proxy
    "auto_set_proxy":       True,        # Automatically set Windows system proxy
    "proxy_host":           "127.0.0.1",
    "proxy_port":           10809,

    # Scan settings
    "scan_concurrency":     100,         # Parallel IP scan workers
    "scan_timeout":         2.0,         # Seconds per IP timeout
    "scan_ip_count":        100,         # IPs to generate per scan

    # Emergency mode
    "engine_order":         ["sni", "gdpi", "psiphon"],  # Priority order
    "retry_interval":       30,          # Seconds between connection checks
    "max_retries":          3,           # Retries per engine before giving up
    "reconnect_initial_delay": 2,        # First retry delay in seconds
    "reconnect_max_delay":    60,        # Exponential retry delay cap in seconds

    # Daemon
    "daemon_log_lines":     200,         # Max lines to keep in daemon log

    # UI
    "show_banner":          True,
    "show_disclaimer":      True,        # Show the legal disclaimer under the banner
    "show_first_run":       False,       # Show the "First Run" welcome panel (auto-shown on true first launch)
    "color_theme":          "red",       # red / blue / green / purple
    "terminal_theme":       "dark",      # dark / light (Blackout Kit Rich palette only)

    # Security modes
    "security_mode":        "speed",     # speed / private / legend
    "kill_switch":          False,       # Enable the verified Linux endpoint-scoped firewall kill switch
    "secrets_vault_enabled": False,      # Keep supported VPN secrets encrypted at rest

    # IKEv2 / Windows built-in VPN
    "ikev2_server":         "",
    "ikev2_username":       "",
    "ikev2_password":       "",
    "ikev2_psk":            "",
    "ikev2_tunnel_type":    "IKEv2",    # IKEv2 | L2tp | Sstp | Pptp

    # WireGuard
    "wg_config_file":       "",
    "wg_interface":         "wg0",

    # OpenVPN
    "openvpn_config":       "",

    # SoftEther VPN
    "softether_host":       "",
    "softether_port":       443,
    "softether_hub":        "VPN",
    "softether_username":   "",
    "softether_password":   "",

    # Neighbor (LAN peer sharing)
    "neighbor_proxy_port":  10809,
    "neighbor_bind_lan":    False,
    "lan_neighbor_cache_ttl_minutes": 10,     # How long to trust cached neighbors
    "lan_neighbor_cache_max_size": 50,        # Max neighbors to store in cache

    # Google Apps Script relay
    "gas_proxy_port":       8087,

    # Country profile
    "country":              "",  # ISO code (IR/RU/US/GB/CN/IQ/EU). Empty = auto-detect from ISP.

    # Iran 2026 Evasion
    "xray_fragment":        "10-50,10-50",  # TLS record fragment mode (range,range)
    "sni_arvancloud_sni":   "www.arvancloud.ir",  # Fake SNI using Iran's domestic CDN (can't be blocked)

    # Routing & Privacy
    "xray_split_tunnel":    True,        # Bypass proxy for LAN and .ir domestic traffic
    "xray_doh_dns":         True,        # Use encrypted DNS-over-HTTPS through XRay

    # Bypass strategy selection
    "selected_engine":      "auto",      # auto / sni / gdpi / psiphon / warp / legend / etc.

    # Smart config rotation
    "config_rotation":     True,        # Rotate to next saved config when current endpoint fails (blocked IP)

    # AmneziaWG
    "awg_config_file":     "",          # Full path to AmneziaWG .conf file

    # Packet capture
    "capture_default_iface": "",        # Empty = pass no --iface, let scapy pick / require explicit choice
    "capture_max_packets":  2000,       # In-memory ring buffer cap feeding the live view + summary

    # Download manager
    "download_speed_limit_kbps": 0,     # Global speed limit (0 = unlimited)
    "download_max_parallel": 2,         # Max concurrent downloads (default 2)
    "download_auto_resume": True,       # Auto-resume on daemon startup

    # Bandwidth caps
    "bandwidth_caps_enabled": False,    # Enable bandwidth cap tracking and alerts
    "bandwidth_alert_threshold": 80,    # Alert when usage exceeds this % of limit

    # Traffic logging
    "traffic_logging_enabled": False,   # Enable per-connection audit trail (privacy concern)
    "traffic_log_max_entries": 100000,  # Max entries before auto-pruning (roughly 30 days at 1Hz)
    "traffic_log_retention_days": 30,   # Auto-prune entries older than this
    "traffic_log_sample_interval_sec": 10,  # Snapshot connections every N seconds

    # Ad blocking
    "adblock_enabled": False,           # Enable network-level ad/tracker blocking
    "adblock_block_mode": "null",       # null (0.0.0.0) or sinkhole (custom IP)
    "adblock_sinkhole_ip": "0.0.0.0",   # IP to serve for blocked domains
    "adblock_auto_update_interval_hours": 24,  # Auto-update blocklists every N hours
    "adblock_query_log_enabled": False,  # Log all DNS queries (privacy concern)

    # QoS (monitor-only local configuration and inspection)
    "qos_enabled": False,               # Enable persisted QoS rule metadata
    "qos_enforcement_mode": "monitor", # off / monitor
    "qos_default_priority": 50,         # Default priority metadata for new rules (0-100)
    "qos_alert_threshold_pct": 110,     # Stored threshold metadata for violation inspection
    "qos_rate_limit_precision_ms": 100, # Stored compatibility metadata

    # Wi-Fi MAC privacy (applied only by explicit tools mac commands)
    "mac_preferred_adapter": "",       # Optional active physical Wi-Fi adapter name
    "mac_randomization_prefix": "02",  # Locally administered + unicast first octet
    "mac_custom_private_address": "",  # Optional locally administered + unicast MAC
}


SETTING_GROUPS = {
    "Network Ports": (
        "sni_listen_port", "sni_connect_port", "xray_socks_port", "xray_http_port",
        "psiphon_http_port", "psiphon_socks_port", "proxy_port", "neighbor_proxy_port",
        "gas_proxy_port", "softether_port",
    ),
    "SNI Engine": (
        "sni_connect_ip", "sni_custom_fakes", "sni_fake_sni", "sni_always_test_all_ips",
        "sni_custom_ips", "sni_arvancloud_sni",
    ),
    "XRay": ("xray_log_level", "xray_mux_enabled", "xray_fingerprint", "xray_fragment"),
    "GoodbyeDPI": ("gdpi_backend", "gdpi_flags", "gdpi_always_test_all"),
    "Psiphon": ("psiphon_country",),
    "MHRV": ("mhrv_direct",),
    "System Proxy": ("auto_set_proxy", "proxy_host"),
    "Scanning": ("scan_concurrency", "scan_timeout", "scan_ip_count"),
    "Reconnect": ("engine_order", "retry_interval", "max_retries", "reconnect_initial_delay", "reconnect_max_delay"),
    "Daemon": ("daemon_log_lines",),
    "User Interface": ("show_banner", "show_disclaimer", "show_first_run", "color_theme", "terminal_theme"),
    "Security": ("security_mode", "kill_switch", "secrets_vault_enabled"),
    "IKEv2 / L2TP": ("ikev2_server", "ikev2_username", "ikev2_password", "ikev2_psk", "ikev2_tunnel_type"),
    "WireGuard": ("wg_config_file", "wg_interface"),
    "OpenVPN": ("openvpn_config",),
    "SoftEther": ("softether_host", "softether_hub", "softether_username", "softether_password"),
    "Neighbor Sharing": ("neighbor_bind_lan", "lan_neighbor_cache_ttl_minutes", "lan_neighbor_cache_max_size"),
    "Country and Routing": ("country", "xray_split_tunnel", "xray_doh_dns"),
    "Engine Selection": ("selected_engine", "config_rotation"),
    "AmneziaWG": ("awg_config_file",),
    "Packet Capture": ("capture_default_iface", "capture_max_packets"),
    "Downloads": ("download_speed_limit_kbps", "download_max_parallel", "download_auto_resume"),
    "Bandwidth Caps": ("bandwidth_caps_enabled", "bandwidth_alert_threshold"),
    "Traffic Logging": ("traffic_logging_enabled", "traffic_log_max_entries", "traffic_log_retention_days", "traffic_log_sample_interval_sec"),
    "Ad Blocking": ("adblock_enabled", "adblock_block_mode", "adblock_sinkhole_ip", "adblock_auto_update_interval_hours", "adblock_query_log_enabled"),
    "QoS": ("qos_enabled", "qos_enforcement_mode", "qos_default_priority", "qos_alert_threshold_pct", "qos_rate_limit_precision_ms"),
    "Wi-Fi MAC Privacy": ("mac_preferred_adapter", "mac_randomization_prefix", "mac_custom_private_address"),
}

SETTING_CHOICES = {
    "gdpi_backend": ("legacy", "native"),
    "xray_log_level": ("debug", "info", "warning", "error", "none"),
    "xray_fingerprint": ("chrome", "firefox", "safari", "random"),
    "security_mode": ("speed", "private", "legend"),
    "ikev2_tunnel_type": ("IKEv2", "L2tp", "Sstp", "Pptp"),
    "color_theme": ("red", "blue", "green", "purple"),
    "terminal_theme": ("dark", "light"),
    "selected_engine": (
        "auto", "sni", "xray", "gdpi", "psiphon", "warp", "tun", "tor", "mhrv",
        "ikev2", "wireguard", "openvpn", "softether", "appsscript", "hysteria2",
        "tuic", "awg", "legend",
    ),
    "qos_enforcement_mode": ("off", "monitor"),
    "adblock_block_mode": ("null", "sinkhole"),
}


def iter_setting_groups() -> list[tuple[str, list[str]]]:
    """Return ordered setting groups, including any newly added keys."""
    assigned = {key for keys in SETTING_GROUPS.values() for key in keys}
    groups = [(name, [key for key in keys if key in DEFAULTS]) for name, keys in SETTING_GROUPS.items()]
    other = [key for key in DEFAULTS if key not in assigned]
    if other:
        groups.append(("Other", other))
    return [(name, keys) for name, keys in groups if keys]


# ──────────────────────────── Validation ─────────────────────────
# Rules: key → (expected_type, validator_fn, error_description)
# Keys without a rule accept any value of the correct default type.

_PORT_RANGE   = (lambda v: 1 <= v <= 65535, "must be 1–65535")
_POSITIVE     = (lambda v: v > 0,           "must be > 0")
_ENGINE_CHOICES = [
    "auto", "sni", "xray", "gdpi", "psiphon", "warp", "tun", "tor", "mhrv",
    "ikev2", "wireguard", "openvpn", "softether", "appsscript", "hysteria2",
    "tuic", "awg", "legend",
]


def _valid_mac_prefix(value: str) -> bool:
    if not re.fullmatch(r"[0-9A-Fa-f]{2}", value.strip()):
        return False
    return (int(value.strip(), 16) & 0x03) == 0x02


def _valid_private_mac_or_empty(value: str) -> bool:
    compact = value.replace(":", "").replace("-", "").strip()
    if not compact:
        return True
    if not re.fullmatch(r"[0-9A-Fa-f]{12}", compact):
        return False
    return (int(compact[:2], 16) & 0x03) == 0x02


_VALIDATORS: dict[str, tuple] = {
    "gdpi_backend":      (str,   lambda v: v in ("legacy", "native"), "must be: legacy / native"),
    "gdpi_always_test_all": (bool,  lambda v: True,            "must be true or false"),
    "mhrv_direct":        (bool,  lambda v: True,              "must be true or false"),
    "sni_always_test_all_ips": (bool, lambda v: True,          "must be true or false"),
    "sni_custom_ips":     (list,  lambda v: True,              "must be a list of strings"),
    "sni_listen_port":    (int,   *_PORT_RANGE),
    "xray_socks_port":    (int,   *_PORT_RANGE),
    "xray_http_port":     (int,   *_PORT_RANGE),
    "psiphon_http_port":  (int,   *_PORT_RANGE),
    "psiphon_socks_port": (int,   *_PORT_RANGE),
    "sni_connect_port":   (int,   *_PORT_RANGE),
    "proxy_port":         (int,   *_PORT_RANGE),
    "softether_port":     (int,   *_PORT_RANGE),
    "neighbor_proxy_port":(int,   *_PORT_RANGE),
    "gas_proxy_port":     (int,   *_PORT_RANGE),
    "xray_fragment":      (str,   lambda v: v == "" or v.count(",") == 1, "must be empty or 'range,range' (e.g. 10-50,10-50)"),
    "xray_split_tunnel":  (bool,  lambda v: True,            "must be true or false"),
    "xray_doh_dns":       (bool,  lambda v: True,            "must be true or false"),
    "scan_concurrency":   (int,   lambda v: 1 <= v <= 500,   "must be 1–500"),
    "scan_timeout":       (float, lambda v: 0.1 <= v <= 30,  "must be 0.1–30.0"),
    "scan_ip_count":      (int,   lambda v: 1 <= v <= 5000,  "must be 1–5000"),
    "retry_interval":     (int,   lambda v: 5 <= v <= 3600,  "must be 5–3600"),
    "max_retries":        (int,   lambda v: 1 <= v <= 20,    "must be 1–20"),
    "reconnect_initial_delay": (int, lambda v: 1 <= v <= 600, "must be 1–600"),
    "reconnect_max_delay":     (int, lambda v: 1 <= v <= 3600, "must be 1–3600"),
    "daemon_log_lines":   (int,   lambda v: 10 <= v <= 10000,"must be 10–10000"),
    "xray_log_level":     (str,   lambda v: v in ("debug","info","warning","error","none"),
                           "must be: debug / info / warning / error / none"),
    "xray_fingerprint":   (str,   lambda v: v in ("chrome","firefox","safari","random"),
                           "must be: chrome / firefox / safari / random"),
    "security_mode":      (str,   lambda v: v in ("speed","private","legend"),
                           "must be: speed / private / legend"),
    "ikev2_tunnel_type":  (str,   lambda v: v in ("IKEv2","L2tp","Sstp","Pptp"),
                           "must be: IKEv2 / L2tp / Sstp / Pptp"),
    "color_theme":        (str,   lambda v: v in ("red","blue","green","purple"),
                           "must be: red / blue / green / purple"),
    "terminal_theme":     (str,   lambda v: v in ("dark", "light"),
                           "must be: dark / light"),
    "selected_engine":    (str,   lambda v: v in _ENGINE_CHOICES, "must be: auto or one of " + ", ".join(_ENGINE_CHOICES)),
    "engine_order":       (list,  lambda v: len(v) > 0 and all(e in _ENGINE_CHOICES for e in v),
                            "must be a non-empty list of valid engines: " + ", ".join(_ENGINE_CHOICES)),
    "capture_max_packets": (int,  lambda v: 100 <= v <= 100000, "must be 100–100000"),
    "download_speed_limit_kbps": (int, lambda v: v >= 0, "must be 0 (unlimited) or > 0"),
    "download_max_parallel": (int, lambda v: 1 <= v <= 32, "must be 1–32"),
    "download_auto_resume": (bool, lambda v: True, "must be true or false"),
    "qos_enabled": (bool, lambda v: True, "must be true or false"),
    "qos_enforcement_mode": (str, lambda v: v in ("off", "monitor"), "must be: off / monitor"),
    "qos_default_priority": (int, lambda v: 0 <= v <= 100, "must be 0–100"),
    "qos_alert_threshold_pct": (int, lambda v: 100 <= v <= 500, "must be 100–500"),
    "qos_rate_limit_precision_ms": (int, lambda v: 10 <= v <= 1000, "must be 10–1000"),
    "mac_preferred_adapter": (str, lambda v: True, "must be an adapter name or empty"),
    "mac_randomization_prefix": (str, lambda v: _valid_mac_prefix(v), "must be a locally administered unicast octet, such as 02"),
    "mac_custom_private_address": (str, lambda v: _valid_private_mac_or_empty(v), "must be empty or a locally administered unicast MAC address"),
}

# ──────────────────────────── Env overrides ───────────────────────
# Any setting can be overridden via environment:
#   BLACKOUT_XRay_HTTP_PORT=9999  →  xray_http_port = 9999
_ENV_PREFIX = "BLACKOUT_"
_QOS_ENFORCEMENT_MODES = frozenset({"off", "monitor"})


def _normalize_qos_enforcement_mode(value) -> str:
    return value if value in _QOS_ENFORCEMENT_MODES else "monitor"


def _normalize_qos_settings(settings: dict) -> dict:
    settings["qos_enforcement_mode"] = _normalize_qos_enforcement_mode(
        settings.get("qos_enforcement_mode")
    )
    return settings


def _apply_env_overrides(settings: dict) -> dict:
    """Apply BLACKOUT_<KEY> environment variables on top of file settings."""
    for key, default_val in DEFAULTS.items():
        env_key = _ENV_PREFIX + key.upper()
        env_raw = os.environ.get(env_key)
        if env_raw is None:
            continue
        try:
            if isinstance(default_val, bool):
                settings[key] = env_raw.lower() in ("1", "true", "yes", "on")
            elif isinstance(default_val, int):
                settings[key] = int(env_raw)
            elif isinstance(default_val, float):
                settings[key] = float(env_raw)
            elif isinstance(default_val, list):
                settings[key] = [v.strip() for v in env_raw.split(",")]
            else:
                settings[key] = env_raw
        except (ValueError, TypeError):
            pass   # Bad env value → ignore silently, keep file value
    return _normalize_qos_settings(settings)


# ──────────────────────────── Public API ─────────────────────────

def _normalize_saved_settings(saved: dict) -> dict:
    if not isinstance(saved, dict):
        raise ValueError("settings data must be an object")
    schema_version = saved.get(_SETTINGS_SCHEMA_KEY, 0)
    if not isinstance(schema_version, int) or schema_version < 0 or schema_version > SETTINGS_SCHEMA_VERSION:
        raise ValueError(f"unsupported settings schema version: {schema_version!r}")
    normalized = {
        key: value
        for key, value in saved.items()
        if key != _SETTINGS_SCHEMA_KEY
    }
    return normalized


def _load_plain_settings() -> dict:
    if not SETTINGS_FILE.exists():
        return dict(DEFAULTS)
    try:
        saved = _normalize_saved_settings(json.loads(SETTINGS_FILE.read_text()))
        merged = dict(DEFAULTS)
        merged.update(saved)
        return _normalize_qos_settings(merged)
    except Exception as exc:
        _log.warning("Settings file '%s' is corrupted (%s). Falling back to defaults.", SETTINGS_FILE, exc)
        return dict(DEFAULTS)


def load() -> dict:
    """Load settings and overlay vault-backed credentials only in memory (thread-safe)."""
    with _settings_lock:
        APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
        merged = _load_plain_settings()
        if merged.get("secrets_vault_enabled", False):
            try:
                merged.update(vault.read_secrets())
            except vault.VaultError as exc:
                _log.warning("Encrypted settings secrets are unavailable: %s", exc)
        return _apply_env_overrides(merged)


def _write_plain_settings(settings: dict) -> None:
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
    stored = dict(settings)
    stored[_SETTINGS_SCHEMA_KEY] = SETTINGS_SCHEMA_VERSION
    data = json.dumps(stored, indent=2).encode()
    fd, tmp = tempfile.mkstemp(dir=APP_DATA_DIR, prefix=".tmp_settings_")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.replace(tmp, SETTINGS_FILE)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def save(settings: dict):
    """Persist settings atomically while preserving activated secret vault storage (thread-safe)."""
    with _settings_lock:
        stored = _normalize_qos_settings(dict(settings))
        if stored.get("secrets_vault_enabled", False):
            vault.read_secrets()
            vault.write_secrets(stored)
            for key in SENSITIVE_KEYS:
                stored.pop(key, None)
        _write_plain_settings(stored)


def vault_health() -> tuple[bool, str]:
    """Return whether activated encrypted settings storage can be read locally."""
    status = vault.settings_vault_status(_load_plain_settings().get("secrets_vault_enabled", False))
    return bool(status["healthy"]), str(status["detail"])


def activate_secret_vault() -> None:
    """Encrypt current sensitive settings before removing them from settings.json."""
    current = load()
    vault.write_secrets(current)
    stored = _load_plain_settings()
    stored["secrets_vault_enabled"] = True
    for key in SENSITIVE_KEYS:
        stored.pop(key, None)
    _write_plain_settings(stored)


def deactivate_secret_vault() -> None:
    """Explicitly restore encrypted credentials to plaintext settings.json."""
    secrets = vault.read_secrets()
    current = _load_plain_settings()
    current.update(secrets)
    current["secrets_vault_enabled"] = False
    _write_plain_settings(current)
    vault.ENC_SECRETS_FILE.unlink(missing_ok=True)


def get(key: str, default=None):
    """Get a single setting value."""
    val = load().get(key, DEFAULTS.get(key))
    if val is None:
        return default
    return val


def coerce_value(key: str, value):
    """Convert CLI and MCP input to the type declared by the setting default."""
    if key not in DEFAULTS:
        raise ValueError(f"Unknown setting: '{key}'. Run 'blackout settings list' to see all.")

    default = DEFAULTS[key]
    if isinstance(default, bool):
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in ("1", "true", "yes", "on"):
                return True
            if normalized in ("0", "false", "no", "off"):
                return False
        raise ValueError(f"Invalid value for '{key}': must be true or false")

    if isinstance(default, int):
        if isinstance(value, bool):
            raise ValueError(f"Invalid value for '{key}': must be an int")
        try:
            return int(value)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"Invalid value for '{key}': must be an int") from exc

    if isinstance(default, float):
        try:
            return float(value)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"Invalid value for '{key}': must be a float") from exc

    if isinstance(default, list):
        if isinstance(value, list):
            return value
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        raise ValueError(f"Invalid value for '{key}': must be a comma-separated list")

    if isinstance(default, str):
        if isinstance(value, str):
            return value
        raise ValueError(f"Invalid value for '{key}': must be a string")

    return value


def validate(key: str, value) -> tuple[bool, str]:
    """
    Validate a single setting value.
    Returns (True, "") on success, (False, reason) on failure.
    """
    if key not in DEFAULTS:
        return False, f"Unknown setting '{key}'"
    try:
        typed = coerce_value(key, value)
    except ValueError as exc:
        return False, str(exc).split(": ", 1)[-1]

    rule = _VALIDATORS.get(key)
    if rule is None:
        return True, ""
    _expected_type, check_fn, error_msg = rule
    if not check_fn(typed):
        return False, error_msg
    return True, ""


def validate_all(settings: dict | None = None) -> list[tuple[str, str]]:
    """
    Validate all current settings.
    Returns a list of (key, error_reason) for every invalid entry.
    Empty list means everything is fine.
    """
    s = settings or load()
    return [
        (key, msg)
        for key, value in s.items()
        if key in DEFAULTS
        for ok, msg in [validate(key, value)]
        if not ok
    ]


def set_value(key: str, value):
    """Update one setting with validation, then save."""
    typed_value = coerce_value(key, value)
    if key == "kill_switch" and typed_value and not sys.platform.startswith("linux"):
        raise ValueError("The kill switch is available only on Linux")
    ok, msg = validate(key, typed_value)
    if not ok:
        raise ValueError(f"Invalid value for '{key}': {msg}")
    settings = load()
    settings[key] = typed_value
    save(settings)


def validate_updates(values: dict) -> dict:
    """Coerce and validate a complete settings update before persistence."""
    if not isinstance(values, dict):
        raise ValueError("Settings update must be a dict")
    normalized = {}
    for key, value in values.items():
        if key not in DEFAULTS:
            raise ValueError(f"Unknown setting: {key}")
        typed = coerce_value(key, value)
        if key == "kill_switch" and typed and not sys.platform.startswith("linux"):
            raise ValueError("The kill switch is available only on Linux")
        ok, reason = validate(key, typed)
        if not ok:
            raise ValueError(f"Invalid setting {key}: {reason}")
        normalized[key] = typed
    return normalized


def reset():
    """Reset all settings to factory defaults."""
    save(dict(DEFAULTS))


def describe(key: str) -> str:
    """Human-readable description of a setting."""
    descriptions = {
        "sni_listen_port":    "Local port the SNI spoofer listens on",
        "xray_socks_port":    "XRay SOCKS5 proxy port",
        "xray_http_port":     "XRay HTTP proxy port (auto-set as system proxy)",
        "sni_connect_ip":     "Cloudflare IP the SNI spoofer connects to",
        "sni_connect_port":   "Port to connect on Cloudflare side (443)",
        "sni_fake_sni":       "Fake SNI domain shown to DPI (e.g. www.hcaptcha.com)",
        "xray_log_level":     "XRay log verbosity: debug/info/warning/error/none",
        "xray_fingerprint":   "TLS fingerprint to mimic: chrome/firefox/safari/random",
        "gdpi_backend":      "GoodbyeDPI backend: legacy (stable goodbyedpi.exe) / native (experimental Go/WinDivert)",
        "gdpi_flags":         "GoodbyeDPI flags (legacy backend only: auto=tries all modesets, or specify e.g. -1 -2 -5)",
        "psiphon_country":    "Psiphon exit country code (DE/US/CA/NL…)",
        "auto_set_proxy":     "Auto-configure Windows system proxy on start/stop",
        "proxy_host":         "System proxy host (usually 127.0.0.1)",
        "proxy_port":         "System proxy port (should match xray_http_port)",
        "scan_concurrency":   "Parallel workers for IP scanning (higher=faster)",
        "scan_timeout":       "Seconds to wait per IP during scan",
        "scan_ip_count":      "Number of Cloudflare IPs to generate per scan",
        "engine_order":       "Engine priority order for emergency mode",
        "capture_default_iface": "Default interface for `tools capture` when none is given",
        "capture_max_packets":   "In-memory packet buffer cap for `tools capture` (feeds the live view + summary)",
        "retry_interval":     "Seconds between healthy daemon connection checks",
        "max_retries":        "Maximum automatic reconnect attempts before the daemon exits",
        "reconnect_initial_delay": "First automatic reconnect delay in seconds",
        "reconnect_max_delay": "Maximum automatic reconnect delay in seconds",
        "daemon_log_lines":   "Max log lines kept in the daemon log file",
        "show_banner":        "Show ASCII art banner on startup",
        "show_disclaimer":    "Show the legal disclaimer panel under the banner",
        "show_first_run":     "Show the First Run welcome panel on a fresh install",
        "color_theme":        "Terminal accent color: red/blue/green/purple",
        "terminal_theme":     "Blackout Kit terminal palette: dark/light (does not change your terminal app)",
        "security_mode":      "Active security mode: speed / private / legend",
        "kill_switch":        "Enable Linux endpoint-scoped firewall protection; unavailable on Windows",
        "secrets_vault_enabled": "Keep supported IKEv2/L2TP and SoftEther secrets encrypted at rest",
        "ikev2_server":       "IKEv2/L2TP VPN server address",
        "ikev2_username":     "IKEv2/L2TP VPN username",
        "ikev2_password":     "IKEv2/L2TP VPN password",
        "ikev2_psk":          "L2TP pre-shared key (L2TP only)",
        "ikev2_tunnel_type":  "VPN tunnel protocol: IKEv2 / L2tp / Sstp / Pptp",
        "wg_config_file":     "Full path to your WireGuard .conf file",
        "wg_interface":       "WireGuard interface name (default: wg0)",
        "openvpn_config":     "Full path to your OpenVPN .ovpn config file",
        "softether_host":     "SoftEther VPN server hostname or IP",
        "softether_port":     "SoftEther server port (443 for SSL-VPN mode)",
        "softether_hub":      "SoftEther Virtual Hub name (e.g. VPN)",
        "softether_username": "SoftEther account username",
        "softether_password": "SoftEther account password",
        "neighbor_proxy_port":"Proxy port to share with nearby LAN devices",
        "neighbor_bind_lan":  "Bind proxy to 0.0.0.0 so LAN devices can reach it",
        "lan_neighbor_cache_ttl_minutes": "How long (in minutes) to trust cached LAN neighbor IPs before requiring fresh discovery",
        "lan_neighbor_cache_max_size": "Maximum number of neighbors to keep in the local cache file",
        "gas_proxy_port":     "Local port for Google Apps Script HTTP relay proxy",
        "country":            "Country profile code (IR/RU/US/GB/CN/IQ/EU). Empty = auto-detect from ISP.",
        "xray_fragment":      "XRay TLS record fragment: empty disables it, otherwise range,range (e.g. 10-50,10-50)",
        "sni_arvancloud_sni": "Fake SNI using Iran domestic CDN (arvancloud.ir) — unblockable inside Iran",
        "xray_split_tunnel":  "Bypass proxy for local LAN and domestic (.ir) traffic",
        "xray_doh_dns":       "Encrypt DNS queries via Cloudflare/Google DoH over XRay",
        "selected_engine":    "Preferred bypass engine: auto / sni / gdpi / psiphon / warp / legend / ...",
        "config_rotation":    "When enabled, the daemon rotates to the next saved config on reconnect failure (blocked IP)",
        "awg_config_file":    "Full path to your AmneziaWG .conf file",
        "mac_preferred_adapter": "Optional active physical Wi-Fi adapter for explicit MAC privacy commands",
        "mac_randomization_prefix": "Locally administered unicast first octet for fresh private Wi-Fi MACs (default: 02)",
        "mac_custom_private_address": "Optional locally administered unicast MAC used only by explicit tools mac randomize",
    }
    return descriptions.get(key, "No description available.")


def get_engine_proxy_details(engine_name: str, settings: dict | None = None) -> tuple[str, int] | None:
    """
    Return (host, port) for the proxy required by the engine, or None if network-level.
    This prevents setting dead system proxies for network-level VPNs or using wrong ports.
    """
    s = settings or load()
    host = s.get("proxy_host", "127.0.0.1")
    if engine_name in ("sni", "xray", "legend"):
        return host, s.get("xray_http_port", 10809)
    elif engine_name == "psiphon":
        return "socks=127.0.0.1", s.get("psiphon_socks_port", 1081)
    elif engine_name == "appsscript":
        return host, s.get("gas_proxy_port", 8087)
    elif engine_name == "mhrv":
        return host, 8085
    elif engine_name == "tor":
        return "socks=127.0.0.1", 9050
    elif engine_name == "warp":
        return "socks=127.0.0.1", 1080
    elif engine_name in ("hysteria2", "tuic"):
        return "socks=127.0.0.1", s.get("xray_socks_port", 10808)
    return None

