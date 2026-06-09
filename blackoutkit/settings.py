"""
Blackout Kit - User settings and customization.

Features:
  - Type + bounds validation on every set_value() call
  - Environment variable overrides: BLACKOUT_<KEY>=value
  - validate_all() for startup sanity check
"""
import json
import os
import tempfile
from pathlib import Path

APP_DATA_DIR  = Path.home() / ".blackout-kit"
SETTINGS_FILE = APP_DATA_DIR / "settings.json"

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
    "sni_fake_sni":         "www.hcaptcha.com",

    # XRay Engine
    "xray_log_level":       "warning",   # debug / info / warning / error / none
    "xray_mux_enabled":     False,
    "xray_fingerprint":     "chrome",    # chrome / firefox / safari / random

    # GoodbyeDPI
    "gdpi_flags":           "-9",        # -9 = max bypass, -5 = balanced

    # Psiphon
    "psiphon_country":      "DE",        # Country code for exit node

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
    "max_retries":          3,           # Retries per engine before switching

    # Daemon
    "daemon_log_lines":     200,         # Max lines to keep in daemon log

    # UI
    "show_banner":          True,
    "show_disclaimer":      True,        # Show the legal disclaimer under the banner
    "show_first_run":       False,       # Show the "First Run" welcome panel (auto-shown on true first launch)
    "color_theme":          "red",       # red / blue / green / purple

    # Security modes
    "security_mode":        "speed",     # speed / private / legend
    "kill_switch":          False,       # Block ALL traffic if proxy drops (Windows only)

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

    # Google Apps Script relay
    "gas_proxy_port":       8087,

    # Country profile
    "country":              "",  # ISO code (IR/US/GB/CN/IQ). Empty = auto-detect from ISP.

    # Iran 2026 Evasion
    "xray_fragment":        "10-50,10-50",  # TLS record fragment mode (range,range)
}


# ──────────────────────────── Validation ─────────────────────────
# Rules: key → (expected_type, validator_fn, error_description)
# Keys without a rule accept any value of the correct default type.

_PORT_RANGE   = (lambda v: 1 <= v <= 65535, "must be 1–65535")
_POSITIVE     = (lambda v: v > 0,           "must be > 0")

_VALIDATORS: dict[str, tuple] = {
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
    "xray_fragment":      (str,   lambda v: v.count(",") == 1, "must be 'range,range' (e.g. 10-50,10-50)"),
    "scan_concurrency":   (int,   lambda v: 1 <= v <= 500,   "must be 1–500"),
    "scan_timeout":       (float, lambda v: 0.1 <= v <= 30,  "must be 0.1–30.0"),
    "scan_ip_count":      (int,   lambda v: 1 <= v <= 5000,  "must be 1–5000"),
    "retry_interval":     (int,   lambda v: 5 <= v <= 3600,  "must be 5–3600"),
    "max_retries":        (int,   lambda v: 1 <= v <= 20,    "must be 1–20"),
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
}

# ──────────────────────────── Env overrides ───────────────────────
# Any setting can be overridden via environment:
#   BLACKOUT_XRay_HTTP_PORT=9999  →  xray_http_port = 9999
_ENV_PREFIX = "BLACKOUT_"


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
    return settings


# ──────────────────────────── Public API ─────────────────────────

def load() -> dict:
    """Load settings with defaults merged and env overrides applied."""
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not SETTINGS_FILE.exists():
        return _apply_env_overrides(dict(DEFAULTS))
    try:
        saved  = json.loads(SETTINGS_FILE.read_text())
        merged = dict(DEFAULTS)
        merged.update(saved)
        return _apply_env_overrides(merged)
    except Exception:
        return _apply_env_overrides(dict(DEFAULTS))


def save(settings: dict):
    """Persist settings to disk using an atomic write (temp → rename)."""
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
    data = json.dumps(settings, indent=2).encode()
    fd, tmp = tempfile.mkstemp(dir=APP_DATA_DIR, prefix=".tmp_settings_")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, SETTINGS_FILE)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def get(key: str):
    """Get a single setting value."""
    return load().get(key, DEFAULTS.get(key))


def validate(key: str, value) -> tuple[bool, str]:
    """
    Validate a single setting value.
    Returns (True, "") on success, (False, reason) on failure.
    """
    if key not in DEFAULTS:
        return False, f"Unknown setting '{key}'"
    rule = _VALIDATORS.get(key)
    if rule is None:
        return True, ""   # No specific rule — accept any value
    expected_type, check_fn, error_msg = rule
    try:
        typed = expected_type(value)
    except (ValueError, TypeError):
        return False, f"must be a {expected_type.__name__}"
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
    if key not in DEFAULTS:
        raise ValueError(f"Unknown setting: '{key}'. Run 'blackout settings list' to see all.")
    ok, msg = validate(key, value)
    if not ok:
        raise ValueError(f"Invalid value for '{key}': {msg}")
    settings = load()
    settings[key] = value
    save(settings)


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
        "gdpi_flags":         "GoodbyeDPI command-line flags (-9=max, -5=balanced)",
        "psiphon_country":    "Psiphon exit country code (DE/US/CA/NL…)",
        "auto_set_proxy":     "Auto-configure Windows system proxy on start/stop",
        "proxy_host":         "System proxy host (usually 127.0.0.1)",
        "proxy_port":         "System proxy port (should match xray_http_port)",
        "scan_concurrency":   "Parallel workers for IP scanning (higher=faster)",
        "scan_timeout":       "Seconds to wait per IP during scan",
        "scan_ip_count":      "Number of Cloudflare IPs to generate per scan",
        "engine_order":       "Engine priority order for emergency mode",
        "retry_interval":     "Seconds between connection checks in daemon mode",
        "max_retries":        "Retries per engine before switching to next",
        "daemon_log_lines":   "Max log lines kept in the daemon log file",
        "show_banner":        "Show ASCII art banner on startup",
        "show_disclaimer":    "Show the legal disclaimer panel under the banner",
        "show_first_run":     "Show the First Run welcome panel on a fresh install",
        "color_theme":        "Terminal color theme: red/blue/green/purple",
        "security_mode":      "Active security mode: speed / private / legend",
        "kill_switch":        "Block all internet if proxy drops (Windows Firewall)",
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
        "gas_proxy_port":     "Local port for Google Apps Script HTTP relay proxy",
        "country":            "Country profile code (IR/US/GB/CN/IQ). Empty = auto-detect from ISP.",
        "xray_fragment":      "XRay TLS record fragment: range,range (TIC 2026 evasion)",
    }
    return descriptions.get(key, "No description available.")
