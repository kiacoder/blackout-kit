"""
Blackout Kit - Split Tunneling Manager.

Allows users and AI agents to configure Split Tunneling rules:
  - Bypassing specific IPs or domains from the system proxy (Direct routing)
  - Intercepting registry ProxyOverride settings
"""
import json
import sys
from pathlib import Path

APP_DATA_DIR = Path.home() / ".blackout-kit"
SPLIT_CONFIG_FILE = APP_DATA_DIR / "split_tunnel.json"

DEFAULT_BYPASS_RULES = [
    "localhost",
    "127.*",
    "10.*",
    "172.16.*",
    "192.168.*",
    "<local>"
]

def _ensure_dir():
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)

def load_split_rules() -> list[str]:
    """Load split tunnel direct bypass rules."""
    _ensure_dir()
    if not SPLIT_CONFIG_FILE.exists():
        save_split_rules(DEFAULT_BYPASS_RULES)
        return list(DEFAULT_BYPASS_RULES)
    try:
        data = json.loads(SPLIT_CONFIG_FILE.read_text(encoding="utf-8"))
        return data.get("direct_bypass", DEFAULT_BYPASS_RULES)
    except Exception:
        return list(DEFAULT_BYPASS_RULES)

def save_split_rules(rules: list[str]) -> bool:
    """Save split tunnel direct bypass rules."""
    _ensure_dir()
    try:
        # Unique preserving order
        unique_rules = []
        for r in rules:
            r = r.strip()
            if r and r not in unique_rules:
                unique_rules.append(r)
        SPLIT_CONFIG_FILE.write_text(json.dumps({"direct_bypass": unique_rules}, indent=2), encoding="utf-8")
        apply_split_tunnel_to_system()
        return True
    except Exception:
        return False

def add_direct_route(target: str) -> bool:
    """Add an IP, CIDR, or domain to the direct bypass list (bypasses proxy)."""
    rules = load_split_rules()
    target = target.strip()
    if target not in rules:
        rules.append(target)
        return save_split_rules(rules)
    return True

def remove_direct_route(target: str) -> bool:
    """Remove an IP, CIDR, or domain from the direct bypass list."""
    rules = load_split_rules()
    target = target.strip()
    if target in rules:
        rules.remove(target)
        return save_split_rules(rules)
    return False

def get_proxy_override_string() -> str:
    """Format the direct bypass list as a Windows Registry ProxyOverride string."""
    rules = load_split_rules()
    return ";".join(rules)

def apply_split_tunnel_to_system() -> bool:
    """Apply the split tunnel direct bypass rules to Windows Registry Internet Settings."""
    if sys.platform != "win32":
        return True
    try:
        import winreg
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
        winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, get_proxy_override_string())
        winreg.CloseKey(key)
        
        # Notify WinInet
        try:
            import ctypes
            wininet = ctypes.windll.Wininet
            wininet.InternetSetOptionW(0, 95, 0, 0) # INTERNET_OPTION_SETTINGS_CHANGED
            wininet.InternetSetOptionW(0, 37, 0, 0) # INTERNET_OPTION_REFRESH
        except Exception:
            pass
        return True
    except Exception:
        return False
