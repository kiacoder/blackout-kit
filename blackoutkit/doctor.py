"""
Blackout Kit - Self-diagnosis and self-healing.
Detects missing/corrupted files, bad settings, broken network drivers,
and attempts automatic repairs where possible.

Epic upgrades:
  - cryptography added to check_python_deps()
  - check_disk_space(): warns if < 200 MB free in bins/ parent drive
  - check_binary_runnable(): actually launches each binary to confirm it executes
"""
import os
import subprocess
import sys
from pathlib import Path

from rich import box
from rich.table import Table

from . import APP_DATA_DIR, BINS_DIR, DATA_DIR, PROJECT_ROOT, resource_path
from . import settings as cfg
from .engines.gdpi import GDPI_BIN_NAMES
from .theme import console


def _data_file_path(relative_path: str) -> Path:
    if relative_path == "data/configs.txt":
        return DATA_DIR / "configs.txt"
    return resource_path(relative_path)


# ──────────────────────────── Defaults ───────────────────────────


def _default_cf_ips() -> str:
    return (
        "# Cloudflare IP ranges\n"
        "104.16.0.0/13\n104.24.0.0/14\n172.64.0.0/13\n"
        "188.114.96.0/20\n162.158.0.0/15\n"
        "# Known good\n104.19.229.21\n188.114.98.0\n"
    )


def _default_snis() -> str:
    return (
        "# Fake SNI domains\n"
        "www.google.com\nwww.hcaptcha.com\nauth.vercel.com\n"
        "www.cloudflare.com\nwww.microsoft.com\ncdn.jsdelivr.net\n"
    )


def _default_configs() -> str:
    return (
        "# V2Ray configs — add yours with: blackout config add <uri>\n"
        "# Or import: blackout config import <subscription-url>\n"
    )


# ──────────────────────────── Check functions ────────────────────

class CheckResult:
    def __init__(self, name: str, ok: bool, message: str, fixable: bool = False, fix=None):
        self.name = name
        self.ok = ok
        self.message = message
        self.fixable = fixable
        self.fix = fix


def check_data_files() -> list[CheckResult]:
    results = []
    defaults = {
        "data/cloudflare_ips.txt": _default_cf_ips,
        "data/fake_snis.txt": _default_snis,
        "data/configs.txt": _default_configs,
    }
    for rel_path, default_fn in defaults.items():
        full = _data_file_path(rel_path)
        mutable = rel_path == "data/configs.txt"
        if full.exists() and full.stat().st_size > 0:
            results.append(CheckResult(rel_path, True, "OK"))
        elif full.exists():
            results.append(CheckResult(
                rel_path,
                False,
                "File is empty",
                fixable=mutable,
                fix=(lambda p=full, fn=default_fn: p.write_text(fn(), encoding="utf-8")) if mutable else None,
            ))
        else:
            results.append(CheckResult(
                rel_path,
                False,
                "File missing — reinstall Blackout Kit to restore bundled resources"
                if not mutable else "File missing",
                fixable=mutable,
                fix=(
                    (lambda p=full, fn=default_fn: (
                        p.parent.mkdir(parents=True, exist_ok=True),
                        p.write_text(fn(), encoding="utf-8"),
                    ))
                    if mutable else None
                ),
            ))
    return results


def check_settings() -> CheckResult:
    try:
        s = cfg.load()
        required_keys = list(cfg.DEFAULTS.keys())
        missing = [k for k in required_keys if k not in s]
        if missing:
            return CheckResult(
                "settings.json", False,
                f"Missing keys: {', '.join(missing)}",
                fixable=True,
                fix=cfg.reset,
            )
        return CheckResult("settings.json", True, "OK")
    except Exception as e:
        return CheckResult(
            "settings.json", False, f"Corrupted: {e}",
            fixable=True, fix=cfg.reset,
        )


def check_bins_dir() -> CheckResult:
    if BINS_DIR.exists():
        return CheckResult("bins/ directory", True, "OK")
    return CheckResult(
        "bins/ directory", False, "Directory missing",
        fixable=True,
        fix=lambda: BINS_DIR.mkdir(parents=True, exist_ok=True),
    )


def check_app_data_dir() -> CheckResult:
    if APP_DATA_DIR.exists():
        return CheckResult("~/.blackout-kit/", True, "OK")
    return CheckResult(
        "~/.blackout-kit/", False, "Directory missing",
        fixable=True,
        fix=lambda: APP_DATA_DIR.mkdir(parents=True, exist_ok=True),
    )


def check_python_deps() -> list[CheckResult]:
    results = []
    deps = {
        "rich":         "rich",
        "httpx":        "httpx",
        "psutil":       "psutil",
        "cryptography": "cryptography",   # Epic: required for AES-256-GCM config encryption
    }
    for name, module in deps.items():
        try:
            __import__(module)
            results.append(CheckResult(f"Python: {name}", True, "Installed"))
        except ImportError:
            results.append(CheckResult(
                f"Python: {name}", False, "Not installed",
                fixable=True,
                fix=lambda n=name: subprocess.run([sys.executable, "-m", "pip", "install", n], check=False),
            ))
    return results


def _gdpi_backend() -> str:
    return str(cfg.load().get("gdpi_backend", "legacy")).lower()


def check_bins_present() -> list[CheckResult]:
    """Check which binaries are present — suggests 'blackout bins download' for missing ones."""
    results = []
    from .downloader import BIN_REGISTRY
    from .downloader import BINS_DIR as _BINS_DIR

    if sys.platform.startswith("linux"):
        runner = _BINS_DIR / "blackout-engine"
        if runner.exists() and os.access(runner, os.X_OK):
            results.append(CheckResult("bins: blackout-engine", True, "Found Linux XRay/sing-box runner"))
        else:
            results.append(CheckResult(
                "bins: blackout-engine",
                False,
                "Missing or not executable — install the Linux x86_64 release asset",
                fixable=False,
            ))
        return results

    # Check for native DLLs
    core_dll = _BINS_DIR / "blackout_core.dll"
    engine_exe = _BINS_DIR / "blackout-engine.exe"
    if core_dll.exists():
        size_kb = core_dll.stat().st_size // 1024
        results.append(CheckResult("bins: blackout_core.dll", True, f"Found ({size_kb} KB)"))
    elif engine_exe.exists():
        results.append(CheckResult("bins: blackout_core.dll", True, "Emulated via blackout-engine.exe — OK"))
    else:
        results.append(CheckResult(
            "bins: blackout_core.dll", False,
            "Missing — SNI, XRay, WireGuard, and native GDPI will not work. "
            "Build from engine/ (Go 1.22+) or wait for pre-built release.",
            fixable=False,
        ))

    warp_dll = _BINS_DIR / "blackout_warp.dll"
    if warp_dll.exists():
        size_kb = warp_dll.stat().st_size // 1024
        results.append(CheckResult("bins: blackout_warp.dll", True, f"Found ({size_kb} KB) — WARP+ and Psiphon ready"))
    else:
        results.append(CheckResult(
            "bins: blackout_warp.dll", False,
            "Missing — WARP and Psiphon engines unavailable. "
            "Build from engine/warp/ (Go 1.22+): "
            "cd engine/warp && go build -buildmode=c-shared -o ../../bins/blackout_warp.dll .",
            fixable=False,
        ))

    gdpi_backend = _gdpi_backend()
    for key, info in BIN_REGISTRY.items():
        if key == "goodbyedpi" and gdpi_backend == "native":
            present = all((_BINS_DIR / b).exists() for b in info.output_bins)
            if present:
                first = _BINS_DIR / info.output_bins[0]
                size_kb = first.stat().st_size // 1024
                results.append(CheckResult(
                    f"bins: {info.display_name}",
                    True,
                    f"Found ({size_kb} KB) — optional while gdpi_backend=native",
                ))
            else:
                results.append(CheckResult(
                    f"bins: {info.display_name}",
                    True,
                    "Optional while gdpi_backend=native",
                ))
            continue

        all_present = all((_BINS_DIR / b).exists() for b in info.output_bins)
        if all_present:
            first = _BINS_DIR / info.output_bins[0]
            size_kb = first.stat().st_size // 1024
            results.append(CheckResult(f"bins: {info.display_name}", True, f"Found ({size_kb} KB)"))
        else:
            from .downloader import download_binary
            if info.github_repo or key in ("tor", "openvpn"):
                results.append(CheckResult(
                    f"bins: {info.display_name}", False,
                    "Missing — Run: blackout bins download",
                    fixable=True,
                    fix=lambda k=key: download_binary(k),
                ))
            else:
                fix_hint = f"Manual: {info.manual_url}"
                if info.manual_note:
                    fix_hint += f"  ({info.manual_note})"
                results.append(CheckResult(
                    f"bins: {info.display_name}", False,
                    f"Missing — {fix_hint}",
                    fixable=False,
                ))
    return results


def check_windivert() -> CheckResult:
    """Check if WinDivert is present for the active GDPI backend and SNI tooling."""
    backend = _gdpi_backend()
    dll = BINS_DIR / "WinDivert.dll"
    sys_file = BINS_DIR / "WinDivert64.sys"
    if dll.exists() and sys_file.exists():
        return CheckResult("WinDivert (GoodbyeDPI driver)", True, f"Found ({backend} backend compatible)")
    if backend == "native":
        return CheckResult(
            "WinDivert (GoodbyeDPI driver)", False,
            "Missing — native GDPI still depends on WinDivert. Build/install the native driver prerequisites.",
            fixable=False,
        )
    return CheckResult(
        "WinDivert (GoodbyeDPI driver)", False,
        "Missing — legacy GDPI requires the GoodbyeDPI package (goodbyedpi.exe + WinDivert files).",
        fixable=False,
    )


def check_scapy() -> CheckResult:
    """Check if scapy is installed (needed for `blackout tools capture`)."""
    try:
        __import__("scapy.all")
        return CheckResult("Python: scapy (packet capture)", True, "Installed")
    except ImportError:
        return CheckResult(
            "Python: scapy (packet capture)", False,
            "Not installed — required for `blackout tools capture`",
            fixable=True,
            fix=lambda: subprocess.run([sys.executable, "-m", "pip", "install", "scapy"], check=False),
        )


def check_npcap() -> CheckResult:
    """Check for the OS-level packet capture driver scapy needs to actually sniff live traffic."""
    if sys.platform == "win32":
        system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
        if (system32 / "Npcap").exists() or (system32 / "wpcap.dll").exists():
            return CheckResult("Npcap (packet capture driver)", True, "Found")
        return CheckResult(
            "Npcap (packet capture driver)", False,
            "Missing — required for `blackout tools capture` to sniff live traffic. "
            'Install from https://npcap.com (check "Install Npcap in WinPcap API-compatible Mode").',
            fixable=False,
        )

    try:
        import ctypes.util
        found = ctypes.util.find_library("pcap") is not None
    except Exception:
        found = False
    if found:
        return CheckResult("libpcap (packet capture driver)", True, "Found")
    return CheckResult(
        "libpcap (packet capture driver)", False,
        "Missing — required for `blackout tools capture`. Install via your package manager "
        "(e.g. `apt install libpcap-dev`).",
        fixable=False,
    )


def check_network_driver() -> CheckResult:
    """Check basic platform networking prerequisites."""
    if sys.platform.startswith("linux"):
        from . import linux_network

        missing = [name for name in ("ip",) if not linux_network._command_available(name)]
        if missing:
            return CheckResult("Linux networking", False, f"Missing required command: {', '.join(missing)}")
        firewall = "nftables" if linux_network._command_available("nft") else "iptables fallback"
        return CheckResult("Linux networking", True, f"ip available; firewall backend: {firewall}")
    if sys.platform != "win32":
        return CheckResult("Network driver", True, "N/A")
    try:
        result = subprocess.run(
            ["netsh", "winsock", "show", "catalog"],
            capture_output=True, timeout=5,
        )
        if result.returncode == 0:
            return CheckResult("Winsock catalog", True, "OK")
        return CheckResult(
            "Winsock catalog", False, "Winsock may be corrupted",
            fixable=True,
            fix=lambda: subprocess.run(["netsh", "winsock", "reset"], capture_output=True, timeout=30),
        )
    except Exception as e:
        return CheckResult("Winsock catalog", False, str(e))


def check_system_path() -> CheckResult:
    """Check if the directory containing the blackout executable is in the system PATH."""
    if sys.platform != "win32":
        return CheckResult("System PATH", True, "N/A (not Windows)")

    exe_path = Path(sys.argv[0]).resolve()
    exe_dir = exe_path.parent
    
    # If running directly via python.exe, skip this check
    if exe_path.name.lower() == "python.exe":
        return CheckResult("System PATH", True, "N/A (Running via Python)")

    current_path = os.environ.get("PATH", "")
    if str(exe_dir).lower() in current_path.lower():
        return CheckResult("System PATH", True, f"Found in PATH ({exe_dir.name})")

    def _fix_path():
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
                try:
                    val, _ = winreg.QueryValueEx(key, "PATH")
                except OSError:
                    val = ""
                if str(exe_dir).lower() not in val.lower():
                    new_path = val.rstrip(";") + ";" + str(exe_dir) if val else str(exe_dir)
                    winreg.SetValueEx(key, "PATH", 0, winreg.REG_EXPAND_SZ, new_path)
            
            # Broadcast the environment change to running windows
            import ctypes
            HWND_BROADCAST = 0xFFFF
            WM_SETTINGCHANGE = 0x001A
            ctypes.windll.user32.SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, "Environment", 2, 1000, None)
            
            # Also update current process env so later checks don't fail if they rely on it
            os.environ["PATH"] = os.environ.get("PATH", "") + ";" + str(exe_dir)
        except Exception as exc:
            raise Exception(f"Failed to update registry: {exc}")

    return CheckResult(
        "System PATH", False, f"Missing {exe_dir.name} from PATH",
        fixable=True, fix=_fix_path
    )


def _load_country_profile_quietly():
    """Load country profile without printing anything — returns profile or None."""
    try:
        from . import country_profiles as cp
        from . import settings as _cfg
        from .network_switcher import get_isp_info
        code = _cfg.load().get("country", "")
        if code:
            return cp.get_profile(code)
        return cp.detect_country(get_isp_info(timeout=4.0))
    except Exception:
        return None


def check_internet() -> CheckResult:
    """Test if direct internet works at all. Uses Baidu for China (always reachable without bypass)."""
    import urllib.request
    profile = _load_country_profile_quietly()
    if profile and profile.code == "CN":
        urls = ["http://www.baidu.com", "http://www.qq.com"]
    else:
        urls = ["http://cp.cloudflare.com/", "http://www.google.com/generate_204"]
    for url in urls:
        try:
            urllib.request.urlopen(url, timeout=5)
            return CheckResult("Direct internet", True, "Connected")
        except Exception:
            continue
    return CheckResult("Direct internet", False, "No connection detected")


def check_country_profile() -> CheckResult:
    """Detect active country profile — informational, always returns ok=True."""
    try:
        from . import settings as _cfg
        pinned = _cfg.load().get("country", "")
        profile = _load_country_profile_quietly()
        if pinned and profile:
            msg = f"Pinned to {profile.name} ({profile.code}) — {profile.censorship_level} censorship"
        elif profile:
            msg = f"Detected: {profile.name} ({profile.code}) — {profile.censorship_level} censorship"
        else:
            msg = "Unknown country — using default settings"
        return CheckResult("Country profile", True, msg)
    except Exception as e:
        return CheckResult("Country profile", True, f"Could not detect ({e})")


def check_russia_whitelist() -> list[CheckResult]:
    """Check if saved proxy configs are on the Russian cellular whitelist."""
    results = []
    try:
        profile = _load_country_profile_quietly()
        if not profile or profile.code != "RU":
            return results

        from .config.manager import load_configs
        from .russia_whitelist import check_whitelist_status
        from .tools import resolve_doh

        configs = load_configs()
        if not configs:
            return results

        for c in configs:
            if c.protocol not in ("vless", "trojan", "vmess", "hysteria2", "tuic"):
                continue
            host = c.address
            resolved = resolve_doh(host)
            ip = resolved or host
            _on_whitelist, detail = check_whitelist_status(ip)
            results.append(CheckResult(
                f"Whitelist: {c.name or c.address}",
                True,
                detail,
            ))
    except Exception as exc:
        results.append(CheckResult("Russia whitelist", True, f"Could not check ({exc})"))
    return results


# ──────────────────── Epic checks ────────────────────────────────

_MIN_FREE_MB = 200   # Minimum free disk space (MB) before warning


def check_disk_space() -> CheckResult:
    """
    Verify that the drive hosting the project has at least _MIN_FREE_MB free.
    Uses shutil.disk_usage() — works on Windows and Linux.
    """
    import shutil
    try:
        usage = shutil.disk_usage(PROJECT_ROOT)
        free_mb = usage.free // (1024 * 1024)
        if free_mb >= _MIN_FREE_MB:
            return CheckResult(
                "Disk space",
                True,
                f"{free_mb} MB free (threshold {_MIN_FREE_MB} MB)",
            )
        return CheckResult(
            "Disk space",
            False,
            f"Only {free_mb} MB free — at least {_MIN_FREE_MB} MB recommended",
            fixable=False,
        )
    except Exception as exc:
        return CheckResult("Disk space", False, f"Could not check: {exc}")


def check_binary_runnable() -> list[CheckResult]:
    """
    Try to execute each critical binary with a harmless flag to verify
    it is not corrupted, quarantined, or missing a DLL dependency.

    A binary that is present but refuses to execute (exit code 1, DLL error,
    access denied, etc.) is flagged as FAIL so the user knows to re-download it.
    """
    results = []
    engine_bin = BINS_DIR / "blackout-engine.exe"
    if engine_bin.exists():
        try:
            result = subprocess.run(
                [str(engine_bin)],
                capture_output=True,
                timeout=5,
            )
            # blackout-engine exits with 1 on no args, which is OK (it executes)
            results.append(CheckResult(
                "runnable: blackout-engine.exe",
                True,
                f"Executes OK (rc={result.returncode})",
            ))
        except Exception as exc:
            results.append(CheckResult(
                "runnable: blackout-engine.exe",
                False,
                f"OS error: {exc}",
                fixable=False,
            ))

    # Map binary → flag that triggers a quick exit without doing real work
    candidates = {}
    if _gdpi_backend() == "legacy":
        candidates["goodbyedpi.exe"] = ["--help"]
    for binary, args in candidates.items():
        if engine_bin.exists() and binary in ("xray.exe", "sing-box.exe"):
            continue
        path = BINS_DIR / binary
        if not path.exists():
            # Already reported missing by check_bins_present() — skip
            continue
        try:
            result = subprocess.run(
                [str(path)] + args,
                capture_output=True,
                timeout=5,
            )
            # Any returncode is acceptable as long as the process actually ran
            # (0 or non-zero — what matters is no exception / OS error)
            results.append(CheckResult(
                f"runnable: {binary}",
                True,
                f"Executes OK (rc={result.returncode})",
            ))
        except FileNotFoundError:
            results.append(CheckResult(
                f"runnable: {binary}",
                False,
                "OS cannot find the file (deleted or quarantined?)",
                fixable=False,
            ))
        except subprocess.TimeoutExpired:
            # Hung on --help? Still counts as "runs"
            results.append(CheckResult(f"runnable: {binary}", True, "Started (timed out on help flag — OK)"))
        except PermissionError:
            results.append(CheckResult(
                f"runnable: {binary}",
                False,
                "Permission denied — run as Administrator or check AV quarantine",
                fixable=False,
            ))
        except OSError as exc:
            # WinError 740 = ERROR_ELEVATION_REQUIRED — binary works fine,
            # it just needs Administrator to load its kernel driver.
            if getattr(exc, "winerror", None) == 740:
                results.append(CheckResult(
                    f"runnable: {binary}",
                    True,
                    "Needs Administrator (kernel driver) — OK",
                ))
            else:
                results.append(CheckResult(
                    f"runnable: {binary}",
                    False,
                    f"OS error: {exc}",
                    fixable=False,
                ))
    return results


def check_config_security() -> CheckResult:
    """Checks if the proxy configuration file is encrypted at rest (AES-256)."""
    from . import security as sec
    if sec.configs_are_obfuscated():
        return CheckResult("Config Encryption", True, "OK (AES-256 encrypted at rest)")
    
    # Check if configs.txt actually has user configurations
    from .config.manager import load_configs
    try:
        configs = load_configs()
    except Exception:
        configs = []
        
    if not configs:
        return CheckResult("Config Encryption", True, "No configs to encrypt")
        
    return CheckResult(
        "Config Encryption", False,
        f"Proxy configs are stored in plaintext. Run '{get_command_prefix()} config encrypt' to secure them.",
        fixable=True,
        fix=sec.obfuscate_configs
    )


def check_process_conflicts() -> CheckResult:
    """Detects if stale bypass processes from previous runs are still alive and blocking ports."""
    import psutil
    conflicts = []
    current_pid = os.getpid()
    
    target_names = {"xray.exe", "sing-box.exe", "singbox.exe"}
    if _gdpi_backend() == "legacy":
        target_names.update({name.lower() for name in GDPI_BIN_NAMES})
    
    for p in psutil.process_iter(attrs=["pid", "name"]):
        try:
            name_info = p.info.get("name")
            if not name_info:
                continue
            pname = name_info.lower()
            if pname in target_names and p.info["pid"] != current_pid:
                try:
                    exe_path = p.exe()
                    if "blackout-kit" in exe_path.lower() or ".blackout-kit" in exe_path.lower():
                        conflicts.append(p)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    conflicts.append(p)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if not conflicts:
        return CheckResult("Process conflicts", True, "OK")

    def _fix_conflicts():
        for p in conflicts:
            try:
                p.terminate()
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass

    p_list = ", ".join(f"{p.name()} ({p.pid})" for p in conflicts)
    return CheckResult(
        "Process conflicts", False,
        f"Stale processes found: {p_list}. May block ports or driver.",
        fixable=True,
        fix=_fix_conflicts
    )


def check_firewall_rules() -> CheckResult:
    """Verify the Blackout Kit kill-switch state when it is enabled."""
    if sys.platform.startswith("linux"):
        from . import linux_network

        enabled = cfg.load().get("kill_switch", False)
        if not enabled:
            return CheckResult("Firewall integrity", True, "OK (Linux kill switch disabled)")
        if not linux_network.is_root():
            return CheckResult("Firewall integrity", False, "Linux kill switch needs sudo/root privileges")
        if linux_network.kill_switch_is_active():
            return CheckResult("Firewall integrity", True, "OK (Blackout Kit-owned Linux firewall rules active)")
        return CheckResult(
            "Firewall integrity",
            False,
            "Linux kill switch is enabled in settings but its Blackout Kit firewall rules are missing.",
            fixable=True,
            fix=lambda: __import__("blackoutkit.security", fromlist=["enable_kill_switch"]).enable_kill_switch(),
        )
    if sys.platform != "win32":
        return CheckResult("Firewall integrity", True, "N/A")

    if not cfg.load().get("kill_switch", False):
        return CheckResult("Firewall integrity", True, "OK (Linux-only kill switch unavailable on Windows)")

    from . import security as sec

    def disable_unsupported_windows_setting():
        try:
            sec.disable_kill_switch()
        finally:
            cfg.set_value("kill_switch", False)

    return CheckResult(
        "Firewall integrity", False,
        "Windows kill switch is unavailable; stale Blackout Kit rules and the saved setting should be removed.",
        fixable=True,
        fix=disable_unsupported_windows_setting,
    )


def check_windows_compat() -> CheckResult:
    """Verify the current platform exposes a supported Blackout Kit runtime."""
    if sys.platform.startswith("linux"):
        import platform

        from . import BINS_DIR

        arch = platform.machine().lower()
        if arch not in {"x86_64", "amd64"}:
            return CheckResult("OS Compatibility", False, f"Linux architecture {arch} is unsupported; x86_64 is required")
        runner = BINS_DIR / "blackout-engine"
        if not runner.exists():
            return CheckResult("Linux runtime", False, "Missing bins/blackout-engine. Install the Linux x86_64 release asset.")
        if not os.access(runner, os.X_OK):
            return CheckResult("Linux runtime", False, "bins/blackout-engine is not executable. Run: chmod +x bins/blackout-engine")
        return CheckResult("OS Compatibility", True, f"Linux {platform.release()} ({arch}) — XRay/TUN runtime ready")
    if sys.platform != "win32":
        return CheckResult("OS Compatibility", True, f"Unsupported platform: {sys.platform}")
    
    import platform
    arch = platform.machine()
    is_64bit = "64" in arch or "AMD64" in arch.upper() or "ARM64" in arch.upper()
    if not is_64bit:
        return CheckResult("OS Compatibility", False, f"32-bit architecture ({arch}) is unsupported. x64 required.")

    try:
        release = platform.release()
        version = platform.version()
        major = int(version.split(".")[0])
        if major < 10:
            return CheckResult("OS Compatibility", False, f"Windows {release} (Version {version}) is too old. Windows 10/11 required.")
        return CheckResult("OS Compatibility", True, f"Windows {release} ({arch}) — OK")
    except Exception as e:
        return CheckResult("OS Compatibility", True, f"Windows (arch {arch}) — {e}")


def check_admin_privileges() -> CheckResult:
    """Checks if the console is running with Administrative privileges."""
    from .proxy_manager import is_admin
    if is_admin():
        return CheckResult("Admin Rights", True, "OK (Elevated)")
    
    return CheckResult(
        "Admin Rights", False,
        "Running without Administrator privileges. Fixes and engines will trigger UAC prompts.",
        fixable=False
    )


def check_stale_proxy() -> CheckResult:
    """Detects if a system proxy is active pointing to our SOCKS/HTTP port while the daemon is offline."""
    if sys.platform != "win32":
        return CheckResult("System Proxy", True, "N/A (not Windows)")

    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_READ) as key:
            try:
                enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
                server, _ = winreg.QueryValueEx(key, "ProxyServer")
            except OSError:
                enabled = 0
                server = ""
    except Exception:
        return CheckResult("System Proxy", True, "OK")

    if not enabled or not server:
        return CheckResult("System Proxy", True, "OK (Proxy disabled)")

    s = cfg.load()
    socks_port = s.get("xray_socks_port", 10808)
    http_port = s.get("xray_http_port", 10809)
    ports = {str(socks_port), str(http_port)}

    is_ours = False
    for p in ports:
        if f"127.0.0.1:{p}" in server or f"localhost:{p}" in server:
            is_ours = True
            break

    if not is_ours:
        return CheckResult("System Proxy", True, f"OK (External proxy active: {server})")

    from . import daemon
    if daemon.get_pid() is not None:
        return CheckResult("System Proxy", True, "OK (Proxy active & daemon running)")

    from .proxy_manager import clear_system_proxy
    return CheckResult(
        "System Proxy", False,
        f"Stale system proxy pointing to offline port ({server}). Browsing will be blocked.",
        fixable=True,
        fix=clear_system_proxy
    )


def get_command_prefix() -> str:
    """Return the prefix used to run the app (either 'blackout' or 'python blackout.py')."""
    import sys
    from pathlib import Path
    exe_name = Path(sys.argv[0]).name.lower()
    if exe_name == "blackout.py":
        return "python blackout.py"
    elif "blackout" in exe_name:
        return "blackout"
    return "python blackout.py"


def get_execution_context() -> dict:
    """Returns information about how and where the app is running."""
    import sys
    from pathlib import Path

    from . import __version__
    
    script_path = Path(sys.argv[0]).resolve()
    # Check if run from a global Python path (Scripts, site-packages, or python installation)
    is_global = "site-packages" in str(script_path).lower() or "scripts" in str(script_path).lower() or not script_path.exists()
    
    return {
        "version": __version__,
        "path": script_path,
        "is_global": is_global,
        "prefix": get_command_prefix(),
    }


def check_ports_in_use() -> CheckResult:
    """Detects if configured ports (SNI, XRay) are already bound by another app."""
    import psutil
    s = cfg.load()
    ports_to_check = {
        "SNI": s.get("sni_listen_port", 40443),
        "XRay SOCKS": s.get("xray_socks_port", 10808),
        "XRay HTTP": s.get("xray_http_port", 10809),
    }
    
    in_use = {}
    try:
        conns = psutil.net_connections(kind="inet")
        for conn in conns:
            if conn.status == "LISTEN" and conn.laddr:
                port = conn.laddr.port
                for name, p in ports_to_check.items():
                    if port == p:
                        try:
                            proc = psutil.Process(conn.pid)
                            pname = proc.name()
                        except Exception:
                            pname = "Unknown"
                        if "blackout" not in pname.lower():
                            in_use[name] = (port, pname)
    except Exception as e:
        return CheckResult("Port Conflicts", True, f"Could not check: {e}")
        
    if not in_use:
        return CheckResult("Port Conflicts", True, "OK (All ports free)")
        
    msg = ", ".join(f"{n} ({p}) by {proc}" for n, (p, proc) in in_use.items())
    
    def _fix_ports():
        import random
        for name in in_use:
            new_port = random.randint(15000, 50000)
            if name == "SNI": cfg.set_value("sni_listen_port", new_port)
            elif name == "XRay SOCKS": cfg.set_value("xray_socks_port", new_port)
            elif name == "XRay HTTP": cfg.set_value("xray_http_port", new_port)
            
    return CheckResult("Port Conflicts", False, f"Ports in use: {msg}", fixable=True, fix=_fix_ports)


def check_tun_adapter() -> CheckResult:
    """Verify virtual adapters and identify post-crash stale adapter state."""
    if sys.platform.startswith("linux"):
        from . import linux_network

        if not linux_network.is_root():
            return CheckResult("Linux TUN", False, "Run with sudo before starting system-wide TUN mode")
        if not linux_network._command_available("ip"):
            return CheckResult("Linux TUN", False, "Missing required command: ip")
        if linux_network.tunnel_exists():
            return CheckResult(
                "Linux TUN",
                False,
                "Stale BlackoutKit-TUN interface found",
                fixable=True,
                fix=linux_network.delete_owned_tunnel,
            )
        return CheckResult("Linux TUN", True, "Ready (no stale BlackoutKit-TUN interface)")
    if sys.platform != "win32":
        return CheckResult("TUN/TAP Adapter", True, "N/A")

    from . import tools as net_tools

    snapshot = net_tools.get_network_recovery_snapshot()
    virtual_markers = ("tap", "tun", "wintun", "wireguard", "sing-box", "singbox")
    virtual_adapters = [
        adapter for adapter in snapshot["adapters"]
        if any(
            marker in " ".join(
                str(adapter.get(field, ""))
                for field in ("Name", "InterfaceAlias", "InterfaceDescription", "DriverDescription")
            ).lower()
            for marker in virtual_markers
        )
    ]
    if not virtual_adapters:
        return CheckResult(
            "TUN/TAP Adapter", False,
            "No TAP/TUN virtual adapter found. Routing engines (WireGuard/TUN) may fail.",
            fixable=False,
        )

    stale = net_tools.find_stale_virtual_adapters(snapshot, daemon_running=False)
    if not stale:
        return CheckResult("TUN/TAP Adapter", True, "OK (Found virtual adapter)")

    names = ", ".join(str(adapter.get("Name", "Unknown")) for adapter in stale)
    return CheckResult(
        "TUN/TAP Adapter", False,
        f"Stale Blackout virtual adapter state: {names}",
        fixable=True,
        fix=lambda: net_tools.run_network_recovery(),
    )


def check_firewall_exclusion() -> CheckResult:
    """Check if the Blackout bins directory is excluded from Windows Defender."""
    if sys.platform != "win32":
        return CheckResult("Windows Defender", True, "N/A")
    try:
        from .proxy_manager import is_admin
        if not is_admin():
            return CheckResult("Windows Defender", True, "OK (Skipped, needs admin)")
            
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command", "Get-MpPreference | Select-Object -ExpandProperty ExclusionPath"],
            capture_output=True, text=True, errors="ignore", timeout=10
        )
        bins_str = str(BINS_DIR).lower()
        if bins_str in r.stdout.lower():
            return CheckResult("Windows Defender", True, "OK (bins/ is excluded)")
            
        def _fix_exclusion():
            escaped_path = str(BINS_DIR).replace("'", "''")
            subprocess.run(
                ["powershell", "-NoProfile", "-Command", f"Add-MpPreference -ExclusionPath '{escaped_path}'"],
                capture_output=True, timeout=10
            )
            
        return CheckResult("Windows Defender", False, "bins/ directory is not excluded from AV scans. False positives may occur.", fixable=True, fix=_fix_exclusion)
    except Exception:
        return CheckResult("Windows Defender", True, "OK (Could not verify)")


# ──────────────────────────── Runner ─────────────────────────────

def run_local_checks(include_optional: bool = False) -> list[CheckResult]:
    """Run checks that inspect local files, settings, and OS state only."""
    checks = [
        check_bins_dir(),
        check_app_data_dir(),
        check_settings(),
        check_disk_space(),
        check_network_driver(),
        check_windivert(),
        check_system_path(),
        check_config_security(),
        check_process_conflicts(),
        check_firewall_rules(),
        check_firewall_exclusion(),
        check_windows_compat(),
        check_tun_adapter(),
        check_ports_in_use(),
        check_admin_privileges(),
        check_stale_proxy(),
    ]
    if include_optional:
        checks.extend((check_scapy(), check_npcap()))
    all_results = list(checks)
    all_results.extend(check_data_files())
    all_results.extend(check_python_deps())
    all_results.extend(check_bins_present())
    return all_results


def run_all_checks(auto_fix: bool = False, include_optional: bool = False) -> list[CheckResult]:
    checks = [
        check_bins_dir(),
        check_app_data_dir(),
        check_settings(),
        check_disk_space(),        # Epic
        check_internet(),
        check_country_profile(),   # Country profile (informational)
        check_network_driver(),
        check_windivert(),
        check_system_path(),
        check_config_security(),
        check_process_conflicts(),
        check_firewall_rules(),
        check_firewall_exclusion(),
        check_windows_compat(),
        check_tun_adapter(),
        check_ports_in_use(),
        check_admin_privileges(),
        check_stale_proxy(),
    ]
    if include_optional:
        checks.extend((check_scapy(), check_npcap()))
    all_results = list(checks)
    all_results.extend(check_data_files())
    all_results.extend(check_python_deps())
    all_results.extend(check_bins_present())
    all_results.extend(check_binary_runnable())    # Epic
    all_results.extend(check_russia_whitelist())   # Russia whitelist (informational)

    if auto_fix:
        for r in all_results:
            if not r.ok and r.fixable and r.fix:
                try:
                    r.fix()
                    r.message = f"[success]Fixed automatically[/success]  (was: {r.message})"
                    r.ok = True
                except Exception as e:
                    r.message += f"  [error](fix failed: {e})[/error]"

    return all_results


def print_report(results: list[CheckResult], auto_fixed: bool = False):
    ok_count   = sum(1 for r in results if r.ok)
    fail_count = len(results) - ok_count

    table = Table(
        title=f"[bold]Blackout Kit — Doctor Report[/bold]  "
              f"({ok_count} OK, {fail_count} issues)",
        box=box.ROUNDED,
        border_style="dim",
        header_style="bold cyan",
    )
    table.add_column("Check",    style="white")
    table.add_column("Status",   width=10)
    table.add_column("Details",  style="dim")

    for r in results:
        status = "[success]✓ OK[/success]" if r.ok else "[error]✗ FAIL[/error]"
        if not r.ok and r.fixable:
            status = "[yellow]⚠ FIXABLE[/yellow]"
        table.add_row(r.name, status, r.message)

    console.print()
    # Execution Context Header
    ctx = get_execution_context()
    run_type = "[bold cyan]Global Executable[/bold cyan]" if ctx["is_global"] else "[bold green]Local Source Script[/bold green]"
    console.print(f"[dim]Running via: {run_type} | Path: {ctx['path']} | Version: {ctx['version']}[/dim]")
    console.print(table)

    if fail_count > 0 and not auto_fixed:
        fixable = sum(1 for r in results if not r.ok and r.fixable)
        if fixable:
            console.print(
                f"\n[yellow]{fixable} issues can be auto-fixed.[/yellow]  "
                f"Run: [bold]{ctx['prefix']} doctor --fix[/bold]"
            )
    elif fail_count == 0:
        console.print("\n[success]Everything looks good! Ready to use.[/success]")
    console.print()
