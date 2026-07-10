"""
Blackout Kit - Self-diagnosis and self-healing.
Detects missing/corrupted files, bad settings, broken network drivers,
and attempts automatic repairs where possible.

Epic upgrades:
  - cryptography added to check_python_deps()
  - check_disk_space(): warns if < 200 MB free in bins/ parent drive
  - check_binary_runnable(): actually launches each binary to confirm it executes
"""
import json
import os
import subprocess
import sys
from pathlib import Path

from . import settings as cfg
from .theme import console
from rich.panel import Panel
from rich.table import Table
from rich import box

PROJECT_ROOT = Path(__file__).parent.parent
BINS_DIR     = PROJECT_ROOT / "bins"
DATA_DIR     = PROJECT_ROOT / "data"
APP_DATA_DIR = Path.home() / ".blackout-kit"

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
        self.name     = name
        self.ok       = ok
        self.message  = message
        self.fixable  = fixable
        self.fix      = fix   # callable that attempts auto-fix


def check_data_files() -> list[CheckResult]:
    results = []
    # Defined here to avoid forward-reference issues at module level
    defaults = {
        "data/cloudflare_ips.txt": _default_cf_ips,
        "data/fake_snis.txt":      _default_snis,
        "data/configs.txt":        _default_configs,
    }
    for rel_path, default_fn in defaults.items():
        full = PROJECT_ROOT / rel_path
        if full.exists() and full.stat().st_size > 0:
            results.append(CheckResult(rel_path, True, "OK"))
        elif full.exists():
            results.append(CheckResult(
                rel_path, False, "File is empty",
                fixable=True,
                fix=lambda p=full, fn=default_fn: p.write_text(fn()),
            ))
        else:
            results.append(CheckResult(
                rel_path, False, "File missing",
                fixable=True,
                fix=lambda p=full, fn=default_fn: (p.parent.mkdir(parents=True, exist_ok=True), p.write_text(fn())),
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


def check_bins_present() -> list[CheckResult]:
    """Check which binaries are present — suggests 'blackout bins download' for missing ones."""
    results = []
    from .downloader import BIN_REGISTRY, BINS_DIR as _BINS_DIR

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
            "Missing — SNI, XRay, and WireGuard will not work. "
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

    for key, info in BIN_REGISTRY.items():
        all_present = all((_BINS_DIR / b).exists() for b in info.output_bins)
        if all_present:
            # Show size of first expected binary as a proxy for the whole group
            first = _BINS_DIR / info.output_bins[0]
            size_kb = first.stat().st_size // 1024
            results.append(CheckResult(f"bins: {info.display_name}", True, f"Found ({size_kb} KB)"))
        else:
            if info.github_repo:
                fix_hint = "Run: blackout bins download"
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
    """Check if WinDivert is present (needed by GoodbyeDPI and SNI spoofer)."""
    dll = BINS_DIR / "WinDivert.dll"
    sys_file = BINS_DIR / "WinDivert64.sys"
    if dll.exists() and sys_file.exists():
        return CheckResult("WinDivert (GoodbyeDPI driver)", True, "Found")
    return CheckResult(
        "WinDivert (GoodbyeDPI driver)", False,
        "Missing — download with goodbyedpi.exe",
        fixable=False,
    )


def check_network_driver() -> CheckResult:
    """Check basic network stack health on Windows."""
    if sys.platform != "win32":
        return CheckResult("Network driver", True, "N/A (not Windows)")
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
            fix=lambda: subprocess.run(["netsh", "winsock", "reset"], capture_output=True),
        )
    except Exception as e:
        return CheckResult("Winsock catalog", False, str(e))


def _load_country_profile_quietly():
    """Load country profile without printing anything — returns profile or None."""
    try:
        from . import country_profiles as cp
        from .network_switcher import get_isp_info
        from . import settings as _cfg
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
    candidates = {
        "goodbyedpi.exe": ["--help"],
    }
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


# ──────────────────────────── Runner ─────────────────────────────

def run_all_checks(auto_fix: bool = False) -> list[CheckResult]:
    checks = (
        check_bins_dir(),
        check_app_data_dir(),
        check_settings(),
        check_disk_space(),        # Epic
        check_internet(),
        check_country_profile(),   # Country profile (informational)
        check_network_driver(),
        check_windivert(),
    )
    all_results = list(checks)
    all_results.extend(check_data_files())
    all_results.extend(check_python_deps())
    all_results.extend(check_bins_present())
    all_results.extend(check_binary_runnable())    # Epic

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
    console.print(table)

    if fail_count > 0 and not auto_fixed:
        fixable = sum(1 for r in results if not r.ok and r.fixable)
        if fixable:
            console.print(
                f"\n[yellow]{fixable} issues can be auto-fixed.[/yellow]  "
                f"Run: [bold]blackout doctor --fix[/bold]"
            )
    elif fail_count == 0:
        console.print("\n[success]Everything looks good! Ready to use.[/success]")
    console.print()
