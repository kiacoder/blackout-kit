#!/usr/bin/env python3
"""
Blackout Kit - Entry point.
Run: python blackout.py <command>

Rare upgrades:
  - _check_compat(): Python 3.10+, Windows 10+, x64 architecture
  - _first_run_hint(): shows quick-start tip on first launch
  - Crash report includes Python version + OS + traceback summary
"""
from __future__ import annotations
import sys
import os
import platform

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# ──────────────────────────── Compatibility gate ──────────────────────────────

def _check_compat() -> list[str]:
    """
    Run lightweight compatibility checks before importing anything heavy.
    Returns a list of warning strings (empty = all good).
    Warnings are non-fatal — Blackout Kit still tries to run.
    """
    warnings: list[str] = []

    # Python version — require 3.10+ (PEP 604 union type hints).
    if sys.version_info < (3, 10):
        warnings.append(
            f"Python {sys.version_info.major}.{sys.version_info.minor} detected. "
            "Blackout Kit requires Python 3.10 or newer. "
            "Download from python.org/downloads"
        )

    # Platform — Windows strongly preferred; Linux/macOS work in degraded mode
    if sys.platform != "win32":
        warnings.append(
            f"Running on {sys.platform} — Windows provides the broad engine catalog. "
            "Linux provides the managed XRay/TUN subset and the endpoint-scoped kill switch."
        )
    else:
        # Windows version — require Windows 10 (build 10240) or later
        try:
            win_ver = sys.getwindowsversion()
            # Major 10 = Windows 10/11 (Server 2016+).  Major 6 = Win 7/8/8.1
            if win_ver.major < 10:
                ver_str = f"{win_ver.major}.{win_ver.minor}.{win_ver.build}"
                warnings.append(
                    f"Windows version {ver_str} detected. "
                    "Windows 10 (build 10240) or newer is recommended. "
                    "Some features may not work on older Windows."
                )
        except Exception:
            pass  # Can't determine version — ignore

    # Architecture — all third-party binaries are x64 only
    machine = platform.machine().lower()
    if machine and machine not in ("amd64", "x86_64"):
        warnings.append(
            f"CPU architecture '{platform.machine()}' detected. "
            "Most binaries (xray.exe, goodbyedpi.exe, etc.) require a 64-bit x64 CPU. "
            "ARM devices are not supported."
        )

    return warnings


# ──────────────────────────── First-run compatibility shim ─────────────────────

def _first_run_hint():
    """Delegate first-run rendering to the installed CLI onboarding boundary."""
    from blackoutkit.onboarding import render_first_run_welcome
    from blackoutkit.theme import console, is_interactive

    if not is_interactive():
        return False
    return render_first_run_welcome(console)


# ──────────────────────────── Main ───────────────────────────────────────────


def _machine_output_requested(argv: list[str] | None = None) -> bool:
    """Return whether this invocation requested the machine-readable contract."""
    return "--json" in (sys.argv[1:] if argv is None else argv)


def _demo_requested(argv: list[str] | None = None) -> bool:
    """Return whether this invocation requests the side-effect-free demo."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    return next((argument for argument in arguments if not argument.startswith("-")), None) == "demo"


if __name__ == "__main__":
    import os
    machine_output = _machine_output_requested()
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w")

    # 1. Compatibility check — print warnings but do not abort
    compat_warnings = _check_compat()
    if compat_warnings:
        try:
            from rich.console import Console
            _con = Console(stderr=True)
            for w in compat_warnings:
                _con.print(f"[yellow]Warning:[/yellow] {w}")
        except Exception:
            for w in compat_warnings:
                print(f"Warning: {w}", file=sys.stderr)

    # 1.5 Extract bundled binaries if running as PyInstaller EXE
    if getattr(sys, 'frozen', False) and not _demo_requested():
        import shutil
        from blackoutkit import BINS_DIR, _MEIPASS
        bundled_bins = _MEIPASS / "bins"
        if bundled_bins.exists():
            for item in bundled_bins.iterdir():
                dest = BINS_DIR / item.name
                if not dest.exists() or dest.stat().st_size != item.stat().st_size:
                    try:
                        if item.is_file():
                            shutil.copy2(item, dest)
                    except Exception:
                        pass

    # 2. Run the Typer CLI (its root callback owns onboarding and launcher output).
    try:
        from blackoutkit.proxy_manager import install_console_close_handler
        from blackoutkit.typer_cli import main

        install_console_close_handler()
        main()
    except KeyboardInterrupt:
        try:
            from rich.console import Console
            Console().print("\n[yellow]Interrupted. Cleaning up...[/yellow]")
        except Exception:
            print("\nInterrupted. Cleaning up...")
        try:
            from blackoutkit.proxy_manager import cleanup_owned_system_proxy
            cleanup_owned_system_proxy()
        except Exception:
            pass
        sys.exit(0)
    except SystemExit:
        raise
    except Exception as exc:
        if machine_output:
            try:
                from blackoutkit.cli_output import emit_error
                from blackoutkit.theme import console

                emit_error(
                    "internal_error",
                    "Blackout Kit could not complete that action",
                    console=console,
                    json_output=True,
                )
            except Exception:
                print('{"schema_version":1,"ok":false,"error":{"code":"internal_error","message":"Blackout Kit could not complete that action"}}')
        else:
            try:
                from blackoutkit.theme import print_friendly_error
                print_friendly_error(exc)
            except Exception:
                print("Blackout Kit could not complete that action. Try: blackout doctor", file=sys.stderr)
        sys.exit(1)
