#!/usr/bin/env python3
"""
Blackout Kit - Entry point.
Run: python blackout.py <command>

Rare upgrades:
  - _check_compat(): Python 3.9+, Windows 10+, x64 architecture
  - _first_run_hint(): shows quick-start tip on first launch
  - Crash report includes Python version + OS + traceback summary
"""
import sys
import os
import platform
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# ──────────────────────────── Compatibility gate ──────────────────────────────

def _check_compat() -> list[str]:
    """
    Run lightweight compatibility checks before importing anything heavy.
    Returns a list of warning strings (empty = all good).
    Warnings are non-fatal — Blackout Kit still tries to run.
    """
    warnings: list[str] = []

    # Python version — require 3.9+ (union type hints, dict merge, etc.)
    if sys.version_info < (3, 9):
        warnings.append(
            f"Python {sys.version_info.major}.{sys.version_info.minor} detected. "
            "Blackout Kit requires Python 3.9 or newer. "
            "Download from python.org/downloads"
        )

    # Platform — Windows strongly preferred; Linux/macOS work in degraded mode
    if sys.platform != "win32":
        warnings.append(
            f"Running on {sys.platform} — most features require Windows 10+. "
            "Kill switch, registry proxy, and GoodbyeDPI are Windows-only."
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


# ──────────────────────────── First-run hint ─────────────────────────────────

def _first_run_hint():
    """
    If this is the first time Blackout Kit is launched (no settings file),
    print a short getting-started nudge.
    """
    from pathlib import Path
    from blackoutkit import settings as _cfg
    settings_file = Path.home() / ".blackout-kit" / "settings.json"
    if not settings_file.exists():
        show = True  # genuine first run
    else:
        show = _cfg.load().get("show_first_run", False)  # hidden after setup unless user re-enables
    if show:
        from rich.console import Console
        from rich.panel import Panel
        Console().print(Panel(
            "[bold]Welcome to Blackout Kit![/bold]  Looks like your first launch.\n\n"
            "Get started in 3 commands:\n"
            "  [cyan]python blackout.py bins download[/cyan]      — auto-download all engine binaries\n"
            "  [cyan]python blackout.py doctor[/cyan]             — verify everything is ready\n"
            "  [cyan]python blackout.py connect[/cyan]            — start bypassing\n\n"
            "[dim]Tip: run 'python blackout.py help quick_start' for the full setup guide.[/dim]",
            title="[bold green]First Run[/bold green]",
            border_style="green",
            padding=(0, 2),
        ))


# ──────────────────────────── Main ───────────────────────────────────────────

if __name__ == "__main__":
    # 1. Compatibility check — print warnings but do not abort
    compat_warnings = _check_compat()
    if compat_warnings:
        from rich.console import Console
        _con = Console(stderr=True)
        for w in compat_warnings:
            _con.print(f"[yellow]Warning:[/yellow] {w}")

    # 2. First-run nudge (only if no settings file yet)
    _first_run_hint()

    # 3. Run the CLI
    try:
        from blackoutkit.cli import main
        main()
    except KeyboardInterrupt:
        from rich.console import Console
        Console().print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(0)
    except SystemExit:
        raise
    except Exception as exc:
        from rich.console import Console
        from rich.panel import Panel
        con = Console(stderr=True)

        # Collect system context to help with bug reports
        py_ver  = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        os_info = f"{platform.system()} {platform.release()} ({platform.machine()})"
        tb_last = traceback.format_exc().strip().splitlines()
        # Show last 5 lines of traceback — enough context without flooding the screen
        tb_snippet = "\n".join(tb_last[-5:]) if len(tb_last) > 5 else "\n".join(tb_last)

        con.print(Panel(
            f"[bold red]{type(exc).__name__}:[/bold red] {exc}\n\n"
            f"[dim]Python {py_ver}  |  {os_info}[/dim]\n\n"
            f"[dim]{tb_snippet}[/dim]\n\n"
            "[dim]Please report this bug at:\n"
            "  github.com/kiacoder/blackout-kit/issues\n"
            "  (paste the error above)[/dim]",
            title="[bold red]Blackout Kit — Crashed[/bold red]",
            border_style="red",
            padding=(0, 2),
        ))
        sys.exit(1)
