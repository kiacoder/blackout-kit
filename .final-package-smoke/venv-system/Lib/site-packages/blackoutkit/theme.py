"""
Blackout Kit - Visual theme and rich formatting helpers.

Features (Rare):
  - NO_COLOR / CI / non-TTY detection (auto-disables color)
  - confirm()  → interactive yes/no prompt
  - spinner()  → context-manager status spinner
  - error_panel()   / success_panel() / warning_panel()  convenience wrappers
"""
import os
import sys
from contextlib import contextmanager

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table
from rich.text import Text
from rich.theme import Theme
from rich import box

from . import __version__, settings as _cfg

# ──────────────────────────────── Color detection ─────────────────────────────
# Respect NO_COLOR spec (https://no-color.org/) and CI/non-TTY environments.
_no_color: bool = (
    os.environ.get("NO_COLOR") is not None          # explicit opt-out
    or os.environ.get("CI") is not None             # CI pipeline
    or not sys.stdout.isatty()                      # redirected / piped
)

# ─────────────────────────────────── Theme ────────────────────────────────────
_THEME_ACCENTS = {
    "red": "red",
    "blue": "blue",
    "green": "green",
    "purple": "magenta",
}


def build_theme(theme_name: str | None = None, terminal_theme: str | None = None) -> Theme:
    settings = _cfg.load()
    name = (theme_name or settings.get("color_theme", "red")).lower()
    palette = (terminal_theme or settings.get("terminal_theme", "dark")).lower()
    accent = _THEME_ACCENTS.get(name, _THEME_ACCENTS["red"])
    foreground = "black" if palette == "light" else "white"
    muted = "dim black" if palette == "light" else "dim white"
    return Theme({
        "info":         f"bold {accent}",
        "success":      "bold green",
        "warning":      "bold yellow",
        "error":        "bold red",
        "engine":       f"bold {accent}",
        "muted":        muted,
        "accent":       f"bold {accent}",
        "heading":      f"bold {foreground}",
        "panel.title":  f"bold {foreground}",
        "panel.border": accent,
        "table.header": f"bold {accent}",
    })


def is_interactive() -> bool:
    """Return whether prompts can safely read from an interactive terminal."""
    return bool(sys.stdin and sys.stdin.isatty() and sys.stdout and sys.stdout.isatty() and not os.environ.get("CI"))


def ask_choice(prompt: str, choices: list[str], default: str | None = None) -> str | None:
    if not is_interactive():
        return default
    return Prompt.ask(prompt, choices=choices, default=default, console=console)


def ask_text(prompt: str, default: str | None = None) -> str | None:
    if not is_interactive():
        return default
    return Prompt.ask(prompt, default=default, console=console)


def ask_int(prompt: str, default: int | None = None) -> int | None:
    if not is_interactive():
        return default
    return IntPrompt.ask(prompt, default=default, console=console)


console = Console(theme=build_theme(), no_color=_no_color)

_theme_override_active = False


def refresh_console_theme() -> None:
    global _theme_override_active
    if _theme_override_active:
        try:
            console.pop_theme()
        except Exception:
            pass
    console.push_theme(build_theme())
    _theme_override_active = True

# ─────────────────────────────────── Banner ───────────────────────────────────
BANNER = f"""[bold red]
  ██████╗ ██╗      █████╗  ██████╗██╗  ██╗ ██████╗ ██╗   ██╗████████╗
  ██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██╔═══██╗██║   ██║╚══██╔══╝
  ██████╔╝██║     ███████║██║     █████╔╝ ██║   ██║██║   ██║   ██║
  ██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ██║   ██║██║   ██║   ██║
  ██████╔╝███████╗██║  ██║╚██████╗██║  ██╗╚██████╔╝╚██████╔╝   ██║
  ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝  [/bold red]
[bold white]                    ██╗  ██╗██╗████████╗[/bold white]
[bold white]                    ██║ ██╔╝██║╚══██╔══╝[/bold white]
[bold white]                    █████╔╝ ██║   ██║   [/bold white]
[bold white]                    ██╔═██╗ ██║   ██║   [/bold white]
[bold white]                    ██║  ██╗██║   ██║   [/bold white]
[bold white]                    ╚═╝  ╚═╝╚═╝   ╚═╝   [/bold white]
[dim]                     v{__version__} — Network Toolkit[/dim]"""


# ──────────────────────────────── Public helpers ──────────────────────────────

def print_banner():
    from . import settings as _cfg
    s = _cfg.load()
    console.print(Panel(
        BANNER,
        border_style="red",
        padding=(0, 2),
    ))
    if s.get("show_disclaimer", True):
        console.print(Panel(
            "[dim]⚖️  This tool is for [bold white]legitimate personal use only[/bold white] — "
            "to access freely available information and protect your privacy.\n"
            "   Do not use it for illegal activities. "
            "The authors bear no responsibility for any misuse.[/dim]",
            border_style="dim",
            padding=(0, 1),
        ))


def status_panel(title: str, rows: list[tuple[str, str]], border_color: str = "panel.border") -> Panel:
    """Build a status info panel."""
    content = "\n".join(
        f"  [muted]{label:<18}[/muted] {value}"
        for label, value in rows
    )
    return Panel(content, title=f"[panel.title]{title}[/panel.title]", border_style=border_color, padding=(0, 1))


def engine_badge(name: str, running: bool) -> str:
    if running:
        return f"[success]▶ {name}[/success]"
    return f"[muted]○ {name}[/muted]"


def latency_color(ms: float) -> str:
    if ms < 50:
        return f"[success]{ms:.0f}ms ⚡[/success]"
    if ms < 150:
        return f"[warning]{ms:.0f}ms[/warning]"
    return f"[error]{ms:.0f}ms[/error]"


def make_table(title: str, columns: list[tuple[str, str]], rows: list[list[str]]) -> Table:
    """Create a styled table."""
    table = Table(
        title=f"[heading]{title}[/heading]",
        box=box.ROUNDED,
        border_style="muted",
        header_style="table.header",
        show_lines=False,
    )
    for col_name, col_style in columns:
        table.add_column(col_name, style=col_style)
    for row in rows:
        table.add_row(*row)
    return table


# ──────────────────────────── New Rare-tier helpers ───────────────────────────

def error_panel(message: str, title: str = "Error") -> Panel:
    """Return a red error panel — use with console.print()."""
    return Panel(
        f"[error]{message}[/error]",
        title=f"[bold red]{title}[/bold red]",
        border_style="red",
        padding=(0, 1),
    )


def friendly_error_panel(exc: BaseException) -> Panel:
    """Render a safe, actionable failure panel without exposing sensitive details."""
    if isinstance(exc, PermissionError):
        message = "Blackout Kit needs additional permissions for that action. Re-run the command with the required administrator or sudo access."
    elif isinstance(exc, FileNotFoundError):
        message = "A required local file or engine binary is missing. Check installed components with `blackout bins`."
    elif isinstance(exc, (ConnectionError, TimeoutError, OSError)):
        message = "A local or network operation could not complete. Check your connection, then run `blackout doctor` for safe diagnostics."
    else:
        message = "Blackout Kit could not complete that action. Local diagnostic logs may contain technical details."
    return error_panel(
        f"{message}\n\n[muted]Safe next steps: blackout doctor · blackout bins · blackout status[/muted]",
        title="Blackout Kit Error",
    )


def print_friendly_error(exc: BaseException) -> None:
    console.print(friendly_error_panel(exc))


def success_panel(message: str, title: str = "Success") -> Panel:
    """Return a green success panel — use with console.print()."""
    return Panel(
        f"[success]{message}[/success]",
        title=f"[bold green]{title}[/bold green]",
        border_style="green",
        padding=(0, 1),
    )


def warning_panel(message: str, title: str = "Warning") -> Panel:
    """Return a yellow warning panel — use with console.print()."""
    return Panel(
        f"[warning]{message}[/warning]",
        title=f"[bold yellow]{title}[/bold yellow]",
        border_style="yellow",
        padding=(0, 1),
    )


def confirm(question: str, default: bool = False) -> bool:
    """Prompt for confirmation only when stdin and stdout are interactive."""
    if not is_interactive():
        return default
    return Confirm.ask(f"[bold]{question}[/bold]", default=default, console=console)


@contextmanager
def spinner(description: str = "Working…"):
    """
    Context manager that shows a Rich status spinner while the block runs.

    Usage:
        with spinner("Scanning IPs…"):
            do_work()
    """
    with console.status(f"[muted]{description}[/muted]", spinner="dots"):
        yield


def create_download_progress():
    """Create a standardized rich Progress instance for downloads."""
    from rich.progress import (
        Progress, SpinnerColumn, TextColumn, BarColumn, 
        DownloadColumn, TransferSpeedColumn, TimeRemainingColumn
    )
    return Progress(
        SpinnerColumn(style="bold cyan"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=38, style="cyan", complete_style="green"),
        DownloadColumn(),
        TransferSpeedColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=True,
    )
