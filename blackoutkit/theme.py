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
from rich.prompt import Confirm
from rich.table import Table
from rich.text import Text
from rich.theme import Theme
from rich import box

from . import __version__

# ──────────────────────────────── Color detection ─────────────────────────────
# Respect NO_COLOR spec (https://no-color.org/) and CI/non-TTY environments.
_no_color: bool = (
    os.environ.get("NO_COLOR") is not None          # explicit opt-out
    or os.environ.get("CI") is not None             # CI pipeline
    or not sys.stdout.isatty()                      # redirected / piped
)

# ─────────────────────────────────── Theme ────────────────────────────────────
BLACKOUT_THEME = Theme({
    "info":     "bold cyan",
    "success":  "bold green",
    "warning":  "bold yellow",
    "error":    "bold red",
    "engine":   "bold magenta",
    "muted":    "dim white",
    "accent":   "bold red",
    "heading":  "bold white",
})

console = Console(theme=BLACKOUT_THEME, no_color=_no_color)

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
[dim]                     v{__version__} — DPI Bypass & Freedom Toolkit[/dim]"""


# ──────────────────────────────── Public helpers ──────────────────────────────

def print_banner():
    console.print(Panel(
        BANNER,
        border_style="red",
        padding=(0, 2),
    ))
    console.print(Panel(
        "[dim]⚖️  This tool is for [bold white]legitimate personal use only[/bold white] — "
        "to access freely available information and protect your privacy.\n"
        "   Do not use it for illegal activities. "
        "The authors bear no responsibility for any misuse.[/dim]",
        border_style="dim",
        padding=(0, 1),
    ))


def status_panel(title: str, rows: list[tuple[str, str]], border_color: str = "cyan") -> Panel:
    """Build a status info panel."""
    content = "\n".join(
        f"  [muted]{label:<18}[/muted] {value}"
        for label, value in rows
    )
    return Panel(content, title=f"[bold]{title}[/bold]", border_style=border_color, padding=(0, 1))


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
        title=f"[bold]{title}[/bold]",
        box=box.ROUNDED,
        border_style="dim",
        header_style="bold cyan",
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
    """
    Prompt the user for yes/no confirmation.
    Falls back to the default value when running non-interactively (CI/pipe).
    """
    if _no_color:
        # Non-interactive: return default silently
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
