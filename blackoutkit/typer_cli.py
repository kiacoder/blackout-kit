"""
Blackout Kit - Modern Typer CLI (Migration in Progress).
This will eventually replace cli.py.
"""
import sys
import typer
from rich.console import Console

from . import __version__
from .theme import console, error_panel

app = typer.Typer(
    name="blackout",
    help="Blackout Kit — DPI Bypass & Censorship Circumvention Toolkit",
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich"
)

# We will gradually port commands from cli.py into here.

@app.command()
def version():
    """Show the Blackout Kit version."""
    console.print(f"blackout-kit [bold green]{__version__}[/bold green]")

@app.command()
def fix():
    """Auto-fix DNS / Winsock / TCP/IP and clear system proxy"""
    from .cli import cmd_fix
    class DummyArgs: pass
    cmd_fix(DummyArgs())

@app.command()
def scan(
    ips: bool = typer.Option(False, "--ips", help="Scan Cloudflare IPs"),
    sni: bool = typer.Option(False, "--sni", help="Scan fake SNI domains"),
    count: int = typer.Option(None, "--count", "-c", help="Number of IPs to generate")
):
    """Scan Cloudflare IPs and fake SNI domains"""
    from .cli import cmd_scan
    class DummyArgs:
        pass
    
    args = DummyArgs()
    args.ips = ips
    args.sni = sni
    args.count = count
    
    cmd_scan(args)

@app.command()
def connect(
    pos_engine: str = typer.Argument(None, help="Engine to use (e.g. sni, gdpi, psiphon, auto)"),
    engine: str = typer.Option(None, "--engine", help="Engine to use"),
    background: bool = typer.Option(False, "--background", "-d", help="Run as background daemon"),
    iran: bool = typer.Option(False, "--iran", help="🔥 TIC 2026 evasion profile")
):
    """Smart connect — auto-preps and starts the best engine"""
    from rich.prompt import Prompt
    from .cli import ALL_ENGINE_CHOICES
    
    # Interactive mode if engine is missing
    final_engine = pos_engine or engine
    if not final_engine:
        console.print()
        final_engine = Prompt.ask(
            "⚡ Select an engine to connect with",
            choices=ALL_ENGINE_CHOICES,
            default="auto"
        )
        console.print()
        
    from .cli import cmd_connect
    class DummyArgs: pass
    args = DummyArgs()
    args.pos_engine = final_engine
    args.engine = None
    args.background = background
    args.iran = iran
    
    cmd_connect(args)

@app.command()
def mode(
    mode_name: str = typer.Argument(None, help="speed | private | legend (omit to interactively select)")
):
    """View or set security mode"""
    from rich.prompt import Prompt
    from .cli import cmd_mode
    
    if not mode_name:
        console.print()
        mode_name = Prompt.ask(
            "🛡️ Select a security mode",
            choices=["speed", "private", "legend"]
        )
        console.print()
        
    class DummyArgs: pass
    args = DummyArgs()
    args.mode_name = mode_name
    cmd_mode(args)

@app.command()
def killswitch(
    action: str = typer.Argument(None, help="on | off | test (omit to interactively select)")
):
    """Enable/disable kill switch (blocks net if proxy drops)"""
    from rich.prompt import Prompt
    from .cli import cmd_killswitch
    
    if not action:
        console.print()
        action = Prompt.ask(
            "☠️ Select killswitch action",
            choices=["on", "off", "test"]
        )
        console.print()
        
    class DummyArgs: pass
    args = DummyArgs()
    args.action = action
    cmd_killswitch(args)

def main():
    """Global entry point for the new Typer CLI."""
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[muted]Operation cancelled by user.[/muted]")
        sys.exit(130)
    except Exception as e:
        import traceback
        console.print(error_panel(
            f"An unexpected fatal error occurred:\n{str(e)}\n\n[dim]Please run 'blackout doctor' to auto-fix common issues.[/dim]",
            title="Fatal Error"
        ))
        sys.exit(1)

if __name__ == "__main__":
    main()
