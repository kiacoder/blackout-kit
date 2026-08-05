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
