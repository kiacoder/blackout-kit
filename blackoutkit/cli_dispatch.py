"""
CLI error handling and command dispatch with professional UX.
"""
from __future__ import annotations

import sys
import traceback
from typing import Any, Callable, Optional

import typer
from rich.panel import Panel

from .cli_navigator import get_navigator
from .theme import console


class ProfessionalCLIGroup:
    """Wraps a Typer group to add professional error handling and suggestions."""

    def __init__(self, app: typer.Typer):
        self.app = app
        self.navigator = get_navigator()

    def handle_command_error(self, command_name: str, error: Exception) -> None:
        """Display a professional error message with suggestions."""
        error_str = str(error)

        # Don't show traceback for expected errors (user input, validation)
        if isinstance(error, (typer.BadParameter, typer.BadArgumentUsage, ValueError)):
            console.print(f"[red]✗ {error_str}[/red]")
            return

        # For unexpected errors, show brief message with tip
        console.print(
            Panel(
                f"[red]✗ Command failed: {command_name}[/red]\n\n"
                f"{error_str}\n\n"
                f"[dim]Run[/dim] [cyan]blackout {command_name} --help[/cyan] [dim]for details[/dim]",
                border_style="red",
            )
        )

    def handle_unknown_command(self, command_name: str) -> None:
        """Handle user typing an unknown command with helpful suggestions."""
        self.navigator.handle_command_not_found(command_name)

    def handle_missing_subcommand(self, group_name: str) -> None:
        """When user types 'blackout config' with no subcommand, show interactive menu."""
        console.print()  # Blank line for spacing
        chosen = self.navigator.show_group_browser(group_name)

        if chosen:
            console.print(f"\n[cyan]→ blackout {group_name} {chosen}[/cyan]\n")
            # In a real implementation, would dispatch to the chosen command
            # For now, just show what would run
        else:
            console.print("[dim](Cancelled)[/dim]")

    def show_help(self, command_name: str | None = None) -> None:
        """Show help for a command or list all commands."""
        if command_name:
            self.navigator.show_command_help(command_name)
        else:
            self.navigator.show_all_commands()

    def show_quick_start(self) -> None:
        """Show quick-start guide."""
        self.navigator.show_quick_start()


def create_professional_app(
    name: str = "blackout",
    help: str = "Blackout Kit — Universal VPN/proxy bypass utility",
    no_args_is_help: bool = True,
) -> tuple[typer.Typer, ProfessionalCLIGroup]:
    """Create a Typer app with professional CLI features."""
    app = typer.Typer(
        name=name,
        help=help,
        no_args_is_help=no_args_is_help,
        pretty_exceptions_show_locals=False,  # Don't dump local vars on error
    )

    dispatcher = ProfessionalCLIGroup(app)

    # Register exception handler
    original_invoke = app.command

    def command_with_error_handling(*args, **kwargs):
        def decorator(func):
            def wrapper(*cmd_args, **cmd_kwargs):
                try:
                    return func(*cmd_args, **cmd_kwargs)
                except Exception as e:
                    if isinstance(e, (typer.Exit, KeyboardInterrupt, SystemExit)):
                        raise
                    dispatcher.handle_command_error(func.__name__, e)
                    raise typer.Exit(1)

            return original_invoke(*args, **kwargs)(wrapper)

        return decorator

    return app, dispatcher


def make_group_callback(
    group_name: str,
    dispatcher: ProfessionalCLIGroup,
) -> Callable:
    """Create a callback for a command group that shows interactive menu on no args."""

    def callback(ctx: typer.Context) -> None:
        # If a subcommand was provided, let it run
        if ctx.invoked_subcommand is not None:
            return

        # No subcommand → show interactive menu
        if sys._stdin.isatty() if hasattr(sys, '_stdin') else sys.stdin.isatty():
            dispatcher.handle_missing_subcommand(group_name)
        else:
            # Non-interactive mode: show help
            dispatcher.show_help(group_name)

    return callback


def suggest_command_on_typo(app: typer.Typer, argv: list[str]) -> None:
    """Pre-process command line to suggest typos before Typer processes them."""
    if len(argv) < 2:
        return

    # Check if first arg after 'blackout' looks like a command
    potential_command = argv[1]
    if potential_command.startswith('-'):
        return

    navigator = get_navigator()
    suggestion = navigator.suggest_command(potential_command)

    if suggestion and suggestion != potential_command:
        # Silently replace the typo (Typer will handle it)
        argv[1] = suggestion


# Example: Enhanced error messages for common mistakes
HELPFUL_ERRORS = {
    "Missing argument": "Required argument missing. Run with --help to see expected format.",
    "No such command": "Unknown command. Run 'blackout commands' to list all available commands.",
    "Invalid value": "Invalid argument value. Check --help for accepted values.",
}


def format_typer_error(error: Exception) -> str:
    """Format Typer exceptions with helpful suggestions."""
    error_str = str(error)

    for pattern, suggestion in HELPFUL_ERRORS.items():
        if pattern.lower() in error_str.lower():
            return f"{error_str}\n\n[yellow]💡 {suggestion}[/yellow]"

    return error_str
