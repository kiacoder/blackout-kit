"""
Enhanced CLI features: typo suggestions, help integration, group menus.
"""
from __future__ import annotations

import sys
from typing import Optional

import typer

from .cli_navigator import get_navigator
from .cli_dispatch import ProfessionalCLIGroup, make_group_callback
from .theme import console, is_interactive


def integrate_navigator_into_typer_app(app: typer.Typer, dispatcher: ProfessionalCLIGroup) -> None:
    """Integrate the professional CLI navigator into an existing Typer app."""

    # Add 'help' command for interactive command browser
    @app.command("help", hidden=True)
    def show_help_interactive(
        command: Optional[str] = typer.Argument(
            None,
            help="Specific command to get help for (or leave blank to browse)",
        ),
    ):
        """Show help for commands interactively."""
        if command:
            dispatcher.show_help(command)
        else:
            if is_interactive():
                chosen = dispatcher.navigator.show_command_browser()
                if chosen:
                    dispatcher.show_help(chosen)
            else:
                dispatcher.show_help(None)

    # Add 'commands' command to list all
    @app.command("commands", hidden=True)
    def list_all_commands():
        """List all available commands."""
        dispatcher.show_help(None)

    # Add 'quickstart' command
    @app.command("quickstart", hidden=True)
    def show_quickstart():
        """Show a quick-start guide."""
        dispatcher.show_quick_start()


def add_group_callback(group: typer.Typer, group_name: str, dispatcher: ProfessionalCLIGroup) -> None:
    """Add a professional callback to a command group."""
    group.callback(invoke_without_command=True)(
        make_group_callback(group_name, dispatcher)
    )


def enhance_typer_error_handling(app: typer.Typer) -> None:
    """Enable professional error handling (currently a no-op to avoid patching console.print)."""
    # Note: Typo suggestions and error formatting are handled by cli_dispatch.py
    # without patching console.print, which preserves normal output integrity.
    pass


def validate_and_suggest_args(
    command_name: str,
    *,
    min_args: int = 0,
    max_args: Optional[int] = None,
    examples: Optional[list[str]] = None,
) -> None:
    """Decorator helper to validate command arguments with suggestions."""

    def decorator(func):
        def wrapper(*args, **kwargs):
            # Count positional args (rough heuristic)
            actual_args = len([a for a in args if not isinstance(a, (dict, typer.Context))])

            if actual_args < min_args:
                console.print(
                    f"[red]✗ {command_name} requires at least {min_args} argument(s)[/red]"
                )
                if examples:
                    console.print("[yellow]Examples:[/yellow]")
                    for ex in examples:
                        console.print(f"  [dim]$[/dim] [cyan]{ex}[/cyan]")
                raise typer.Exit(1)

            if max_args is not None and actual_args > max_args:
                console.print(
                    f"[red]✗ {command_name} accepts at most {max_args} argument(s)[/red]"
                )
                raise typer.Exit(1)

            return func(*args, **kwargs)

        return wrapper

    return decorator


class SmartHelpFormatter:
    """Format help text with examples and related commands."""

    @staticmethod
    def format_command_help(
        description: str,
        *,
        details: Optional[str] = None,
        examples: Optional[list[str]] = None,
        related: Optional[list[str]] = None,
        options_note: Optional[str] = None,
    ) -> str:
        """Create a formatted help string with standard sections."""
        parts = [description]

        if details:
            parts.append(f"\n{details}")

        if examples:
            parts.append("\nExamples:")
            for example in examples:
                parts.append(f"  $ {example}")

        if related:
            parts.append("\nRelated commands:")
            for cmd in related:
                parts.append(f"  • {cmd}")

        if options_note:
            parts.append(f"\n{options_note}")

        return "\n".join(parts)

    @staticmethod
    def format_group_help(
        group_name: str,
        description: str,
        subcommands: dict[str, str],
        *,
        intro: Optional[str] = None,
    ) -> str:
        """Create a formatted help string for a command group."""
        parts = [f"{description}"]

        if intro:
            parts.append(f"\n{intro}")

        parts.append(f"\nSubcommands of '{group_name}':")
        for cmd_name, cmd_desc in sorted(subcommands.items()):
            parts.append(f"  {cmd_name:<20} {cmd_desc}")

        parts.append(f"\nUsage: blackout {group_name} <subcommand> [OPTIONS]")
        parts.append("Run 'blackout help' to browse all commands interactively.")

        return "\n".join(parts)


# Monkey-patch helpers for existing code
def make_typo_tolerant(app: typer.Typer) -> None:
    """Make the app tolerant of command typos with suggestions."""
    enhance_typer_error_handling(app)


def add_help_system(app: typer.Typer, dispatcher: ProfessionalCLIGroup) -> None:
    """Add comprehensive help system to the app."""
    integrate_navigator_into_typer_app(app, dispatcher)


def create_smart_group(
    name: str,
    help: str,
    dispatcher: Optional[ProfessionalCLIGroup] = None,
) -> typer.Typer:
    """Create a command group with smart help and navigation."""
    group = typer.Typer(name=name, help=help, no_args_is_help=False)

    if dispatcher:
        add_group_callback(group, name, dispatcher)

    return group
