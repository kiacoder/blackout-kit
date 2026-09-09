"""
Professional CLI navigation system for Blackout Kit.
Features: typo suggestions, interactive group browsers, command discovery.
"""
from __future__ import annotations

import difflib
import sys
from dataclasses import dataclass
from typing import Any, Callable, Optional

from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from .terminal_menu import MenuItem, run_menu
from .theme import console


@dataclass
class CommandInfo:
    """Metadata about a CLI command."""
    name: str
    description: str
    category: str
    subcommands: dict[str, CommandInfo] | None = None
    aliases: list[str] | None = None
    examples: list[str] | None = None
    help_text: str | None = None


class CLINavigator:
    """Smart command navigation with discovery and error handling."""

    def __init__(self):
        self.commands: dict[str, CommandInfo] = {}
        self.category_groups: dict[str, list[CommandInfo]] = {}

    def register_command(
        self,
        name: str,
        description: str,
        category: str,
        aliases: list[str] | None = None,
        examples: list[str] | None = None,
        help_text: str | None = None,
    ) -> None:
        """Register a top-level command."""
        cmd = CommandInfo(
            name=name,
            description=description,
            category=category,
            aliases=aliases or [],
            examples=examples or [],
            help_text=help_text,
        )
        self.commands[name] = cmd

        if category not in self.category_groups:
            self.category_groups[category] = []
        self.category_groups[category].append(cmd)

    def register_group_commands(
        self,
        group_name: str,
        group_description: str,
        subcommands: dict[str, tuple[str, list[str]]],  # name -> (desc, examples)
    ) -> None:
        """Register a command group (e.g., 'config' with 'list', 'add', 'remove')."""
        if group_name not in self.commands:
            self.register_command(
                name=group_name,
                description=group_description,
                category="Groups",
            )

        sub_commands = {}
        for cmd_name, (cmd_desc, examples) in subcommands.items():
            sub_cmd = CommandInfo(
                name=cmd_name,
                description=cmd_desc,
                category=group_name,
                examples=examples,
            )
            sub_commands[cmd_name] = sub_cmd

        self.commands[group_name].subcommands = sub_commands

    def suggest_command(self, typed: str, cutoff: float = 0.6) -> str | None:
        """Suggest a command name if user made a typo."""
        all_commands = list(self.commands.keys())

        for cmd_info in self.commands.values():
            if cmd_info.aliases:
                all_commands.extend(cmd_info.aliases)

        matches = difflib.get_close_matches(typed, all_commands, n=1, cutoff=cutoff)
        return matches[0] if matches else None

    def show_command_browser(self) -> str | None:
        """Launch interactive command browser."""
        items = []
        for cmd_name, cmd_info in sorted(self.commands.items()):
            items.append(
                MenuItem(
                    key=cmd_name,
                    label=f"[bold]{cmd_name}[/bold]",
                    description=cmd_info.description,
                )
            )

        if not items:
            console.print("[yellow]No commands available[/yellow]")
            return None

        chosen = run_menu(items, title="Available Commands", guide="↑↓ Navigate    Enter Select    Esc Exit")
        return chosen.key if chosen else None

    def show_group_browser(self, group_name: str) -> str | None:
        """Launch interactive browser for a command group (e.g., 'blackout config')."""
        group_cmd = self.commands.get(group_name)
        if not group_cmd or not group_cmd.subcommands:
            return None

        items = []
        for sub_name, sub_info in sorted(group_cmd.subcommands.items()):
            items.append(
                MenuItem(
                    key=sub_name,
                    label=f"[cyan]{sub_name}[/cyan]",
                    description=sub_info.description,
                )
            )

        if not items:
            return None

        chosen = run_menu(
            items,
            title=f"[bold]{group_name}[/bold] — {group_cmd.description}",
            guide="↑↓ Navigate    Enter Select    Esc Back",
        )
        return chosen.key if chosen else None

    def show_command_help(self, command_name: str) -> None:
        """Display comprehensive help for a command."""
        cmd = self.commands.get(command_name)
        if not cmd:
            console.print(f"[red]Unknown command: {command_name}[/red]")
            return

        # Header
        console.print(f"\n[bold cyan]{command_name}[/bold cyan]")
        console.print(f"[dim]{cmd.description}[/dim]\n")

        # Help text if available
        if cmd.help_text:
            console.print(cmd.help_text)
            console.print()

        # Subcommands if this is a group
        if cmd.subcommands:
            table = Table(title="Subcommands", show_header=True, highlight=True)
            table.add_column("Command", style="cyan", width=20)
            table.add_column("Description", style="white")

            for sub_name, sub_info in sorted(cmd.subcommands.items()):
                table.add_row(sub_name, sub_info.description)

            console.print(table)
            console.print()

        # Examples
        if cmd.examples:
            console.print("[bold]Examples:[/bold]")
            for example in cmd.examples:
                console.print(f"  [dim]$[/dim] [yellow]{example}[/yellow]")
            console.print()

        # Related commands
        if cmd.category != "Groups":
            related = self.category_groups.get(cmd.category, [])
            if len(related) > 1:
                console.print("[bold]Related commands:[/bold]")
                for rel_cmd in related:
                    if rel_cmd.name != command_name:
                        console.print(f"  [cyan]{rel_cmd.name}[/cyan] — {rel_cmd.description}")
                console.print()

    def show_all_commands(self) -> None:
        """Display all available commands organized by category."""
        console.print("\n[bold]Blackout Kit Commands[/bold]\n")

        for category in sorted(self.category_groups.keys()):
            commands = self.category_groups[category]
            console.print(f"[bold]{category}[/bold]")

            for cmd in sorted(commands, key=lambda c: c.name):
                aliases_str = f" ({', '.join(cmd.aliases)})" if cmd.aliases else ""
                console.print(f"  [cyan]{cmd.name}{aliases_str}[/cyan] — {cmd.description}")

            console.print()

    def handle_command_not_found(self, command_name: str) -> None:
        """Handle user typing an unknown command with helpful suggestions."""
        suggestion = self.suggest_command(command_name, cutoff=0.5)

        error_panel = f"[red]✗ Unknown command: {command_name}[/red]"
        if suggestion:
            error_panel += f"\n\n[yellow]Did you mean:[/yellow]\n  [cyan]blackout {suggestion}[/cyan]"

        error_panel += "\n\n[dim]Run[/dim] [cyan]blackout --help[/cyan] [dim]for command list[/dim]"

        console.print(Panel(error_panel, border_style="red"))

    def show_quick_start(self) -> None:
        """Show a quick-start guide for new users."""
        guide = """
[bold cyan]Blackout Kit — Quick Start[/bold cyan]

[bold]Common Commands:[/bold]

  [cyan]blackout connect sni[/cyan]           Start VPN with SNI engine
  [cyan]blackout config list[/cyan]          Show saved proxy configs
  [cyan]blackout config add[/cyan]           Add a new proxy configuration
  [cyan]blackout doctor[/cyan]               Run diagnostics
  [cyan]blackout help [command][/cyan]       Show help for any command

[bold]Interactive Menus:[/bold]

Just type the group name to browse interactively:
  [cyan]blackout config[/cyan]              Browse configurations
  [cyan]blackout tools[/cyan]               Browse network tools
  [cyan]blackout settings[/cyan]            Browse settings

[bold]Tips:[/bold]

  • Use [cyan]--help[/cyan] flag for detailed info on any command
  • Type [cyan]?[/cyan] during menus to show help
  • Commands support [cyan]--json[/cyan] for scripting
  • Press [cyan]Tab[/cyan] for command auto-completion (enable with [cyan]blackout --install-completion[/cyan])

[dim]For more info: blackout --help[/dim]
"""
        console.print(guide)


# Global navigator instance
_navigator: CLINavigator | None = None


def get_navigator() -> CLINavigator:
    """Get or create the global CLI navigator."""
    global _navigator
    if _navigator is None:
        _navigator = CLINavigator()
        _register_default_commands()
    return _navigator


def _register_default_commands() -> None:
    """Register default Blackout Kit commands."""
    nav = _navigator or CLINavigator()

    # Top-level commands
    nav.register_command(
        "connect",
        "Start a VPN connection with specified engine",
        "Connection Management",
        aliases=["c", "start"],
        examples=[
            "blackout connect",
            "blackout connect sni",
            "blackout connect --iran",
        ],
        help_text="Start the daemon with a specified engine. Supports auto-detection.",
    )

    nav.register_command(
        "disconnect",
        "Stop the active VPN connection",
        "Connection Management",
        aliases=["d", "stop"],
        examples=["blackout disconnect"],
    )

    nav.register_command(
        "status",
        "Show current daemon and VPN status",
        "Connection Management",
        examples=["blackout status", "blackout status --watch"],
    )

    nav.register_command(
        "doctor",
        "Run diagnostic checks and fix issues",
        "Maintenance",
        examples=["blackout doctor", "blackout doctor --fix"],
    )

    nav.register_command(
        "logs",
        "Show daemon operation logs",
        "Maintenance",
        examples=["blackout logs --lines 50", "blackout logs --follow"],
    )

    # Config group
    nav.register_group_commands(
        "config",
        "Manage proxy configurations",
        {
            "list": ("Show all saved configurations", ["blackout config list"]),
            "add": ("Add a new proxy configuration", ["blackout config add"]),
            "remove": ("Remove a configuration", ["blackout config remove 1"]),
            "import": ("Import from a subscription URL", ["blackout config import <url>"]),
            "validate": ("Check if configs are valid", ["blackout config validate"]),
            "export": ("Export all configs", ["blackout config export"]),
        },
    )

    # Settings group
    nav.register_group_commands(
        "settings",
        "Configure application settings",
        {
            "list": ("Show all settings", ["blackout settings list"]),
            "set": ("Change a setting", ["blackout settings set kill_switch true"]),
            "reset": ("Reset all settings to defaults", ["blackout settings reset"]),
        },
    )

    # Tools group
    nav.register_group_commands(
        "tools",
        "Network diagnostics and utilities",
        {
            "dns-bench": ("Benchmark DNS servers", ["blackout tools dns-bench"]),
            "dns-flush": ("Clear DNS cache", ["blackout tools dns-flush"]),
            "dns-set": ("Set custom DNS", ["blackout tools dns-set 8.8.8.8"]),
            "ping": ("Test reachability", ["blackout tools ping example.com"]),
            "netfix": ("Run network recovery", ["blackout tools netfix"]),
            "hotspot": ("Toggle mobile hotspot", ["blackout tools hotspot"]),
        },
    )

    # Help/Info commands
    nav.register_command(
        "help",
        "Show help for any command or browse commands interactively",
        "Info",
        aliases=["?"],
        examples=["blackout help", "blackout help config", "blackout help config add"],
    )

    nav.register_command(
        "commands",
        "List all available commands",
        "Info",
        examples=["blackout commands"],
    )

    nav.register_command(
        "version",
        "Show version information",
        "Info",
        examples=["blackout version"],
    )
