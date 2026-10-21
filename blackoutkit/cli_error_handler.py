"""Central error formatting helper for Blackout Kit CLI."""
from __future__ import annotations

from typing import Optional
from rich.console import Console
from rich.markup import escape

_console = Console(stderr=True)


def format_error(
    summary: str,
    reason: Optional[str] = None,
    hint: Optional[str] = None,
    *,
    console: Optional[Console] = None,
    exit_code: int = 1,
    json_output: bool = False,
) -> int:
    """
    Format and output standardized CLI errors.

    Format:
    Error: <what failed>
    Reason: <specific issue/missing field/detail>
    Hint: Run 'blackout <cmd> --help' for details
    """
    target_console = console or _console

    if json_output:
        from blackoutkit.cli_output import emit_error
        msg = summary
        if reason:
            msg += f" - {reason}"
        if hint:
            msg += f" ({hint})"
        return emit_error("cli_error", msg, console=target_console, exit_code=exit_code, json_output=True)

    # summary/reason/hint are frequently built from exception text, which can
    # contain '[...]' tokens. Rich would interpret those as markup (e.g. a
    # "[socks]" in a message would be silently swallowed, or "[red]" would
    # inject colour), so escape them before interpolation.
    target_console.print(f"[bold red]Error:[/bold red] {escape(summary)}")
    if reason:
        target_console.print(f"[yellow]Reason:[/yellow] {escape(reason)}")
    if hint:
        target_console.print(f"[cyan]Hint:[/cyan] {escape(hint)}")

    return exit_code


def handle_cli_exception(
    exc: Exception,
    command_name: str,
    *,
    reason: Optional[str] = None,
    console: Optional[Console] = None,
    exit_code: int = 1,
    json_output: bool = False,
) -> int:
    """Convenience handler to wrap an exception into the standard format."""
    summary = f"Command '{command_name}' failed: {exc}"
    derived_reason = reason or str(exc)
    hint = f"blackout {command_name} --help"
    return format_error(
        summary=summary,
        reason=derived_reason,
        hint=hint,
        console=console,
        exit_code=exit_code,
        json_output=json_output,
    )
