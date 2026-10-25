# blackoutkit/tui/screens/_worker.py
"""Shared background-run helper and allowlisted CLI capture path."""
from __future__ import annotations

import io
import threading
from typing import Callable

from rich.console import Console

from blackoutkit import cli as cli_mod

_console_lock = threading.Lock()


def run_bg(
    screen,
    fn: Callable[[], str],
    on_done: Callable[[str], None],
    *,
    group: str = "tools",
) -> None:
    """Run fn() in a worker thread; deliver str result to on_done on the UI thread.

    exclusive=True: re-triggering the same group cancels any previous run in that group.
    """

    def deliver(text: str) -> None:
        screen.app.call_from_thread(on_done, text)

    def operation() -> None:
        try:
            deliver(str(fn()))
        except Exception as exc:  # noqa: BLE001
            deliver(f"error: {exc}")

    screen.run_worker(operation, thread=True, exclusive=True, group=group, exit_on_error=False)


def capture_cli(command: str, *args: str) -> str:
    """Capture one of the allowlisted, non-mutating CLI diagnostic/tool paths.

    The cli_mod.console global swap is process-wide, so concurrent worker threads
    serialize on _console_lock (reentrancy safe).
    """
    buffer = io.StringIO()
    with _console_lock:
        original_console = cli_mod.console
        cli_mod.console = Console(file=buffer, force_terminal=False, width=100)
        try:
            if command == "doctor":
                cli_args = cli_mod._make_fake_args(local_only=True, include_optional=False)
                cli_mod.cmd_doctor(cli_args)
            elif command == "fix_preview":
                cli_args = cli_mod._make_fake_args(
                    preview=True,
                    full_route_reset=False,
                    full_stack_reset=False,
                    flush_arp=False,
                    history=False,
                    history_lines=20,
                )
                cli_mod.cmd_fix(cli_args)
            elif command == "tools_ping":
                target = args[0] if args else "1.1.1.1"
                cli_args = cli_mod._make_fake_args(tools_command="ping", host=target)
                cli_mod.cmd_tools(cli_args)
            elif command == "tools_speedtest":
                cli_args = cli_mod._make_fake_args(tools_command="speedtest")
                cli_mod.cmd_tools(cli_args)
            else:
                raise ValueError(f"Unsupported capture command: {command!r}")
        finally:
            cli_mod.console = original_console
    return buffer.getvalue()
