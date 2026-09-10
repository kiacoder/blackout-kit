"""Progress indicators and spinners for long-running operations."""
from __future__ import annotations

import sys
import time
import threading
from contextlib import contextmanager
from typing import Optional, Generator

from .theme import console


class Spinner:
    """Simple ASCII spinner for long operations."""

    FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    FRAMES_ALT = ["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"]
    FRAMES_SIMPLE = ["|", "/", "-", "\\"]

    def __init__(self, message: str = "Loading", frame_set: str = "braille"):
        """
        Initialize spinner.

        Args:
            message: Message to display while spinning
            frame_set: "braille" (fancy), "alt" (medium), or "simple" (basic)
        """
        self.message = message
        self.running = False
        self.thread = None

        if frame_set == "alt":
            self.frames = self.FRAMES_ALT
        elif frame_set == "simple":
            self.frames = self.FRAMES_SIMPLE
        else:
            self.frames = self.FRAMES

    def start(self) -> None:
        """Start the spinner in a background thread."""
        if self.running:
            return

        self.running = True
        self.thread = threading.Thread(target=self._spin, daemon=True)
        self.thread.start()

    def stop(self, final_message: Optional[str] = None) -> None:
        """Stop the spinner and display a final message."""
        if not self.running:
            return

        self.running = False
        if self.thread:
            self.thread.join(timeout=1)

        # Clear the spinner line
        sys.stdout.write("\r" + " " * 80 + "\r")
        sys.stdout.flush()

        if final_message:
            console.print(final_message)

    def _spin(self) -> None:
        """Spin loop (runs in background thread)."""
        idx = 0
        while self.running:
            frame = self.frames[idx % len(self.frames)]
            sys.stdout.write(f"\r{frame} {self.message}")
            sys.stdout.flush()
            idx += 1
            time.sleep(0.1)


@contextmanager
def spinner(message: str = "Loading", *, final_success: Optional[str] = None) -> Generator[Spinner, None, None]:
    """
    Context manager for showing a spinner during a block of code.

    Usage:
        with spinner("Connecting...") as spin:
            do_something_slow()
        # Spinner stops and clears automatically
    """
    s = Spinner(message)
    s.start()
    try:
        yield s
    finally:
        s.stop(final_success or f"✓ {message.rstrip('.')} complete")


@contextmanager
def progress_message(message: str) -> Generator[None, None, None]:
    """
    Context manager for displaying a status message that clears when done.

    Usage:
        with progress_message("Checking configuration..."):
            validate_config()
    """
    console.print(f"[cyan]{message}[/cyan]", end="", flush=True)
    try:
        yield
    finally:
        # Clear the line
        console.print("\r" + " " * len(message) + "\r", end="", flush=True)


def show_status(message: str, status: str = "✓", color: str = "green") -> None:
    """Display a status message with icon and color."""
    if color == "green":
        console.print(f"[{color}]✓[/{color}] {message}")
    elif color == "yellow":
        console.print(f"[{color}]⚠[/{color}] {message}")
    elif color == "red":
        console.print(f"[{color}]✗[/{color}] {message}")
    else:
        console.print(f"[{color}]{status}[/{color}] {message}")


def show_success(message: str) -> None:
    """Display a success message."""
    show_status(message, status="✓", color="green")


def show_warning(message: str) -> None:
    """Display a warning message."""
    show_status(message, status="⚠", color="yellow")


def show_error(message: str) -> None:
    """Display an error message."""
    show_status(message, status="✗", color="red")
