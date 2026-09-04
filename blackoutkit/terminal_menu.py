"""
Blackout Kit - Cross-platform keyboard-navigable terminal menu primitives.

Provides a single reusable building block (`run_menu`) used by the
zero-argument launcher chooser and the interactive CLI menus. Reading raw
keys is isolated in `KeyReader` so callers/tests can inject a canned
sequence of `Key` values instead of touching a real terminal.
"""
import sys
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum, auto

from rich import box
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from .theme import console, is_interactive


class Key(Enum):
    UP = auto()
    DOWN = auto()
    LEFT = auto()
    RIGHT = auto()
    SPACE = auto()
    ENTER = auto()
    ESCAPE = auto()
    CTRL_C = auto()
    BACKSPACE = auto()
    OTHER = auto()


DEFAULT_GUIDE = "[muted]↑↓ Move    Type to filter    Backspace Edit    →/Space/Enter Select    ←/Esc Back    Ctrl+C Quit[/muted]"


@dataclass
class MenuItem:
    key: str
    label: str
    description: str = ""
    enabled: bool = True


class KeyReader:
    """Reads a single logical Key from the real terminal, one platform branch at a time."""

    def read_key(self) -> Key:
        if sys.platform == "win32":
            return self._read_windows()
        return self._read_posix()

    def _read_windows(self) -> Key:
        import msvcrt

        ch = msvcrt.getch()
        if ch in (b"\x00", b"\xe0"):
            arrow = msvcrt.getch()
            return {
                b"H": Key.UP,
                b"P": Key.DOWN,
                b"K": Key.LEFT,
                b"M": Key.RIGHT,
            }.get(arrow, Key.OTHER)
        if ch == b"\r":
            return Key.ENTER
        if ch == b" ":
            return Key.SPACE
        if ch in (b"\x08", b"\x7f"):
            return Key.BACKSPACE
        if ch == b"\x1b":
            return Key.ESCAPE
        if ch == b"\x03":
            return Key.CTRL_C
        return Key.OTHER

    def _read_posix_input(self) -> tuple[Key, str | None]:
        import select
        import termios
        import tty

        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            ch = sys.stdin.read(1)
            if ch == "\x1b":
                if not select.select([sys.stdin], [], [], 0.05)[0]:
                    return Key.ESCAPE, None

                sequence = sys.stdin.read(1)
                if sequence != "[":
                    return Key.OTHER, None

                final = sys.stdin.read(1)
                if final in "ABCD":
                    return {
                        "A": Key.UP,
                        "B": Key.DOWN,
                        "C": Key.RIGHT,
                        "D": Key.LEFT,
                    }[final], None
                while select.select([sys.stdin], [], [], 0.05)[0]:
                    final = sys.stdin.read(1)
                    if "@" <= final <= "~":
                        break
                return Key.OTHER, None
            if ch in ("\r", "\n"):
                return Key.ENTER, None
            if ch == " ":
                return Key.SPACE, " "
            if ch in ("\x08", "\x7f"):
                return Key.BACKSPACE, None
            if ch == "\x03":
                return Key.CTRL_C, None
            if ch.isprintable():
                return Key.OTHER, ch
            return Key.OTHER, None
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    def _read_posix(self) -> Key:
        return self._read_posix_input()[0]

    def read_text_key(self) -> tuple[Key, str | None]:
        """Read one key and return its logical action plus printable text."""
        if sys.platform != "win32":
            return self._read_posix_input()

        import msvcrt

        ch = msvcrt.getch()
        if ch in (b"\x00", b"\xe0"):
            arrow = msvcrt.getch()
            return ({
                b"H": Key.UP,
                b"P": Key.DOWN,
                b"K": Key.LEFT,
                b"M": Key.RIGHT,
            }.get(arrow, Key.OTHER), None)
        if ch == b"\r":
            return Key.ENTER, None
        if ch == b" ":
            return Key.SPACE, " "
        if ch in (b"\x08", b"\x7f"):
            return Key.BACKSPACE, None
        if ch == b"\x1b":
            return Key.ESCAPE, None
        if ch == b"\x03":
            return Key.CTRL_C, None
        try:
            return Key.OTHER, ch.decode("utf-8")
        except UnicodeDecodeError:
            return Key.OTHER, None


def _first_enabled(items: list) -> int:
    for i, item in enumerate(items):
        if item.enabled:
            return i
    return 0


def _step(items: list, idx: int, direction: int) -> int:
    n = len(items)
    for _ in range(n):
        idx = (idx + direction) % n
        if items[idx].enabled:
            return idx
    return idx


def _menu_dimensions() -> tuple[int, int]:
    size = console.size
    return max(1, int(size.width)), max(1, int(size.height))


def _menu_column_widths() -> tuple[int, int]:
    width, _height = _menu_dimensions()
    content_width = max(12, width - 8)
    label_width = max(6, min(32, content_width // 3))
    description_width = max(6, content_width - label_width - 4)
    return label_width, description_width


def _build_panel(
    title: str,
    items: list,
    idx: int,
    guide: str,
    max_visible: int | None = None,
    filter_text: str = "",
) -> Panel:
    from rich.markup import escape

    width, height = _menu_dimensions()
    if max_visible is None:
        max_visible = max(1, height - 8)
    else:
        max_visible = max(1, max_visible)

    total = len(items)
    if total <= max_visible:
        start, end = 0, total
    else:
        start = max(0, min(idx - max_visible // 2, total - max_visible))
        end = start + max_visible

    narrow = width < 44
    if narrow:
        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 0))
        table.add_column("Marker", style="bold cyan", width=2, no_wrap=True)
        table.add_column(
            "Item",
            style="bold white",
            width=max(1, width - 4),
            no_wrap=True,
            overflow="ellipsis",
        )
    else:
        label_width, description_width = _menu_column_widths()
        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        table.add_column("Marker", style="bold cyan", width=2, no_wrap=True)
        table.add_column(
            "Label",
            style="bold white",
            width=label_width,
            no_wrap=True,
            overflow="ellipsis",
        )
        table.add_column(
            "Description",
            style="dim",
            width=description_width,
            no_wrap=True,
            overflow="ellipsis",
        )

    def add_row(marker: str, label: str, description: str = "") -> None:
        if narrow:
            combined = label if not description else f"{label} — {description}"
            table.add_row(marker, combined)
        else:
            table.add_row(marker, label, description)

    if filter_text:
        add_row(" ", f"[bold cyan]Filter: {escape(filter_text)}[/bold cyan]")
    if total == 0:
        add_row(" ", "[yellow]No matching items[/yellow]")
        return Panel(table, title=f"[bold]{title}[/bold]", subtitle=guide, border_style="cyan")
    if start:
        add_row(" ", "[dim]↑ more above[/dim]")
    for i in range(start, end):
        item = items[i]
        marker = ">" if i == idx else " "
        if not item.enabled:
            add_row(marker, f"[dim]{item.label}[/dim]", f"[dim]{item.description} (unavailable)[/dim]")
        elif i == idx:
            add_row(marker, f"[cyan]{item.label}[/cyan]", f"[cyan]{item.description}[/cyan]")
        else:
            add_row(marker, item.label, item.description)
    if end < total:
        add_row(" ", "[dim]↓ more below[/dim]")
    return Panel(table, title=f"[bold]{title}[/bold]", subtitle=guide, border_style="cyan")


def _filtered_items(items: list, filter_text: str) -> list:
    if not filter_text:
        return items
    needle = filter_text.casefold()
    return [
        item
        for item in items
        if needle in f"{item.key} {item.label} {item.description}".casefold()
    ]


def _read_menu_event(
    source: Callable[[], object],
    reader: KeyReader | None,
) -> tuple[Key, str | None]:
    event = source() if reader is None else reader.read_text_key()
    if isinstance(event, tuple):
        key, text = event
        return key, text
    if isinstance(event, Key):
        return event, None
    if isinstance(event, str):
        return Key.OTHER, event
    return Key.OTHER, None


def run_menu(
    title: str,
    items: list,
    guide: str | None = None,
    key_source: Callable[[], object] | None = None,
    max_visible: int | None = None,
) -> str | None:
    """
    Render a keyboard-navigable menu and return the activated item's key.

    Up/Down move the selection (wrapping, skipping disabled items). Printable
    input filters by key, label, or description. Backspace edits the filter;
    Escape clears an active filter first and backs out when it is empty. Space,
    Enter, or Right activate the selected enabled item. Left returns Back and
    Ctrl+C raises KeyboardInterrupt.
    """
    if not any(item.enabled for item in items):
        return None

    guide_text = guide or DEFAULT_GUIDE

    if key_source is None and not is_interactive():
        return None

    reader = None if key_source is not None else KeyReader()
    source = key_source or (lambda: None)
    filter_text = ""
    visible_items = list(items)
    idx = _first_enabled(visible_items)

    def render():
        return _build_panel(
            title,
            visible_items,
            idx,
            guide_text,
            max_visible=max_visible,
            filter_text=filter_text,
        )

    with Live(
        render(),
        console=console,
        screen=True,
        auto_refresh=True,
        transient=True,
        get_renderable=render,
    ) as live:
        while True:
            live.update(render(), refresh=True)
            try:
                key, text = _read_menu_event(source, reader)
            except StopIteration:
                return None

            if text is not None and text != " " and text.isprintable():
                filter_text += text
                visible_items = _filtered_items(items, filter_text)
                idx = _first_enabled(visible_items)
                continue
            if key == Key.BACKSPACE:
                if filter_text:
                    filter_text = filter_text[:-1]
                    visible_items = _filtered_items(items, filter_text)
                    idx = _first_enabled(visible_items)
                continue
            if key == Key.UP:
                if visible_items:
                    idx = _step(visible_items, idx, -1)
            elif key == Key.DOWN:
                if visible_items:
                    idx = _step(visible_items, idx, 1)
            elif key in (Key.SPACE, Key.ENTER, Key.RIGHT):
                if visible_items and visible_items[idx].enabled:
                    return visible_items[idx].key
            elif key == Key.LEFT:
                return None
            elif key == Key.ESCAPE:
                if filter_text:
                    filter_text = ""
                    visible_items = list(items)
                    idx = _first_enabled(visible_items)
                else:
                    return None
            elif key == Key.CTRL_C:
                raise KeyboardInterrupt
            elif key == Key.OTHER:
                continue
