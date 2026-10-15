"""Phase 5 — auto-wrapping responsive tables (theme.make_table)."""
from __future__ import annotations

from rich.console import Console

from blackoutkit.theme import build_theme, make_table


def test_wrap_default_sets_fold_overflow():
    table = make_table("t", [("Process", "white"), ("Remote", "white")], [])
    assert table.columns[0].overflow == "fold"
    assert table.columns[1].overflow == "fold"


def test_wrap_false_keeps_columns_unwrapped():
    table = make_table("t", [("ID", "cyan")], [], wrap=False)
    # rich's default overflow is "ellipsis"; we must not force folding.
    assert table.columns[0].overflow != "fold"


def test_long_cell_is_not_truncated_when_wrapped():
    long_remote = "2001:0db8:85a3:0000:0000:8a2e:0370:7334:443"
    # Single-column table: a multi-line folded cell stays contiguous within its
    # own column (no interleaving with a neighbour), so the full value must
    # survive after joining the fold lines.
    table = make_table("Remote", [("Remote", "white")], [[long_remote]])
    buf = Console(width=40, theme=build_theme(), file=__import__("io").StringIO(), force_terminal=False)
    buf.print(table)
    # A folded multi-line cell separates its segments with box borders / line
    # breaks; strip those (the value itself contains none) to reconstruct it.
    cleaned = "".join(ch for ch in buf.file.getvalue() if ch not in "\n│ ")
    assert long_remote in cleaned, "remote address was truncated"
