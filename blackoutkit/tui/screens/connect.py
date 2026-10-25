"""Engine picker with honest local readiness badges."""
from __future__ import annotations

import sys
from collections.abc import Callable
from typing import Any

from textual.message import Message
from textual.screen import Screen
from textual.widgets import ListItem, ListView, Static

from blackoutkit.capabilities import build_capability_matrix

_STATE_STYLE = {"ready": "green", "blocked": "yellow", "unsupported": "grey"}


class ConnectAction(Message):
    def __init__(self, kind: str, engine: str = "") -> None:
        super().__init__()
        self.kind = kind
        self.engine = engine


class ConnectScreen(Screen):
    SCREEN_ID = "connect"

    def __init__(
        self,
        state,
        capability_matrix_fn: Callable[..., list[dict[str, Any]]] | None = None,
    ) -> None:
        super().__init__()
        self._state = state
        self._capability_matrix_fn = capability_matrix_fn or build_capability_matrix

    def compose(self):
        yield Static(
            "Engines — local checks only; upstream reachability is not tested",
            markup=False,
        )
        yield ListView(id="engine-list")

    def build_rows(self) -> list[dict[str, str]]:
        matrix = self._capability_matrix_fn(platform=sys.platform, include_local=True)
        rows = []
        for row in matrix:
            blockers = row.get("blockers") or []
            detail = row["summary"]
            if blockers:
                detail += " · " + blockers[0]
            else:
                detail += " · local checks passed"
            detail += " · local check only"
            rows.append(
                {
                    "name": row["name"],
                    "display_name": row["display_name"],
                    "state": row["state"],
                    "detail": detail,
                }
            )
        return rows

    def on_mount(self) -> None:
        self.set_rows(self.build_rows())

    def set_rows(self, rows: list[dict[str, str]]) -> None:
        view = self.query_one("#engine-list", ListView)
        view.clear()
        for row in rows:
            style = _STATE_STYLE.get(row["state"], "grey")
            label = (
                f"[{style}]{row['display_name']}[/{style}] · "
                f"{row['state']} · {row['detail']}"
            )
            view.append(
                ListItem(
                    Static(label, markup=True),
                    name=row["name"],
                    id=f"engine-{row['name']}",
                )
            )

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        engine = event.item.name or ""
        if engine:
            self.post_message(ConnectAction("start", engine))
