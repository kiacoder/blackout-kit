# blackoutkit/tui/widgets/status_strip.py
"""One-line live local status: daemon, engine, local proxy ports, country.

Carries the product honesty rule: this strip reports LOCAL state only and
never claims that an upstream server is reachable.
"""
from __future__ import annotations

from textual.reactive import reactive
from textual.widgets import Static


class StatusStrip(Static):
    BINDINGS = []

    DEFAULT_CSS = """
    StatusStrip {
        height: 1;
        background: $surface;
        color: $text;
        padding: 0 1;
    }
    """

    _line: reactive[str] = reactive("…")

    def __init__(self, state, interval: float = 2.0) -> None:
        # markup=False: snapshot text (especially error = str(exc)) is plain
        # data that may contain brackets; markup parsing would swallow tags
        # like [b] or raise on hostile input inside the timer callback.
        super().__init__(markup=False)
        self._state = state
        self._interval = interval
        self._timer = None

    @staticmethod
    def compose_line(snapshot: dict) -> str:
        if snapshot.get("error"):
            return f"🔴 daemon: {snapshot['error']} · local readiness only"
        pid = snapshot.get("pid")
        alive = "🟢" if pid else "🔴"
        engine = snapshot.get("active_engine") or "none"
        parts = [f"{alive} daemon pid={pid or '—'}", f"engine: {engine}"]
        if snapshot.get("http_port"):
            parts.append(f"http:{snapshot['http_port']}")
        if snapshot.get("socks_port"):
            parts.append(f"socks:{snapshot['socks_port']}")
        country = (snapshot.get("settings") or {}).get("country")
        if country:
            parts.append(f"country: {country}")
        parts.append("local readiness only")
        return " · ".join(str(p) for p in parts)

    def on_mount(self) -> None:
        self._refresh()
        self._timer = self.set_interval(self._interval, self._refresh)

    def _refresh(self) -> None:
        self._line = self.compose_line(self._state.snapshot())

    def watch__line(self, line: str) -> None:
        # Mirror the rendered line so tests/inspectors can read the strip's
        # content without depending on Textual's renamed Static attributes
        # (renderable -> content across versions).
        self._content = line
        self.update(line)
