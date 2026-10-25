"""Operation spinner with rotating status verbs."""
from __future__ import annotations

from textual.timer import Timer
from textual.widgets import Static

_VERBS = ("Reticulating", "Tunneling", "Patching", "Coaxing", "Routing", "Polishing")


class OperationSpinner(Static):
    DEFAULT_CSS = """
    OperationSpinner { height: 1; padding: 0 1; display: none; }
    """

    def __init__(self) -> None:
        super().__init__("", markup=False)
        self._operation_running = False
        self._verb_index = 0
        self._label = ""
        self._text = ""
        self._tick: Timer | None = None
        self._hide: Timer | None = None

    def is_running(self) -> bool:
        return self._operation_running

    def label_text(self) -> str:
        return self._text

    def start(self, label: str) -> None:
        if not self.is_mounted:
            raise RuntimeError("Cannot start an operation spinner before it is mounted.")
        if self._tick is not None:
            self._tick.stop()
        if self._hide is not None:
            self._hide.stop()
            self._hide = None
        self._operation_running = True
        self._label = label
        self._verb_index = 0
        self.display = True
        self._advance()
        self._tick = self.set_interval(0.4, self._advance)

    def finish(self, ok: bool, note: str = "") -> None:
        self._operation_running = False
        if self._tick is not None:
            self._tick.stop()
            self._tick = None
        mark = "✔" if ok else "✘"
        self._set_text(f"{mark} {self._label} {note}".strip())
        if self.is_mounted:
            if self._hide is not None:
                self._hide.stop()
            self._hide = self.set_timer(2.5, self._hide_spinner)

    def _advance(self) -> None:
        verb = _VERBS[self._verb_index % len(_VERBS)]
        self._verb_index += 1
        self._set_text(f"⠋ {verb} {self._label}…")

    def _set_text(self, text: str) -> None:
        self._text = text
        self.update(text)

    def _hide_spinner(self) -> None:
        self.display = False
        self._hide = None

    def on_unmount(self) -> None:
        self._operation_running = False
        if self._tick is not None:
            self._tick.stop()
            self._tick = None
        if self._hide is not None:
            self._hide.stop()
            self._hide = None
