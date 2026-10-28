# blackoutkit/tui/screens/dnsscr.py
"""DNS resolver switch: pick a catalogue pair, apply it, put it back.

Applying a resolver runs `netsh` / `resolvectl` / `networksetup`, which can
take a second and may fail for lack of elevation. Every action therefore runs
through the shared background worker and reports its result in the output
panel instead of blocking the UI thread.
"""
from __future__ import annotations

from textual.binding import Binding
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widgets import Button, ListItem, ListView, Static

from ._worker import run_bg
from ..widgets.output_panel import CollapsibleOutput


class DNSScreen(Screen):
    SCREEN_ID = "dns"
    AUTO_FOCUS = ""

    BINDINGS = [
        Binding("a", "apply_selected", "Apply", priority=False),
        Binding("r", "restore_dns", "Restore", priority=False),
    ]

    DEFAULT_CSS = """
    DNSScreen {
        layout: vertical;
        padding: 1;
    }
    DNSScreen #dns-current {
        height: auto;
        padding-bottom: 1;
    }
    DNSScreen #dns-categories {
        height: 3;
    }
    DNSScreen #dns-categories Button {
        width: 1fr;
        height: 3;
    }
    DNSScreen #dns-providers {
        height: 1fr;
        border: round $primary;
    }
    DNSScreen #dns-actions {
        height: 3;
    }
    DNSScreen #dns-actions Button {
        width: 1fr;
        height: 3;
    }
    DNSScreen #dns-status {
        height: auto;
    }
    DNSScreen CollapsibleOutput {
        height: auto;
        max-height: 12;
    }
    """

    def __init__(self, engine=None) -> None:
        super().__init__()
        # Injected in tests; built lazily otherwise so importing this module
        # never touches the network stack.
        self._engine = engine
        self._category = "sanctions"
        self._last_result = None

    # ── engine ───────────────────────────────────────────────────────
    @property
    def engine(self):
        if self._engine is None:
            from blackoutkit.dns_engine import DNSEngine

            self._engine = DNSEngine()
        return self._engine

    # ── layout ───────────────────────────────────────────────────────
    def compose(self):
        yield Static("DNS — resolver switch (sanctions / speed)", markup=False)
        yield Static("", id="dns-current", markup=False)
        with Horizontal(id="dns-categories"):
            yield Button("Sanctions", id="cat-sanctions", variant="primary")
            yield Button("Speed", id="cat-speed")
            yield Button("Extra", id="cat-extra")
        yield ListView(id="dns-providers")
        with Horizontal(id="dns-actions"):
            yield Button("Apply selected", id="btn-dns-apply", variant="success")
            yield Button("Restore", id="btn-dns-restore")
            yield Button("Flush cache", id="btn-dns-flush")
            yield Button("Benchmark", id="btn-dns-bench")
        yield Static("", id="dns-status", markup=False)
        yield CollapsibleOutput(title="dns output", collapsed=True)

    def on_mount(self) -> None:
        self.refresh_view()

    # ── view ─────────────────────────────────────────────────────────
    def refresh_view(self) -> None:
        """Redraw the current-resolver line and the provider list."""
        self.query_one("#dns-current", Static).update(self.current_line())
        self.rebuild_list()
        self._sync_category_buttons()

    def current_line(self) -> str:
        try:
            servers = self.engine.current_servers()
            active = self.engine.active()
        except Exception as exc:  # noqa: BLE001 - UI must never crash here
            return f"Current: <unavailable: {exc}>"
        if not servers:
            return "Current: (no system resolver detected)"
        line = f"Current: {', '.join(servers)}"
        if active is not None:
            line += f"   ✓ {active.name} ({active.category})"
        else:
            line += "   (custom — not in the catalogue)"
        return line

    def provider_rows(self, category: str | None = None) -> list[tuple[str, str]]:
        """[(key, one-line label)] for the visible category."""
        wanted = category or self._category
        try:
            provs = self.engine.providers(wanted)
        except Exception:  # noqa: BLE001
            return []
        rows = []
        for prov in provs:
            label = f"{prov.name:<20} {prov.primary:<16}"
            if prov.secondary:
                label += f" {prov.secondary:<16}"
            else:
                label += f" {'—':<16}"
            if prov.note:
                label += f" {prov.note}"
            rows.append((prov.key, label))
        return rows

    def visible_keys(self) -> list[str]:
        return [key for key, _ in self.provider_rows()]

    def selected_key(self) -> str | None:
        view = self.query_one("#dns-providers", ListView)
        index = view.index
        keys = self.visible_keys()
        if index is None or not (0 <= index < len(keys)):
            return None
        return keys[index]

    def rebuild_list(self) -> None:
        view = self.query_one("#dns-providers", ListView)
        view.clear()
        for key, label in self.provider_rows():
            item = ListItem(Static(label, markup=False))
            item.provider_key = key  # type: ignore[attr-defined]
            view.append(item)

    def select_category(self, category: str) -> None:
        self._category = category
        self.rebuild_list()
        self._sync_category_buttons()
        self._set_status(f"Showing {category} resolvers.")

    def _sync_category_buttons(self) -> None:
        for cat in ("sanctions", "speed", "extra"):
            try:
                button = self.query_one(f"#cat-{cat}", Button)
            except Exception:  # noqa: BLE001
                continue
            button.variant = "primary" if cat == self._category else "default"

    def _set_status(self, message: str) -> None:
        self.query_one("#dns-status", Static).update(message)

    def _fill(self, text: str) -> None:
        self.query_one(CollapsibleOutput).set_text(text)

    def output_text(self) -> str:
        return self.query_one(CollapsibleOutput).last_text

    # ── actions ──────────────────────────────────────────────────────
    def do_apply(self, key: str) -> None:
        """Apply one catalogue entry (or raw IP) in the background."""
        if not key:
            self._set_status("Select a resolver first.")
            return
        self._set_status(f"Applying {key}…")
        self._fill(f"Applying {key}…")

        def work() -> str:
            result = self.engine.apply(key)
            self._last_result = result
            lines = [result.detail or ("Applied." if result.ok else "Failed.")]
            if result.applied:
                lines.append(f"applied: {', '.join(result.applied)}")
            if result.previous:
                lines.append(f"previous: {', '.join(result.previous)}")
            return "\n".join(lines)

        run_bg(self, work, self._on_action_done, group="dns-apply")

    def do_restore(self) -> None:
        self._set_status("Restoring previous resolvers…")
        self._fill("Restoring previous resolvers…")

        def work() -> str:
            result = self.engine.restore()
            self._last_result = result
            return result.detail or ("Restored." if result.ok else "Restore failed.")

        run_bg(self, work, self._on_action_done, group="dns-restore")

    def do_flush(self) -> None:
        self._set_status("Flushing DNS cache…")
        self._fill("Flushing DNS cache…")

        def work() -> str:
            return "DNS cache flushed." if self.engine.flush() else "Could not flush the DNS cache."

        run_bg(self, work, self._on_action_done, group="dns-flush")

    def do_bench(self) -> None:
        self._set_status("Benchmarking resolvers…")
        self._fill("Benchmarking resolvers…")

        def work() -> str:
            rows = self.engine.benchmark(repeat=2)
            if not rows:
                return "No resolver answered — every query timed out."
            body = "\n".join(f"{name:<12} {ip:<16} {ms:6.0f} ms" for name, ip, ms in rows)
            return f"fastest: {rows[0][0]} ({rows[0][1]}, {rows[0][2]:.0f} ms)\n{body}"

        run_bg(self, work, self._on_bench_done, group="dns-bench")

    def action_apply_selected(self) -> None:
        self.do_apply(self.selected_key() or "")

    def action_restore_dns(self) -> None:
        self.do_restore()

    # ── callbacks ────────────────────────────────────────────────────
    def _on_action_done(self, text: str) -> None:
        self._fill(text)
        self._set_status(text.splitlines()[0] if text else "done")
        self.refresh_view()

    def _on_bench_done(self, text: str) -> None:
        self._fill(text)
        self._set_status(text.splitlines()[0] if text else "done")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        if button_id.startswith("cat-"):
            event.stop()
            self.select_category(button_id[4:])
        elif button_id == "btn-dns-apply":
            event.stop()
            self.action_apply_selected()
        elif button_id == "btn-dns-restore":
            event.stop()
            self.do_restore()
        elif button_id == "btn-dns-flush":
            event.stop()
            self.do_flush()
        elif button_id == "btn-dns-bench":
            event.stop()
            self.do_bench()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        key = getattr(event.item, "provider_key", None)
        if key:
            self._set_status(f"Selected {key} — press Apply.")
