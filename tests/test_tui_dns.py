"""DNS screen: category switching, provider rows, and worker-driven actions."""
from __future__ import annotations

import pytest

textual = pytest.importorskip("textual")
from textual.app import App, ComposeResult  # noqa: E402
from textual.widgets import Static  # noqa: E402

from blackoutkit import dns_engine as dns  # noqa: E402
from blackoutkit.tui.screens.dnsscr import DNSScreen  # noqa: E402


class _FakeEngine(dns.DNSEngine):
    def __init__(self):
        super().__init__()
        self.current = ["1.1.1.1", "1.0.0.1"]
        self.applied = []
        self.restored = 0
        self.flushed = 0
        self.benched = 0

    def current_servers(self):
        return list(self.current)

    def apply(self, query, adapter=None):
        self.applied.append((query, adapter))
        prov = dns.find(query)
        servers = list(prov.servers) if prov else [query]
        previous = self.current
        self.current = servers
        return dns.DNSApplyResult(
            True,
            f"Applied {prov.name if prov else query}",
            provider=prov.describe() if prov else query,
            applied=tuple(servers),
            previous=tuple(previous),
        )

    def restore(self):
        self.restored += 1
        self.current = ["1.1.1.1"]
        return dns.DNSApplyResult(True, "Restored to DHCP DNS.")

    def flush(self):
        self.flushed += 1
        return True

    def benchmark(self, domain="www.google.com", repeat=2):
        self.benched += 1
        return [("Shecan", "178.22.122.100", 41.0)]


class DnsApp(App):
    def __init__(self, engine):
        super().__init__()
        self._engine = engine

    def compose(self) -> ComposeResult:
        yield Static("root", markup=False)

    def on_mount(self) -> None:
        self.push_screen(DNSScreen(engine=self._engine))


def _screen(app) -> DNSScreen:
    assert isinstance(app.screen, DNSScreen)
    return app.screen


async def _settle(pilot, predicate, tries=60):
    for _ in range(tries):
        await pilot.pause(0.05)
        if predicate():
            return True
    return False


@pytest.mark.asyncio
async def test_default_category_lists_sanctions_providers():
    app = DnsApp(_FakeEngine())
    async with app.run_test() as pilot:
        screen = _screen(app)
        await pilot.pause()
        keys = screen.visible_keys()
        # The XDNS pairs lead the group; the rest may grow over time.
        assert keys[:5] == ["shecan", "electro", "begzar", "radar", "403"]
        assert "opendns" in keys
        assert all(k in {p.key for p in dns.providers("sanctions")} for k in keys)
        assert "178.22.122.100" in screen.provider_rows()[0][1]


@pytest.mark.asyncio
async def test_switching_category_rebuilds_the_list():
    app = DnsApp(_FakeEngine())
    async with app.run_test() as pilot:
        screen = _screen(app)
        await pilot.pause()
        screen.select_category("speed")
        await pilot.pause()
        assert screen.visible_keys()[:3] == ["yandex", "cloudflare", "cloudflare-security"]
        assert set(screen.visible_keys()) == {p.key for p in dns.providers("speed")}
        screen.select_category("extra")
        await pilot.pause()
        assert "quad9" in screen.visible_keys()
        assert set(screen.visible_keys()) == {p.key for p in dns.providers("extra")}


@pytest.mark.asyncio
async def test_current_line_names_the_active_provider():
    app = DnsApp(_FakeEngine())
    async with app.run_test() as pilot:
        screen = _screen(app)
        await pilot.pause()
        line = screen.current_line()
        assert "1.1.1.1" in line
        assert "Cloudflare" in line


@pytest.mark.asyncio
async def test_apply_runs_in_background_and_refreshes():
    engine = _FakeEngine()
    app = DnsApp(engine)
    async with app.run_test() as pilot:
        screen = _screen(app)
        await pilot.pause()
        screen.do_apply("shecan")
        assert await _settle(pilot, lambda: engine.applied)
        assert await _settle(pilot, lambda: "Applied Shecan" in screen.output_text())
        assert engine.current == ["178.22.122.100", "185.51.200.2"]
        assert "Shecan" in screen.current_line()


@pytest.mark.asyncio
async def test_restore_and_flush_and_bench_are_reachable():
    engine = _FakeEngine()
    app = DnsApp(engine)
    async with app.run_test() as pilot:
        screen = _screen(app)
        await pilot.pause()
        screen.do_restore()
        assert await _settle(pilot, lambda: engine.restored == 1)
        screen.do_flush()
        assert await _settle(pilot, lambda: engine.flushed == 1)
        screen.do_bench()
        assert await _settle(pilot, lambda: engine.benched == 1)
        assert await _settle(pilot, lambda: "fastest" in screen.output_text())


@pytest.mark.asyncio
async def test_apply_with_no_selection_reports_instead_of_crashing():
    app = DnsApp(_FakeEngine())
    async with app.run_test() as pilot:
        screen = _screen(app)
        await pilot.pause()
        screen.do_apply("")
        await pilot.pause()
        status = screen.query_one("#dns-status", Static)
        assert "Select a resolver" in str(status.render())


@pytest.mark.asyncio
async def test_unknown_provider_surfaces_the_error_text():
    class _Failing(_FakeEngine):
        def apply(self, query, adapter=None):
            return dns.DNSApplyResult(False, "Unknown DNS provider 'zzz'.")

    app = DnsApp(_Failing())
    async with app.run_test() as pilot:
        screen = _screen(app)
        await pilot.pause()
        screen.do_apply("zzz")
        assert await _settle(pilot, lambda: "Unknown DNS provider" in screen.output_text())
