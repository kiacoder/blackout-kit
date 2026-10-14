import sys

import pytest

from blackoutkit import cli, daemon
from blackoutkit.engine_stack import get_engine_classes, start_engines_in_order
from blackoutkit.engines.sni import SNIEngine
from blackoutkit.engines.tun import TUNEngine
from blackoutkit.engines.xray import XRayEngine


@pytest.mark.parametrize(
    ("platform", "expected"),
    [
        ("win32", (SNIEngine, XRayEngine, TUNEngine)),
        ("linux", (XRayEngine, TUNEngine)),
    ],
)
def test_cli_tun_stack_uses_platform_specific_upstream_order(monkeypatch, platform, expected):
    monkeypatch.setattr(cli.sys, "platform", platform)

    assert cli._get_engine_classes("tun") == expected


def test_foreground_tun_stack_starts_sequentially_before_reporting_success(monkeypatch):
    events = []

    class FakeEngine:
        name = "fake"
        pid = None
        _log = __import__("logging").getLogger("fake")

        def __init__(self, engine_name):
            self.name = engine_name

        def start(self):
            events.append(f"start {self.name}")
            return True

        def stop(self):
            events.append(f"stop {self.name}")

    classes = tuple(
        type(
            f"{name.title()}Engine",
            (),
            {
                "__new__": lambda cls, engine_name=name: FakeEngine(engine_name),
                "name": name,
            },
        )
        for name in ("sni", "xray", "tun")
    )
    monkeypatch.setattr(cli, "_get_engine_classes", lambda _name: classes)
    monkeypatch.setattr(cli, "_linux_missing_dependencies", lambda _name: [])
    monkeypatch.setattr(cli, "_linux_dependencies", lambda _name: [])

    running = cli._start_engine_stack("tun", emit=False)

    assert [engine.name for engine in running] == ["sni", "xray", "tun"]
    assert events == ["start sni", "start xray", "start tun"]


def test_daemon_uses_same_tun_stack_as_foreground():
    assert daemon.get_engine_classes("tun", platform="win32") == get_engine_classes("tun", "win32")
    assert daemon.get_engine_classes("tun", platform="linux") == get_engine_classes("tun", "linux")
    assert daemon.get_engine_classes("other", platform="win32") == ()


@pytest.mark.parametrize(
    ("platform", "expected"),
    [
        ("win32", (SNIEngine, XRayEngine, TUNEngine)),
        ("linux", (XRayEngine, TUNEngine)),
    ],
)
def test_active_daemon_tun_factory_uses_ordered_platform_stack(monkeypatch, platform, expected):
    import blackoutkit.daemon as daemon_package

    monkeypatch.setattr(daemon_package.sys, "platform", platform)
    assert daemon_package.get_engine_classes("tun", daemon_package.sys.platform) == expected


def test_foreground_tun_start_wrapper_rolls_back_in_reverse_order(monkeypatch):
    events = []

    class FakeEngine:
        def __init__(self, name, result):
            self.name = name
            self.result = result
            self._log = __import__("logging").getLogger(name)

        def start(self):
            events.append(f"start {self.name}")
            return self.result

        def stop(self):
            events.append(f"stop {self.name}")

    class First:
        def __new__(cls):
            return FakeEngine("upstream", True)

    class Second:
        def __new__(cls):
            return FakeEngine("xray", True)

    class Third:
        def __new__(cls):
            return FakeEngine("tun", False)

    monkeypatch.setattr(cli, "_get_engine_classes", lambda _name: (First, Second, Third))
    monkeypatch.setattr(cli, "_linux_missing_dependencies", lambda _name: [])
    # The stack-start wrapper also probes downloader.check_installed() for the
    # engine's binary dependencies and prompts interactively when any are
    # missing. On a fresh CI checkout nothing is installed, so pin the
    # dependency list empty — this test covers stack rollback order, not the
    # download flow (and must not touch stdin under pytest capture).
    monkeypatch.setattr(cli, "_linux_dependencies", lambda _name: [])

    assert cli._start_engine_stack("tun", emit=False) == []
    assert events == [
        "start upstream",
        "start xray",
        "start tun",
        "stop xray",
        "stop upstream",
    ]


def test_daemon_tun_start_wrapper_uses_sequential_stack_and_reverse_rollback(monkeypatch, tmp_path):
    from unittest.mock import MagicMock

    import blackoutkit.daemon as daemon_package
    from blackoutkit import readiness, settings, tray

    events = []

    class FakeEngine:
        def __init__(self, name, result):
            self.name = name
            self.result = result
            self.pid = None

        def start(self):
            events.append(f"start {self.name}")
            return self.result

        def stop(self):
            events.append(f"stop {self.name}")

    class FakeSpinner:
        def __init__(self, *_args, **_kwargs):
            pass

        def start(self):
            pass

        def stop(self, *_args):
            pass

    classes = (object, object, object)
    engines = [
        FakeEngine("sni", True),
        FakeEngine("xray", True),
        FakeEngine("tun", False),
    ]
    monkeypatch.setattr(daemon_package.sys, "platform", "win32")
    monkeypatch.setattr(daemon_package, "get_engine_classes", lambda *_args: classes)
    monkeypatch.setattr(daemon_package, "start_engines_in_order", lambda _engines, start_engine: _exercise_stack(engines, start_engine))
    monkeypatch.setattr(daemon_package, "Spinner", FakeSpinner)
    settings_values = dict(readiness.cfg.DEFAULTS)
    settings_values.update(auto_set_proxy=False, gdpi_backend="legacy", fallback_enabled=False)
    monkeypatch.setattr(settings, "load", lambda: settings_values)
    monkeypatch.setattr(readiness, "evaluate", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(tray, "start_tray", lambda *_args: None)
    monkeypatch.setattr(daemon_package.subprocess, "Popen", MagicMock())
    monkeypatch.setattr(daemon_package, "APP_DATA_DIR", tmp_path)
    monkeypatch.setattr(daemon_package, "PID_FILE", tmp_path / "daemon.pid")
    monkeypatch.setattr(daemon_package, "STATE_FILE", tmp_path / "daemon_state.json")
    monkeypatch.setattr(daemon_package, "LOG_FILE", tmp_path / "daemon.log")
    monkeypatch.setattr(daemon_package, "_daemon_shutdown_requested", lambda *_args: True)

    daemon_package.run_daemon_loop("tun")

    assert events == [
        "start sni",
        "start xray",
        "start tun",
        "stop xray",
        "stop sni",
    ]


def _exercise_stack(engines, start_engine):
    started = []
    for engine in engines:
        if not start_engine(engine):
            for item in reversed(started):
                item.stop()
            return []
        started.append(engine)
    return started


def test_tun_stack_starts_upstream_before_tun_and_rolls_back_in_reverse():
    events = []

    class Upstream:
        name = "upstream"

        def start(self):
            events.append("start upstream")
            return True

        def stop(self):
            events.append("stop upstream")

    class SocksProvider:
        name = "socks-provider"

        def start(self):
            events.append("start socks-provider")
            return True

        def stop(self):
            events.append("stop socks-provider")

    class TunConsumer:
        name = "tun"

        def start(self):
            events.append("start tun")
            return False

        def stop(self):
            events.append("stop tun")

    started = start_engines_in_order((Upstream(), SocksProvider(), TunConsumer()))

    assert started == []
    assert events == [
        "start upstream",
        "start socks-provider",
        "start tun",
        "stop socks-provider",
        "stop upstream",
    ]


def test_tun_stack_start_failure_only_stops_started_upstreams():
    events = []

    class Upstream:
        name = "upstream"

        def start(self):
            events.append("start upstream")
            return True

        def stop(self):
            events.append("stop upstream")

    class TunConsumer:
        name = "tun"

        def start(self):
            events.append("start tun")
            return False

        def stop(self):
            events.append("stop tun")

    assert start_engines_in_order((Upstream(), TunConsumer())) == []
    assert events == ["start upstream", "start tun", "stop upstream"]


def test_tun_stack_stops_starting_after_an_upstream_fails():
    events = []

    class FailedUpstream:
        name = "failed upstream"

        def start(self):
            events.append("start failed upstream")
            return False

        def stop(self):
            events.append("stop failed upstream")

    class TunConsumer:
        name = "tun"

        def start(self):
            events.append("start tun")
            return True

        def stop(self):
            events.append("stop tun")

    assert start_engines_in_order((FailedUpstream(), TunConsumer())) == []
    assert events == ["start failed upstream"]


def test_tun_stack_rolls_back_started_engines_when_start_raises():
    events = []

    class Upstream:
        name = "upstream"

        def start(self):
            events.append("start upstream")
            return True

        def stop(self):
            events.append("stop upstream")

    class FailedEngine:
        name = "failed"

        def start(self):
            events.append("start failed")
            raise RuntimeError("start failed")

        def stop(self):
            events.append("stop failed")

    with pytest.raises(RuntimeError, match="start failed"):
        start_engines_in_order((Upstream(), FailedEngine()))

    assert events == ["start upstream", "start failed", "stop upstream"]
