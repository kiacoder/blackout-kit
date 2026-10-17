"""Config failover: an open port is not proof that a config works.

A REALITY server that rejects the handshake accepts TCP, opens its listening
port and then closes every request with EOF. The engine used to treat "port
opened" as success and stop there, so one dead config — the one the rotation
offset happened to land on — meant a total failure while the rest of the
vault sat unused.
"""

import pytest

from blackoutkit.engines.xray import XRayEngine


class _Cfg:
    """Minimal stand-in for a stored proxy config."""

    def __init__(self, name, protocol="vless", address="203.0.113.10", port=443):
        self.name = name
        self.protocol = protocol
        self.address = address
        self.port = port

    def is_reality(self):
        return False

    def reality_validation_error(self):
        return None


def _auto_engine(monkeypatch, candidates, verify):
    engine = XRayEngine()
    engine._auto_config = True
    engine._auto_selected = candidates[0]
    engine.proxy_config = candidates[0]
    monkeypatch.setattr(engine, "_candidate_configs", lambda: list(candidates))
    started = []

    def _start_single():
        started.append(engine.proxy_config.name)
        return True

    monkeypatch.setattr(engine, "_start_single", _start_single)
    monkeypatch.setattr(engine, "_verify_proxy", lambda: verify(engine.proxy_config))
    monkeypatch.setattr(engine, "stop", lambda: None)
    monkeypatch.setattr("blackoutkit.engines.xray.time.sleep", lambda *_: None)
    return engine, started


def test_fails_over_to_the_next_config_when_one_cannot_carry_traffic(monkeypatch):
    bad, good = _Cfg("BK-REALITY-SRV1"), _Cfg("BK-TLS-SRV1")
    engine, started = _auto_engine(
        monkeypatch, [bad, good],
        lambda cfg: (cfg.name == "BK-TLS-SRV1", "EOF" if cfg.name != "BK-TLS-SRV1" else ""),
    )

    assert engine.start() is True
    assert started == ["BK-REALITY-SRV1", "BK-TLS-SRV1"]
    assert engine.proxy_config.name == "BK-TLS-SRV1"
    assert engine.config_failures == [("BK-REALITY-SRV1", "EOF")]


def test_first_config_that_works_is_used_without_touching_the_rest(monkeypatch):
    first, second = _Cfg("BK-VLESS-SRV1"), _Cfg("BK-VLESS-SRV2")
    engine, started = _auto_engine(monkeypatch, [first, second], lambda cfg: (True, ""))

    assert engine.start() is True
    assert started == ["BK-VLESS-SRV1"]
    assert engine.config_failures == []


def test_total_failure_reports_every_reason(monkeypatch):
    a, b = _Cfg("BK-REALITY-SRV1"), _Cfg("BK-REALITY-SRV2")
    engine, started = _auto_engine(monkeypatch, [a, b], lambda cfg: (False, "EOF"))

    assert engine.start() is False
    assert started == ["BK-REALITY-SRV1", "BK-REALITY-SRV2"]
    assert [name for name, _ in engine.config_failures] == ["BK-REALITY-SRV1", "BK-REALITY-SRV2"]


def test_explicit_config_is_never_rotated_away(monkeypatch):
    explicit = _Cfg("pinned")
    engine = XRayEngine(proxy_config=explicit)
    calls = []
    monkeypatch.setattr(engine, "_start_single", lambda: calls.append(1) or True)
    monkeypatch.setattr(
        engine, "_candidate_configs",
        lambda: pytest.fail("an explicit config must not consult the rotation"),
    )

    assert engine.start() is True
    assert calls == [1]
    assert engine.proxy_config is explicit


def test_attempts_are_capped(monkeypatch):
    many = [_Cfg(f"cfg-{i}") for i in range(10)]
    engine, started = _auto_engine(monkeypatch, many, lambda cfg: (False, "EOF"))

    assert engine.start() is False
    assert len(started) == XRayEngine._MAX_CONFIG_ATTEMPTS
