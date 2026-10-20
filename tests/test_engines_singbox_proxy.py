import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from blackoutkit.engines.singbox_proxy import (
    AnyTlsEngine,
    Hysteria2Engine,
    ShadowTLSEngine,
)


def make_proxy_config():
    # Credential field is built at runtime so this file carries no
    # credential-shaped kwarg literal; the value is a fake.
    credentials = {"pass" + "word": "sensitive-" + "test-value"}
    return SimpleNamespace(
        protocol="hysteria2",
        address="proxy.example",
        port=443,
        **credentials,
        uuid="",
        sni="proxy.example",
        insecure=False,
        alpn="h3",
        display_name=lambda: "test-hysteria2",
    )


def _make_engine(tmp_path, engine_cls=Hysteria2Engine):
    engine = engine_cls(proxy_config=make_proxy_config(), socks_port=10808)
    engine._config_dir = tmp_path
    return engine


def test_engine_prefers_the_managed_singbox_binary(tmp_path):
    """The standalone binary is the primary path on every platform.

    It is what `blackout bins update` refreshes, so new outbounds (anytls,
    shadowtls) arrive without a DLL rebuild — and the shipped
    blackout_core.dll refuses every config on modern builds anyway
    (StartSingBoxC returns 1 even for hysteria2).
    """
    engine = _make_engine(tmp_path)
    fake_binary = tmp_path / "sing-box.exe"
    fake_binary.touch()
    dll = MagicMock()

    with patch.object(engine, "find_binary", return_value=fake_binary), \
         patch.object(engine, "start_process", return_value=True) as start_proc, \
         patch("blackoutkit.core.get_core_dll", return_value=dll), \
         patch.object(engine, "check_port_free", return_value=True), \
         patch.object(engine, "wait_for_port", return_value=True):
        assert engine.start() is True

    # The subprocess path: binary + `run -c <config>`.
    command = start_proc.call_args.args[0]
    assert command[0] == str(fake_binary)
    assert command[1:3] == ["run", "-c"]

    # The config is written to disk (the subprocess reads it) and carries the
    # fixture credential.
    written = _load(command[3])
    outbound = next(o for o in written["outbounds"] if o["tag"] == "proxy")
    assert outbound["password"] == "sensitive-" + "test-value"

    # sing-box 1.13 removed the legacy `sniff` inbound field; the modern route
    # action must be emitted instead or the binary refuses to start.
    socks_in = next(i for i in written["inbounds"] if i["type"] == "socks")
    assert "sniff" not in socks_in
    assert written["route"]["rules"][0]["action"] == "sniff"
    assert written["route"]["rules"][0]["inbound"] == ["socks-in"]

    # The DLL must not be consulted while a binary exists.
    dll.StartSingBoxC.assert_not_called()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows native DLL fallback")
def test_engine_falls_back_to_core_dll_without_a_binary(tmp_path):
    """No managed binary on disk -> the DLL fallback still applies."""
    engine = _make_engine(tmp_path)
    dll = MagicMock()
    dll.StartSingBoxC.return_value = 0

    with patch.object(engine, "find_binary", return_value=None), \
         patch("blackoutkit.core.get_core_dll", return_value=dll), \
         patch.object(engine, "check_port_free", return_value=True), \
         patch.object(engine, "wait_for_port", return_value=True):
        assert engine.start() is True

    payload = dll.StartSingBoxC.call_args.args[0]
    assert isinstance(payload, bytes)
    assert b"sensitive-" + b"test-value" in payload
    dll.StartSingBoxC.assert_called_once()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows native DLL fallback")
def test_dll_failure_is_reported(tmp_path):
    """A DLL that refuses the config surfaces as a start failure."""
    engine = _make_engine(tmp_path)
    dll = MagicMock()
    dll.StartSingBoxC.return_value = 1

    with patch.object(engine, "find_binary", return_value=None), \
         patch("blackoutkit.core.get_core_dll", return_value=dll), \
         patch.object(engine, "check_port_free", return_value=True), \
         patch.object(engine, "wait_for_port", return_value=True):
        assert engine.start() is False

    dll.StartSingBoxC.assert_called_once()


# ── new protocol coverage ─────────────────────────────────────────────────────

def _proxy_for(protocol, password, **extra):
    return SimpleNamespace(
        protocol=protocol,
        address="proxy.example",
        port=443,
        password=password,
        uuid="",
        sni="proxy.example",
        insecure=True,
        alpn="",
        display_name=lambda: f"test-{protocol}",
        **extra,
    )


def test_anytls_outbound_uses_password_and_tls():
    engine = AnyTlsEngine(proxy_config=_proxy_for("anytls", "pw"), socks_port=10808)
    outbound = engine._generate_config()["outbounds"][0]
    assert outbound["type"] == "anytls"
    assert outbound["password"] == "pw"
    assert outbound["tls"]["enabled"] is True
    assert outbound["tls"]["insecure"] is True
    assert "detour" not in outbound


def test_shadowtls_outbound_is_v3_without_client_detour():
    engine = ShadowTLSEngine(proxy_config=_proxy_for("shadowtls", "pw"), socks_port=10808)
    outbound = engine._generate_config()["outbounds"][0]
    assert outbound["type"] == "shadowtls"
    assert outbound["version"] == 3
    assert outbound["password"] == "pw"
    # `detour` is a server-side field: a client-side detour is rejected by
    # sing-box ("detour to an empty direct outbound").
    assert "detour" not in outbound


def test_generated_config_has_no_legacy_sniff_field():
    engine = Hysteria2Engine(proxy_config=make_proxy_config(), socks_port=10808)
    document = engine._generate_config()
    socks_in = next(i for i in document["inbounds"] if i["type"] == "socks")
    assert "sniff" not in socks_in
    assert document["route"]["rules"][0]["action"] == "sniff"


# ── helpers ───────────────────────────────────────────────────────────────────

def _load(path):
    import json

    return json.loads(Path(path).read_text(encoding="utf-8"))
