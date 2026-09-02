import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from blackoutkit.engines.singbox_proxy import Hysteria2Engine


def make_proxy_config():
    return SimpleNamespace(
        protocol="hysteria2",
        address="proxy.example",
        port=443,
        password="sensitive-password",
        uuid="",
        sni="proxy.example",
        insecure=False,
        alpn="h3",
        display_name=lambda: "test-hysteria2",
    )


@pytest.mark.skipif(sys.platform != "win32", reason="Windows native DLL test")
def test_hysteria2_passes_config_directly_to_core_dll(tmp_path):
    engine = Hysteria2Engine(proxy_config=make_proxy_config(), socks_port=10808)
    engine._config_dir = tmp_path
    dll = MagicMock()
    dll.StartSingBoxC.return_value = 0

    with patch("blackoutkit.core.get_core_dll", return_value=dll), \
         patch.object(engine, "check_port_free", return_value=True), \
         patch.object(engine, "wait_for_port", return_value=True):
        assert engine.start() is True

    payload = dll.StartSingBoxC.call_args.args[0]
    assert isinstance(payload, bytes)
    assert b"sensitive-password" in payload
    assert not list(tmp_path.iterdir())
    dll.StartSingBoxC.assert_called_once()
