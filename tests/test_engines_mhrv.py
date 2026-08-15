from unittest.mock import MagicMock, patch

from blackoutkit.engines.mhrv import MhrvEngine


def test_mhrv_is_described_as_http_relay_without_certificate_claims():
    engine = MhrvEngine()

    assert "HTTP Google Apps Script relay" in engine.description
    assert "MITM" not in engine.description
    assert "certificate" not in engine.description.lower()


def test_mhrv_starts_native_http_relay_with_gas_ids():
    engine = MhrvEngine(http_port=18085)
    dll = MagicMock()
    dll.StartMHRVC.return_value = 0

    with patch("blackoutkit.core.get_core_dll", return_value=dll), \
         patch("blackoutkit.settings.load", return_value={"mhrv_direct": False}), \
         patch("blackoutkit.engines.appsscript._load_gas_ids", return_value=["relay-a", "relay-b"]), \
         patch.object(engine, "wait_for_port", return_value=True):
        assert engine.start() is True

    dll.StartMHRVC.assert_called_once_with(18085, b"relay-a,relay-b")
    assert engine._dll_stop_func is dll.StopMHRVC


def test_mhrv_direct_mode_passes_no_gas_ids():
    engine = MhrvEngine(http_port=18085)
    dll = MagicMock()
    dll.StartMHRVC.return_value = 0

    with patch("blackoutkit.core.get_core_dll", return_value=dll), \
         patch("blackoutkit.settings.load", return_value={"mhrv_direct": True}), \
         patch.object(engine, "wait_for_port", return_value=True):
        assert engine.start() is True

    dll.StartMHRVC.assert_called_once_with(18085, b"")
