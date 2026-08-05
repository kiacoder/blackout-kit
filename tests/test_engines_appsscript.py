import pytest
import json
from unittest.mock import patch, MagicMock
from blackoutkit.engines.appsscript import (
    AppsScriptEngine, _load_gas_ids, _relay_request, _GASProxyHandler, BUILTIN_GAS_IDS
)

@patch("blackoutkit.engines.appsscript.GAS_IDS_FILE")
def test_load_gas_ids(mock_file):
    # test default
    mock_file.exists.return_value = False
    assert _load_gas_ids() == BUILTIN_GAS_IDS
    
    # test file override
    mock_file.exists.return_value = True
    mock_file.read_text.return_value = "id1\nid2\n#comment\n"
    res = _load_gas_ids()
    assert res[0] == "id1"
    assert res[1] == "id2"
    assert len(res) == len(BUILTIN_GAS_IDS) + 2

@patch("urllib.request.urlopen")
@patch("ssl.create_default_context")
def test_relay_request(mock_ssl, mock_urlopen):
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps({"status": 200, "headers": {"a": "b"}, "body": "test"}).encode()
    mock_ctx = MagicMock()
    mock_ssl.return_value = mock_ctx
    mock_urlopen.return_value.__enter__.return_value = mock_resp
    
    res = _relay_request("id1", "http://test", "GET", {"host": "foo"}, b"data")
    assert res["status"] == 200
    assert res["body"] == "test"

@patch("urllib.request.urlopen", side_effect=Exception("network err"))
def test_relay_request_fail(mock_urlopen):
    res = _relay_request("id1", "http://test", "GET", {}, None)
    assert res is None

def test_proxy_handler_next_id():
    _GASProxyHandler.gas_ids = ["a", "b"]
    _GASProxyHandler._current_idx = 0
    assert _GASProxyHandler.next_id() == "a"
    assert _GASProxyHandler.next_id() == "b"
    assert _GASProxyHandler.next_id() == "a"

@patch("blackoutkit.settings.load", return_value={})
def test_engine_init(mock_load):
    engine = AppsScriptEngine(1234)
    assert engine.proxy_port == 1234
    assert engine.is_running() is False
    assert engine.pid is None

@patch("blackoutkit.settings.load", return_value={})
@patch("blackoutkit.engines.appsscript._load_gas_ids", return_value=["a", "b"])
@patch("blackoutkit.engines.appsscript.AppsScriptEngine._verify_relay")
@patch("socketserver.TCPServer.server_bind", MagicMock())
@patch("socketserver.TCPServer.server_activate", MagicMock())
def test_engine_start_stop(mock_verify, mock_load_gas, mock_load):
    mock_verify.side_effect = lambda id: id == "a"  # only 'a' works
    engine = AppsScriptEngine(0) # random port
    
    res = engine.start()
    assert res is True
    assert _GASProxyHandler.gas_ids == ["a"]
    assert engine.is_running() is True
    
    engine.stop()
    assert engine.is_running() is False

@patch("blackoutkit.settings.load", return_value={})
@patch("blackoutkit.engines.appsscript._load_gas_ids", return_value=[])
def test_engine_start_no_ids(mock_load_gas, mock_load):
    engine = AppsScriptEngine()
    assert engine.start() is False

@patch("blackoutkit.engines.appsscript._relay_request", return_value={"status": 200})
def test_engine_verify_relay(mock_relay):
    engine = AppsScriptEngine()
    assert engine._verify_relay("id1") is True

@patch("blackoutkit.engines.appsscript._relay_request", return_value={"status": 500})
def test_engine_verify_relay_fail(mock_relay):
    engine = AppsScriptEngine()
    assert engine._verify_relay("id1") is False
