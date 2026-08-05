import pytest
import json
import http.server
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

@patch("blackoutkit.engines.appsscript.GAS_IDS_FILE")
def test_load_gas_ids_exception(mock_file):
    mock_file.exists.return_value = True
    mock_file.read_text.side_effect = Exception("err")
    assert _load_gas_ids() == BUILTIN_GAS_IDS

def test_gas_proxy_handler_methods():
    # We will instantiate _GASProxyHandler without a real socket using MagicMock
    req = MagicMock()
    client_addr = ("127.0.0.1", 12345)
    server = MagicMock()
    
    with patch.object(http.server.BaseHTTPRequestHandler, '__init__', return_value=None):
        handler = _GASProxyHandler(req, client_addr, server)
        handler.path = "/test"
        handler.headers = {"Host": "example.com", "Content-Length": "4"}
        handler.rfile = MagicMock()
        handler.rfile.read.return_value = b"body"
        handler.wfile = MagicMock()
        
        # mock send methods
        handler.send_response = MagicMock()
        handler.send_header = MagicMock()
        handler.end_headers = MagicMock()
        
        # Test log_message
        handler.log_message("format", "arg") # covers line 144
        
        # Test _send_error_response
        handler._send_error_response(500, "error")
        handler.wfile.write.assert_called_with(b"error")
        
        # Test do_CONNECT
        handler.do_CONNECT()
        handler.send_response.assert_called_with(405)
        
        # Test _do_relay success
        _GASProxyHandler.gas_ids = ["a"]
        with patch("blackoutkit.engines.appsscript._relay_request") as mock_relay:
            mock_relay.return_value = {
                "status": 200,
                "headers": {"Content-Type": "text/html", "Set-Cookie": ["c1", "c2"], "Transfer-Encoding": "chunked"},
                "body": "dGVzdA==" # "test" in b64
            }
            handler.do_GET() # calls _do_relay("GET")
            handler.wfile.write.assert_called_with(b"test")
            
        # Test _do_relay with full url
        handler.path = "http://example.com/foo"
        _GASProxyHandler.gas_ids = ["a", "b"]
        with patch("blackoutkit.engines.appsscript._relay_request") as mock_relay, \
             patch("base64.b64decode", side_effect=Exception("decode err")):
            mock_relay.side_effect = [None, {"status": 200, "headers": {}, "body": "!@#$"}] # first fails, second succeeds, body not b64 decodable
            handler.do_POST()
            handler.wfile.write.assert_called_with(b"!@#$") # fallback to encode()
            
        # Test _do_relay failure
        with patch("blackoutkit.engines.appsscript._relay_request", return_value=None):
            handler.do_PUT()
            handler.send_response.assert_called_with(502)

def test_silent_server():
    from blackoutkit.engines.appsscript import SilentThreadingTCPServer
    srv = SilentThreadingTCPServer(("127.0.0.1", 0), _GASProxyHandler, bind_and_activate=False)
    srv.handle_error(None, None) # covers line 237

@patch("blackoutkit.settings.load", return_value={})
@patch("blackoutkit.engines.appsscript._load_gas_ids", return_value=["a", "b"])
@patch("blackoutkit.engines.appsscript.AppsScriptEngine._verify_relay", return_value=False)
@patch("socketserver.TCPServer.server_bind", MagicMock())
@patch("socketserver.TCPServer.server_activate", MagicMock())
def test_engine_start_no_working_ids(mock_verify, mock_load_gas, mock_load):
    engine = AppsScriptEngine(0)
    assert engine.start() is True # fallback to all ids
    assert set(_GASProxyHandler.gas_ids) == {"a", "b"}

@patch("blackoutkit.settings.load", return_value={})
@patch("blackoutkit.engines.appsscript._load_gas_ids", return_value=["a"])
@patch("blackoutkit.engines.appsscript.AppsScriptEngine._verify_relay", return_value=True)
def test_engine_start_oserror(mock_verify, mock_load_gas, mock_load):
    engine = AppsScriptEngine(0)
    with patch("blackoutkit.engines.appsscript.SilentThreadingTCPServer", side_effect=OSError("port in use")):
        assert engine.start() is False

def test_engine_stop_exception():
    engine = AppsScriptEngine()
    engine._running = True
    mock_server = MagicMock()
    mock_server.shutdown.side_effect = Exception("err")
    engine._server = mock_server
    engine.stop() # covers lines 311-312
