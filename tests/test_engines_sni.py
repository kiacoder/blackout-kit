import pytest
from unittest.mock import patch, MagicMock
from blackoutkit.engines.sni import SNIEngine
import blackoutkit.settings as cfg

@patch("blackoutkit.settings.load")
def test_sni_engine_init(mock_load):
    mock_load.return_value = {
        "sni_connect_ip": "1.1.1.1",
        "sni_fake_sni": "google.com",
        "sni_listen_port": 1234
    }
    engine = SNIEngine()
    assert engine.connect_ip == "1.1.1.1"
    assert engine.fake_sni == "google.com"
    assert engine.listen_port == 1234
    
@patch("blackoutkit.settings.load")
def test_sni_engine_write_config(mock_load, tmp_path):
    mock_load.return_value = {
        "sni_connect_ip": "1.1.1.1",
        "sni_fake_sni": "google.com",
        "sni_listen_port": 1234
    }
    engine = SNIEngine()
    engine._config_dir = tmp_path
    path = engine._write_config()
    import json
    data = json.loads(path.read_text())
    assert data["CONNECT_IP"] == "1.1.1.1"
    assert data["FAKE_SNI"] == "google.com"

@patch("blackoutkit.core.get_core_dll")
@patch("blackoutkit.settings.load")
@patch("blackoutkit.engines.sni.SNIEngine.wait_for_port")
def test_sni_engine_start_success(mock_wait, mock_load, mock_get_dll, tmp_path):
    mock_load.return_value = {
        "sni_connect_ip": "1.1.1.1",
        "sni_fake_sni": "google.com",
        "sni_listen_port": 1234
    }
    engine = SNIEngine()
    engine._config_dir = tmp_path
    
    mock_dll = MagicMock()
    mock_dll.StartSNIC.return_value = 0
    mock_get_dll.return_value = mock_dll
    mock_wait.return_value = True
    
    assert engine.start() is True
    mock_dll.StartSNIC.assert_called_once()
    mock_wait.assert_called_once()

@patch("blackoutkit.core.get_core_dll", return_value=None)
@patch("blackoutkit.settings.load")
def test_sni_engine_start_no_dll(mock_load, mock_get_dll, tmp_path):
    mock_load.return_value = {
        "sni_connect_ip": "1.1.1.1",
        "sni_fake_sni": "google.com",
        "sni_listen_port": 1234
    }
    engine = SNIEngine()
    engine._config_dir = tmp_path
    assert engine.start() is False

@patch("blackoutkit.core.get_core_dll")
@patch("blackoutkit.settings.load")
def test_sni_engine_start_dll_fails(mock_load, mock_get_dll, tmp_path):
    mock_load.return_value = {
        "sni_connect_ip": "1.1.1.1",
        "sni_fake_sni": "google.com",
        "sni_listen_port": 1234
    }
    engine = SNIEngine()
    engine._config_dir = tmp_path
    
    mock_dll = MagicMock()
    mock_dll.StartSNIC.return_value = -1
    mock_get_dll.return_value = mock_dll
    
    assert engine.start() is False

@patch("blackoutkit.engines.sni.SNIEngine._run_auto_scan")
@patch("blackoutkit.core.get_core_dll")
@patch("blackoutkit.settings.load")
@patch("blackoutkit.settings.set_value")
@patch("blackoutkit.engines.sni.SNIEngine.wait_for_port")
def test_sni_engine_start_auto(mock_wait, mock_set, mock_load, mock_get_dll, mock_scan, tmp_path):
    mock_load.return_value = {
        "sni_connect_ip": "auto",
        "sni_fake_sni": "google.com",
        "sni_listen_port": 1234
    }
    mock_scan.return_value = "8.8.8.8"
    engine = SNIEngine()
    engine._config_dir = tmp_path
    
    mock_dll = MagicMock()
    mock_dll.StartSNIC.return_value = 0
    mock_get_dll.return_value = mock_dll
    mock_wait.return_value = True
    
    assert engine.start() is True
    mock_set.assert_called_with("sni_connect_ip", "8.8.8.8")
    assert engine.connect_ip == "8.8.8.8"

@patch("blackoutkit.engines.sni.SNIEngine._run_auto_scan", return_value=None)
@patch("blackoutkit.core.get_core_dll")
@patch("blackoutkit.settings.load")
def test_sni_engine_start_auto_fail(mock_load, mock_get_dll, mock_scan, tmp_path):
    mock_load.return_value = {
        "sni_connect_ip": "auto",
        "sni_fake_sni": "google.com",
        "sni_listen_port": 1234
    }
    engine = SNIEngine()
    engine._config_dir = tmp_path
    mock_get_dll.return_value = MagicMock()
    
    assert engine.start() is False

@patch("asyncio.new_event_loop")
@patch("blackoutkit.scanner.ip_scanner.scan_ips", new_callable=MagicMock)
@patch("blackoutkit.scanner.ip_scanner.generate_cloudflare_ips")
@patch("blackoutkit.settings.get")
def test_run_auto_scan_success(mock_get, mock_gen, mock_scan, mock_loop, tmp_path):
    def mock_settings_get(k, default=None):
        if k == "scan_ip_count": return 5
        if k == "scan_concurrency": return 5
        if k == "scan_timeout": return 1.0
        if k == "sni_always_test_all_ips": return False
        if k == "sni_custom_ips": return []
        if k == "sni_custom_fakes": return []
        return default
    mock_get.side_effect = mock_settings_get

    mock_loop_instance = MagicMock()
    mock_loop.return_value = mock_loop_instance
    mock_loop_instance.run_until_complete.side_effect = [
        [],
        [("2.2.2.2", 120.0), ("3.3.3.3", 150.0)]
    ]
    
    mock_dll = MagicMock()
    mock_dll.StartSNIC.return_value = 0
    
    engine = SNIEngine()
    engine._config_dir = tmp_path
    
    with patch.object(engine, "_test_http_get", return_value=50.0):
        winner = engine._run_auto_scan(mock_dll, tmp_path / "c.json")
    
    assert winner == "2.2.2.2"
    assert mock_dll.StartSNIC.call_count > 0
    assert mock_dll.StopSNIC.call_count > 0

@patch("asyncio.new_event_loop")
@patch("blackoutkit.scanner.ip_scanner.scan_ips", new_callable=MagicMock)
def test_run_auto_scan_no_ips(mock_scan, mock_loop, tmp_path):
    mock_loop_instance = MagicMock()
    mock_loop.return_value = mock_loop_instance
    mock_loop_instance.run_until_complete.return_value = []
    
    engine = SNIEngine()
    engine._config_dir = tmp_path
    
    winner = engine._run_auto_scan(MagicMock(), tmp_path / "c.json")
    assert winner is None

def test_test_http_get():
    engine = SNIEngine()

    class FakeSocket:
        def sendall(self, _data):
            pass

        def recv(self, _size):
            return b"HTTP/1.1 200 OK"

    class FakeWrappedSocket:
        def __enter__(self):
            return FakeSocket()

        def __exit__(self, *_args):
            return False

    class FakeSSLContext:
        def __init__(self, _protocol):
            self.options = 0
            self.minimum_version = None
            self.check_hostname = True
            self.verify_mode = None

        def wrap_socket(self, _sock, server_hostname):
            assert server_hostname == "google.com"
            return FakeWrappedSocket()

    fake_ssl = type("FakeSSL", (), {
        "SSLContext": FakeSSLContext,
        "PROTOCOL_TLS_CLIENT": 1,
        "TLSVersion": type("TLSVersion", (), {"TLS1_2": 2}),
        "OP_NO_SSLv2": 0,
        "OP_NO_SSLv3": 0,
        "OP_NO_TLSv1": 0,
        "OP_NO_TLSv1_1": 0,
        "CERT_NONE": 0,
    })

    with patch("socket.create_connection"), patch.dict("sys.modules", {"ssl": fake_ssl}):
        lat = engine._test_http_get("google.com")

    assert lat is not None

@patch("blackoutkit.core.get_core_dll")
@patch("blackoutkit.settings.load")
@patch("blackoutkit.engines.sni.SNIEngine.wait_for_port")
def test_sni_engine_start_wait_port_fails(mock_wait, mock_load, mock_get_dll, tmp_path):
    mock_load.return_value = {
        "sni_connect_ip": "1.1.1.1",
        "sni_fake_sni": "google.com",
        "sni_listen_port": 1234
    }
    engine = SNIEngine()
    engine._config_dir = tmp_path
    mock_dll = MagicMock()
    mock_dll.StartSNIC.return_value = 0
    mock_get_dll.return_value = mock_dll
    mock_wait.return_value = False
    
    with patch.object(engine, "stop") as mock_stop:
        assert engine.start() is False
        mock_stop.assert_called_once()

@patch("asyncio.new_event_loop")
@patch("blackoutkit.scanner.ip_scanner.scan_ips", new_callable=MagicMock)
@patch("blackoutkit.scanner.ip_scanner.generate_cloudflare_ips")
@patch("blackoutkit.settings.get")
def test_run_auto_scan_phase1_fast(mock_get, mock_gen, mock_scan, mock_loop, tmp_path):
    mock_get.side_effect = lambda k, d=None: 5 if k in ("scan_ip_count", "scan_concurrency") else (True if k == "sni_always_test_all_ips" else d)
    
    mock_loop_instance = MagicMock()
    mock_loop.return_value = mock_loop_instance
    mock_loop_instance.run_until_complete.return_value = [("4.4.4.4", 50.0), ("5.5.5.5", 60.0)]
    
    mock_dll = MagicMock()
    mock_dll.StartSNIC.side_effect = [-1, 0] # fail first time, succeed second
    
    engine = SNIEngine()
    engine._config_dir = tmp_path
    
    with patch.object(engine, "_test_http_get", side_effect=[Exception("crash"), None, 50.0, 50.0, 50.0]):
        # The exception covers lines 194-195
        # None covers lines 200 and 240
        winner = engine._run_auto_scan(mock_dll, tmp_path / "c.json")
    
    assert winner is not None

@patch("asyncio.new_event_loop")
@patch("blackoutkit.scanner.ip_scanner.scan_ips", new_callable=MagicMock)
@patch("blackoutkit.scanner.ip_scanner.generate_cloudflare_ips")
@patch("blackoutkit.settings.get")
def test_run_auto_scan_cached_ip(mock_get, mock_gen, mock_scan, mock_loop, tmp_path):
    def mock_settings_get(k, default=None):
        if k == "sni_connect_ip": return "cached.ip"
        if k == "sni_always_test_all_ips": return False
        if k == "sni_custom_ips": return ["custom.ip"]
        return default
    mock_get.side_effect = mock_settings_get
    
    mock_loop_instance = MagicMock()
    mock_loop.return_value = mock_loop_instance
    mock_loop_instance.run_until_complete.side_effect = [
        [],
        [("2.2.2.2", 120.0)]
    ]
    
    mock_dll = MagicMock()
    mock_dll.StartSNIC.return_value = 0
    
    engine = SNIEngine()
    engine._config_dir = tmp_path
    
    with patch.object(engine, "_test_http_get", return_value=50.0):
        winner = engine._run_auto_scan(mock_dll, tmp_path / "c.json")
    
    assert winner is not None

def test_test_http_get_no_http():
    engine = SNIEngine()

    class FakeSocket:
        def sendall(self, _data):
            pass

        def recv(self, _size):
            return b"GARBAGE DATA"

    class FakeWrappedSocket:
        def __enter__(self):
            return FakeSocket()

        def __exit__(self, *_args):
            return False

    class FakeSSLContext:
        def __init__(self, _protocol):
            self.options = 0
            self.minimum_version = None
            self.check_hostname = True
            self.verify_mode = None

        def wrap_socket(self, _sock, server_hostname):
            assert server_hostname == "google.com"
            return FakeWrappedSocket()

    fake_ssl = type("FakeSSL", (), {
        "SSLContext": FakeSSLContext,
        "PROTOCOL_TLS_CLIENT": 1,
        "TLSVersion": type("TLSVersion", (), {"TLS1_2": 2}),
        "OP_NO_SSLv2": 0,
        "OP_NO_SSLv3": 0,
        "OP_NO_TLSv1": 0,
        "OP_NO_TLSv1_1": 0,
        "CERT_NONE": 0,
    })

    with patch("socket.create_connection"), patch.dict("sys.modules", {"ssl": fake_ssl}):
        lat = engine._test_http_get("google.com")

    assert lat is None

def test_test_http_get_fail():
    engine = SNIEngine()
    with patch("socket.create_connection", side_effect=Exception("conn err")):
        lat = engine._test_http_get("google.com")
        assert lat is None


@patch("time.sleep", return_value=None)
@patch("asyncio.new_event_loop")
@patch("blackoutkit.scanner.ip_scanner.scan_ips", new_callable=MagicMock)
@patch("blackoutkit.scanner.ip_scanner.generate_cloudflare_ips")
@patch("blackoutkit.settings.get")
@patch("blackoutkit.settings.load")
def test_run_auto_scan_accepts_single_label_custom_host(
    mock_load,
    mock_get,
    _mock_generate,
    _mock_scan,
    mock_loop,
    _mock_sleep,
    tmp_path,
):
    mock_load.return_value = {
        "sni_connect_ip": "auto",
        "sni_fake_sni": "google.com",
        "sni_listen_port": 1234,
    }
    mock_get.side_effect = lambda key, default=None: {
        "scan_ip_count": 5,
        "scan_concurrency": 5,
        "scan_timeout": 1.0,
        "sni_always_test_all_ips": False,
        "sni_custom_ips": [],
        "sni_custom_fakes": ["www"],
    }.get(key, default)
    mock_loop_instance = MagicMock()
    mock_loop.return_value = mock_loop_instance
    mock_loop_instance.run_until_complete.side_effect = [[], [("2.2.2.2", 120.0)]]

    engine = SNIEngine()
    engine._config_dir = tmp_path
    mock_dll = MagicMock()
    mock_dll.StartSNIC.return_value = 0

    with patch.object(engine, "_test_http_get", return_value=50.0):
        winner = engine._run_auto_scan(mock_dll, tmp_path / "config.json")

    assert winner == "2.2.2.2"
