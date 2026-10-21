"""Tests for the v2 IPC client and the socks-tunnel engine supervisor."""
import json
import socket
import struct
import threading

import pytest

from blackoutkit import v2_ipc
from blackoutkit.v2_ipc import (
    API_VERSION,
    IPCError,
    IPCProtocolError,
    CoreClient,
    decode_envelope,
    default_endpoint,
    encode_envelope,
    encode_frame,
    read_frame,
    validate_endpoint,
)


MAGIC = b"BKV2"


class FakeCore:
    """A minimal blackout-core speaking the real framing on a TCP socket.

    It accepts one client connection, answers handshake/start/stop/status in
    order, and records the requests so tests can assert the exact wire shape.
    """

    def __init__(self, responses=None):
        self._responses = responses or {}
        self.requests = []
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def url(self):
        return f"127.0.0.1:{self.port}"

    def close(self):
        self._sock.close()

    def _serve(self):
        try:
            conn, _ = self._sock.accept()
        except OSError:
            return
        buf = b""

        def read(n):
            nonlocal buf
            while len(buf) < n:
                chunk = conn.recv(4096)
                if not chunk:
                    raise EOFError
                buf += chunk
            out, buf = buf[:n], buf[n:]
            return out

        try:
            while True:
                header = read(8)
                if header[:4] != MAGIC:
                    return
                length = struct.unpack(">I", header[4:8])[0]
                body = read(length)
                env = json.loads(body.decode("utf-8"))
                if env.get("kind") != "request":
                    return
                self.requests.append(env)
                method = env["method"]
                payload = self._responses.get(method)
                if payload is None:
                    payload = {
                        "handshake": {"api_version": API_VERSION, "methods": ["start", "stop"], "pid": 1},
                        "ping": {"ok": True},
                        "start": {"engine": "socks-tunnel", "status": "running", "listen": "127.0.0.1:18080"},
                        "stop": {"engine": "socks-tunnel", "status": "stopped"},
                        "status": {"engine": "socks-tunnel", "status": "running"},
                        "tune": {"fake_sni": "www.example.com"},
                    }.get(method)
                if isinstance(payload, dict) and payload.get("force_error"):
                    reply = {"v": "2.0.0", "kind": "response", "id": env["id"],
                             "error": {"code": payload["force_error"], "message": "nope"}}
                else:
                    reply = {"v": "2.0.0", "kind": "response", "id": env["id"], "payload": payload}
                body_out = json.dumps(reply, separators=(",", ":")).encode("utf-8")
                conn.sendall(MAGIC + struct.pack(">I", len(body_out)) + body_out)
        except (EOFError, OSError):
            pass


# ── framing ──────────────────────────────────────────────────────────────────

def test_envelope_round_trip():
    raw = encode_envelope("request", method="start", id="abc", params={"engine": "socks-tunnel"})
    env = decode_envelope(raw)
    assert env["kind"] == "request"
    assert env["method"] == "start"
    assert env["id"] == "abc"
    assert env["params"] == {"engine": "socks-tunnel"}


def test_request_requires_method():
    with pytest.raises(ValueError):
        encode_envelope("request", id="x")


def test_frame_layout_matches_go():
    body = b'{"v":"2.0.0","kind":"request","method":"ping"}'
    frame = encode_frame(body)
    assert frame[:4] == MAGIC
    assert frame[4:8] == len(body).to_bytes(4, "big")
    assert frame[8:] == body


def test_frame_too_large_rejected():
    import pytest
    with pytest.raises(IPCProtocolError):
        encode_frame(b"x" * (v2_ipc.MAX_FRAME_SIZE + 1))


def test_read_frame_rejects_bad_magic():
    import io
    stream = io.BytesIO(b"XXXX" + (0).to_bytes(4, "big"))
    with pytest.raises(IPCProtocolError):
        read_frame(stream.read)


def test_read_frame_rejects_absurd_length():
    import io
    stream = io.BytesIO(MAGIC + (v2_ipc.MAX_FRAME_SIZE + 1).to_bytes(4, "big"))
    with pytest.raises(IPCProtocolError):
        read_frame(stream.read)


# ── endpoint validation ──────────────────────────────────────────────────────

def test_validate_endpoint_rejects_empty():
    with pytest.raises(ValueError):
        validate_endpoint("  ")


def test_validate_endpoint_windows_pipe():
    if v2_ipc.sys.platform == "win32":
        assert validate_endpoint(r"\\.\pipe\blackout_ipc") == r"\\.\pipe\blackout_ipc"
    else:
        with pytest.raises(ValueError):
            validate_endpoint(r"\\.\pipe\blackout_ipc")


def test_validate_endpoint_unix_style():
    if v2_ipc.sys.platform == "win32":
        with pytest.raises(ValueError):
            validate_endpoint("/tmp/blackout_ipc")
    else:
        assert validate_endpoint("/tmp/blackout_ipc") == "/tmp/blackout_ipc"


def test_default_endpoint_is_loopback_scoped():
    ep = default_endpoint()
    assert "blackout_ipc" in ep


# ── client against a protocol-faithful fake daemon ──────────────────────────

def test_client_handshake_start_stop_round_trip():
    fake = FakeCore()
    try:
        # CoreClient only opens pipes on win32 and unix sockets elsewhere; the
        # fake speaks TCP, so patch the transport just for this test.
        client = CoreClient.__new__(CoreClient)
        client.endpoint = fake.url()
        client.connect_timeout = 5.0
        client._io = None
        client._write_lock = threading.Lock()
        client._id_counter = 0
        client._open_transport = lambda: _make_tcp(fake.url())
        client.connect()

        hello = client.handshake()
        assert hello["api_version"] == API_VERSION
        assert client.ping() is True

        result = client.start("socks-tunnel", {"listen": "127.0.0.1:18080"})
        assert result["status"] == "running"
        assert result["listen"] == "127.0.0.1:18080"

        stopped = client.stop()
        assert stopped["status"] == "stopped"

        start_request = fake.requests[-2]
        assert start_request["method"] == "start"
        assert start_request["params"]["engine"] == "socks-tunnel"
        assert start_request["params"]["config"]["listen"] == "127.0.0.1:18080"
        assert start_request["v"] == API_VERSION
        client.close()
    finally:
        fake.close()


def test_client_surfaces_structured_errors():
    fake = FakeCore(responses={"start": {"force_error": "engine_failure"}})
    try:
        client = CoreClient.__new__(CoreClient)
        client.endpoint = fake.url()
        client.connect_timeout = 5.0
        client._io = None
        client._write_lock = threading.Lock()
        client._id_counter = 0
        client._open_transport = lambda: _make_tcp(fake.url())
        with pytest.raises(IPCError) as excinfo:
            client.start("socks-tunnel")
        assert excinfo.value.code == "engine_failure"
        client.close()
    finally:
        fake.close()


def _make_tcp(url):
    host, port = url.split(":")
    sock = socket.socket()
    sock.settimeout(5.0)
    sock.connect((host, int(port)))
    sock.settimeout(None)
    return sock


# ── engine wiring ────────────────────────────────────────────────────────────

def test_engine_registered():
    from blackoutkit.engines import ENGINE_REGISTRY, SocksTunnelEngine
    assert ENGINE_REGISTRY["socks-tunnel"] is SocksTunnelEngine
    assert SocksTunnelEngine.name == "socks-tunnel"


def test_engine_in_public_choices():
    from blackoutkit.cli import ALL_ENGINE_CHOICES
    assert "socks-tunnel" in ALL_ENGINE_CHOICES
    from blackoutkit.capabilities import PUBLIC_ENGINE_NAMES
    assert "socks-tunnel" in PUBLIC_ENGINE_NAMES


def test_capability_declared():
    from blackoutkit.capabilities import _CAPABILITIES
    from blackoutkit.routing import platform_engines
    cap = _CAPABILITIES["socks-tunnel"]
    assert cap.local_proxy is True
    assert "v2_tunnel_port" in cap.local_ports
    assert "socks-tunnel" in platform_engines("win32")
    assert "socks-tunnel" not in platform_engines("linux")


def test_proxy_details_map_to_tunnel_port():
    from blackoutkit import settings
    host, port = settings.get_engine_proxy_details("socks-tunnel", {"v2_tunnel_port": 18081})
    assert host == "socks=127.0.0.1"
    assert port == 18081


def test_engine_start_fails_cleanly_without_binary(monkeypatch, tmp_path):
    from blackoutkit.engines.socks_tunnel import SocksTunnelEngine
    engine = SocksTunnelEngine()
    monkeypatch.delenv("BLACKOUT_CORE_BIN", raising=False)
    monkeypatch.setattr(engine, "find_binary", lambda names, system_names=None: None)
    monkeypatch.setattr(engine, "check_port_free", lambda port, host="127.0.0.1": True)
    # find_core_binary must not crash when nothing is installed; start returns False.
    monkeypatch.setattr(engine, "find_core_binary", lambda: None)
    assert engine.start() is False


def test_setting_registered():
    from blackoutkit import settings
    assert "v2_tunnel_port" in settings.DEFAULTS
    assert settings.validate("v2_tunnel_port", 18080)[0] is True
    assert settings.validate("v2_tunnel_port", "not-a-port")[0] is False


# ── release-asset download path ──────────────────────────────────────────────

def test_blackout_core_registry_entry_is_platform_correct():
    import sys
    from blackoutkit.downloader import BIN_REGISTRY
    info = BIN_REGISTRY["blackout-core"]
    assert info.github_repo == "kiacoder/blackout-kit"
    if sys.platform == "win32":
        assert info.output_bins == ["blackout-core.exe"]
        assert list(info.extract_map) == ["blackout-core-windows-amd64.exe"]
    else:
        assert info.output_bins == ["blackout-core"]
        assert list(info.extract_map) == ["blackout-core-linux-amd64"]


def test_blackout_core_registry_key_is_downloadable():
    from blackoutkit.downloader import BIN_REGISTRY
    # The verified download path requires a trusted github_repo and an
    # extract_map pattern per output; anything else is manual-only.
    info = BIN_REGISTRY["blackout-core"]
    assert info.github_repo and info.extract_map
    assert len(info.extract_map) == len(info.output_bins)


def test_readiness_requires_blackout_core_runtime():
    from blackoutkit import readiness
    checks = readiness._binary_checks(
        "socks-tunnel", installed={}, platform="win32", settings={})
    names = [check.name for check in checks]
    assert "Runtime: blackout-core" in names
    missing = next(check for check in checks if check.name == "Runtime: blackout-core")
    assert missing.ok is False

    present = readiness._binary_checks(
        "socks-tunnel", installed={"blackout-core": True}, platform="win32", settings={})
    ok = next(check for check in present if check.name == "Runtime: blackout-core")
    assert ok.ok is True


def test_check_installed_covers_blackout_core(tmp_path, monkeypatch):
    """A PE-valid blackout-core.exe in bins/ counts as installed."""
    import sys
    from blackoutkit import downloader
    if sys.platform != "win32":
        import pytest
        pytest.skip("PE structural check is Windows-shaped")
    monkeypatch.setattr(downloader, "BINS_DIR", tmp_path)
    provenance = tmp_path / ".provenance.json"
    provenance.write_text("{}", encoding="utf-8")
    if hasattr(downloader, "_PROVENANCE_FILE"):
        monkeypatch.setattr(downloader, "_PROVENANCE_FILE", provenance)
    import struct
    # Minimal PE: "MZ" + padding + e_lfanew pointing EXACTLY at "PE\0\0".
    e_lfanew = 0x40
    data = b"MZ" + b"\x00" * (e_lfanew - 6) + struct.pack("<I", e_lfanew) + b"PE\x00\x00"
    (tmp_path / "blackout-core.exe").write_bytes(data)
    installed = downloader.check_installed()
    assert installed.get("blackout-core") is True
