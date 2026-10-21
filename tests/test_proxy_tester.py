import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import MagicMock, patch

import pytest

from blackoutkit.scanner import proxy_tester


class _LocalHttpProxyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("http://"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_error(400)

    def log_message(self, *_args):
        pass


@pytest.fixture
def local_http_proxy():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _LocalHttpProxyHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


@pytest.fixture
def local_socks5_proxy():
    requests = []
    server_socket = socket.socket()
    server_socket.bind(("127.0.0.1", 0))
    server_socket.listen()
    server_socket.settimeout(2)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                connection, _address = server_socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with connection:
                connection.settimeout(2)
                greeting = connection.recv(2)
                if greeting != b"\x05\x01":
                    continue
                methods = connection.recv(1)
                if not methods or methods[0] != 0:
                    continue
                connection.sendall(b"\x05\x00")
                request = connection.recv(4)
                if len(request) != 4 or request[:3] != b"\x05\x01\x00":
                    continue
                if request[3] == 3:
                    size = connection.recv(1)[0]
                    host = connection.recv(size).decode("ascii")
                elif request[3] == 1:
                    host = socket.inet_ntoa(connection.recv(4))
                else:
                    continue
                port = int.from_bytes(connection.recv(2), "big")
                requests.append((host, port))
                connection.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50")
                data = bytearray()
                while b"\r\n\r\n" not in data:
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    data.extend(chunk)
                if bytes(data).startswith(b"GET / HTTP/1.1"):
                    connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield server_socket.getsockname(), requests
    finally:
        stop.set()
        server_socket.close()
        thread.join(timeout=2)


def test_http_proxy_uses_http_proxy_request(local_http_proxy):
    host, port = local_http_proxy

    latency = proxy_tester.test_http_proxy(host, port, test_url="http://example.test/", timeout=1)

    assert latency is not None


def test_socks5_proxy_performs_handshake_and_proxied_request(local_socks5_proxy):
    (host, port), requests = local_socks5_proxy

    latency = proxy_tester.test_socks5_proxy(host, port, test_url="http://example.test/", timeout=1)

    assert latency is not None
    assert requests == [("example.test", 80)]


def test_socks5_proxy_rejects_unusable_proxy():
    with socket.socket() as unavailable:
        unavailable.bind(("127.0.0.1", 0))
        host, port = unavailable.getsockname()

    assert proxy_tester.test_socks5_proxy(host, port, test_url="http://example.test/", timeout=0.2) is None


def test_http_proxy_client_cache_separates_probe_timeouts():
    proxy_tester._cleanup_httpx_clients()
    clients = []

    def make_client(*, proxy, timeout):
        client = MagicMock()
        client.proxy = proxy
        client.timeout = timeout
        clients.append(client)
        return client

    with patch("httpx.Client", side_effect=make_client):
        long_timeout = proxy_tester._get_httpx_client("http://127.0.0.1:10809", 5)
        bounded_timeout = proxy_tester._get_httpx_client("http://127.0.0.1:10809", 0.2)

    assert long_timeout is not bounded_timeout
    assert long_timeout.timeout == 5
    assert bounded_timeout.timeout == 0.2
    assert len(clients) == 2
    proxy_tester._cleanup_httpx_clients()


def test_http_proxy_enforces_total_probe_deadline(monkeypatch):
    import threading
    import time

    entered_stream = threading.Event()
    never_release = threading.Event()

    class SlowResponse:
        status_code = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def iter_bytes(self):
            never_release.wait()
            yield b"late"

    class SlowClient:
        def stream(self, _method, _url, *, timeout):
            assert timeout == 0.2
            entered_stream.set()
            never_release.wait()
            return SlowResponse()

    monkeypatch.setattr(proxy_tester, "_get_httpx_client", lambda *_args: SlowClient())
    started = time.monotonic()

    assert proxy_tester.test_http_proxy(timeout=0.2) is None
    assert entered_stream.is_set()
    assert time.monotonic() - started < 0.5
    never_release.set()


def test_http_proxy_caps_outstanding_blocked_probe_workers(monkeypatch):
    import threading

    release_workers = threading.Event()
    started = []
    start_lock = threading.Lock()

    class BlockingResponse:
        status_code = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def iter_bytes(self):
            release_workers.wait()
            yield b"done"

    class BlockingClient:
        def stream(self, *_args, **_kwargs):
            with start_lock:
                started.append(True)
            release_workers.wait()
            return BlockingResponse()

    monkeypatch.setattr(proxy_tester, "_proxy_probe_slots", threading.BoundedSemaphore(4))
    monkeypatch.setattr(proxy_tester, "_get_httpx_client", lambda *_args: BlockingClient())

    results = []
    callers = [
        threading.Thread(
            target=lambda: results.append(
                proxy_tester.test_http_proxy(timeout=0.05)
            )
        )
        for _ in range(4)
    ]
    for caller in callers:
        caller.start()
    for caller in callers:
        caller.join()

    started_before_extra_probe = len(started)
    assert started_before_extra_probe == 4
    assert proxy_tester.test_http_proxy(timeout=0.05) is None
    assert len(started) == started_before_extra_probe
    release_workers.set()
    assert results == [None] * 4


def test_http_proxy_cache_reuses_matching_timeout():
    proxy_tester._cleanup_httpx_clients()
    with patch("httpx.Client") as client_factory:
        first = proxy_tester._get_httpx_client("http://127.0.0.1:10809", 0.2)
        second = proxy_tester._get_httpx_client("http://127.0.0.1:10809", 0.2)

    assert second is first
    client_factory.assert_called_once_with(proxy="http://127.0.0.1:10809", timeout=0.2)
    proxy_tester._cleanup_httpx_clients()
