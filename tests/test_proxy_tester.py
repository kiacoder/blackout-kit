from unittest.mock import MagicMock, patch

from blackoutkit.scanner import proxy_tester


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
    import time

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
