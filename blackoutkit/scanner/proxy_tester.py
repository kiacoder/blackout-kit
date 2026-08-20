"""
Blackout Kit - Proxy and connection tester.
Tests whether the system proxy and SNI engines are working.
"""
import socket
import threading
import time
import urllib.request
import urllib.error

# Lightweight test URLs — these return very small responses
TEST_URLS = [
    "http://cp.cloudflare.com/",          # Cloudflare connectivity page
    "http://www.google.com/generate_204", # Google captive portal check
    "http://detectportal.firefox.com/",   # Firefox connectivity check
]


def test_direct(timeout: int = 5) -> tuple[bool, float]:
    """
    Test direct internet connectivity (no proxy).
    Returns (connected: bool, latency_ms: float).
    """
    for url in TEST_URLS:
        try:
            start = time.monotonic()
            urllib.request.urlopen(url, timeout=timeout)
            return True, (time.monotonic() - start) * 1000
        except Exception:
            continue
    return False, 0.0


def test_tcp_port(host: str, port: int, timeout: float = 3.0) -> float | None:
    """
    Check if a TCP port is open.
    Returns latency_ms or None.
    """
    try:
        start = time.monotonic()
        with socket.create_connection((host, port), timeout=timeout):
            return (time.monotonic() - start) * 1000
    except Exception:
        return None


_httpx_clients = {}
_httpx_lock = threading.Lock()

def _get_httpx_client(proxy_url: str, timeout: int):
    import httpx
    with _httpx_lock:
        if proxy_url not in _httpx_clients:
            _httpx_clients[proxy_url] = httpx.Client(proxy=proxy_url, timeout=timeout)
        return _httpx_clients[proxy_url]

def _cleanup_httpx_clients():
    with _httpx_lock:
        for client in _httpx_clients.values():
            try:
                client.close()
            except Exception:
                pass
        _httpx_clients.clear()

def test_http_proxy(
    proxy_host: str = "127.0.0.1",
    proxy_port: int = 10809,
    test_url: str = "http://cp.cloudflare.com/",
    timeout: int = 10,
) -> float | None:
    """
    Test HTTP proxy connectivity with connection pooling.
    Returns latency_ms or None if proxy is unreachable/broken.
    """
    try:
        proxy_url = f"http://{proxy_host}:{proxy_port}"
        client = _get_httpx_client(proxy_url, timeout)
        start = time.monotonic()
        resp = client.get(test_url)
        if resp.status_code < 400:
            return (time.monotonic() - start) * 1000
    except ImportError:
        # Fallback to urllib if httpx is missing
        proxy_url = f"http://{proxy_host}:{proxy_port}"
        handler = urllib.request.ProxyHandler({
            "http":  proxy_url,
            "https": proxy_url,
        })
        opener = urllib.request.build_opener(handler)
        try:
            start = time.monotonic()
            opener.open(test_url, timeout=timeout)
            return (time.monotonic() - start) * 1000
        except Exception:
            return None
    except Exception:
        return None
    return None

def test_socks5_proxy(
    proxy_host: str = "127.0.0.1",
    proxy_port: int = 10808,
    test_url: str = "http://cp.cloudflare.com/",
    timeout: int = 10,
) -> float | None:
    """
    Test SOCKS5 proxy connectivity with connection pooling.
    Requires the 'httpx' package with SOCKS support.
    Returns latency_ms or None.
    """
    try:
        proxy_url = f"socks5://{proxy_host}:{proxy_port}"
        client = _get_httpx_client(proxy_url, timeout)
        start = time.monotonic()
        resp = client.get(test_url)
        if resp.status_code < 400:
            return (time.monotonic() - start) * 1000
    except Exception:
        pass
    return None


def full_connectivity_report(http_port: int = 10809, socks_port: int = 10808) -> dict:
    """
    Run a full connectivity check and return a summary dict.
    Keys: direct, sni_port_open, http_proxy, socks_proxy
    """
    report = {}
    report["direct"] = test_direct()[0]
    report["http_proxy_port_open"] = test_tcp_port("127.0.0.1", http_port) is not None
    report["socks_proxy_port_open"] = test_tcp_port("127.0.0.1", socks_port) is not None
    report["http_proxy_latency"] = test_http_proxy(proxy_port=http_port)
    report["socks_proxy_latency"] = test_socks5_proxy(proxy_port=socks_port)
    return report
