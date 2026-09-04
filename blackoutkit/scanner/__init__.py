"""
Blackout Kit — Scanner package public API.

Re-exports the most useful names from ip_scanner and proxy_tester so callers
can write:

    from blackoutkit.scanner import quick_scan, is_connected

instead of importing from the individual sub-modules.

Rare upgrades:
  - Clean public re-exports from both sub-modules
  - quick_scan(count): one-call convenience wrapper (scan + return best IPs)
  - is_connected(): single boolean — "is the proxy/internet working right now?"
  - best_ip(): return the single fastest Cloudflare IP from a fresh scan
"""

from .ip_scanner import (
    cache_age_str,
    check_ip,
    generate_cloudflare_ips,
    load_cache,
    save_cache,
    scan_ips,
    scan_sync,
)
from .proxy_tester import (
    full_connectivity_report,
    test_direct,
    test_http_proxy,
    test_socks5_proxy,
    test_tcp_port,
)


def quick_scan(count: int = 50) -> list[tuple[str, float]]:
    """
    Convenience wrapper: generate `count` Cloudflare IPs, scan them,
    and return results sorted by latency (fastest first).

    Returns a list of (ip, latency_ms) tuples.
    Results are also saved to the IP cache automatically.

    Usage:
        results = quick_scan(50)
        best_ip = results[0][0] if results else None
    """
    ips = generate_cloudflare_ips(count)
    results = scan_sync(ips)
    if results:
        save_cache(results)
    return results


def best_ip(count: int = 50) -> str | None:
    """
    Scan `count` Cloudflare IPs and return the single fastest one.
    Returns None if no IPs respond.

    Usage:
        ip = best_ip()
        if ip:
            settings.set_value("sni_connect_ip", ip)
    """
    results = quick_scan(count)
    return results[0][0] if results else None


def is_connected(
    http_port: int = 10809,
    direct_fallback: bool = True,
) -> bool:
    """
    Return True if the machine has working internet right now.

    Checks in order:
      1. HTTP proxy on http_port (proxy is up and working)
      2. Direct internet (if direct_fallback=True)

    Usage:
        if not is_connected():
            start_emergency_mode()
    """
    # Try proxy first
    proxy_latency = test_http_proxy(proxy_port=http_port)
    if proxy_latency is not None:
        return True
    # Fallback: direct internet
    if direct_fallback:
        return test_direct()[0]
    return False


__all__ = [
    "best_ip",
    "cache_age_str",
    # From ip_scanner
    "check_ip",
    "full_connectivity_report",
    "generate_cloudflare_ips",
    "is_connected",
    "load_cache",
    # Package-level helpers
    "quick_scan",
    "save_cache",
    "scan_ips",
    "scan_sync",
    # From proxy_tester
    "test_direct",
    "test_http_proxy",
    "test_socks5_proxy",
    "test_tcp_port",
]
