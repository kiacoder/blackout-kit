"""
Blackout Kit - Async Cloudflare IP scanner.
Tests hundreds of Cloudflare IPs in parallel using asyncio.
Finds the lowest-latency reachable IP for the SNI engine.
"""
import asyncio
import ipaddress
import random
import time

# Official Cloudflare IPv4 CIDR ranges (from https://www.cloudflare.com/ips/)
CLOUDFLARE_RANGES = [
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "108.162.192.0/18",
    "131.0.72.0/22",
    "141.101.64.0/18",
    "162.158.0.0/15",
    "172.64.0.0/13",
    "173.245.48.0/20",
    "188.114.96.0/20",
    "190.93.240.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
]

# Pre-tested IPs known to work well with SNI spoofing
KNOWN_GOOD_IPS = [
    "104.19.229.21",
    "104.21.0.1",
    "104.17.1.1",
    "104.16.1.1",
    "188.114.98.0",
    "188.114.99.0",
    "172.64.0.1",
    "172.67.0.1",
    "162.159.0.1",
    "162.158.0.1",
    "108.162.192.1",
    "141.101.64.1",
]


async def check_ip(ip: str, port: int = 443, timeout: float = 2.0) -> tuple[str, float] | None:
    """
    Test TCP reachability of ip:port.
    Returns (ip, latency_ms) on success, None on failure.
    """
    try:
        start = time.monotonic()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        latency = (time.monotonic() - start) * 1000
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
        except Exception:
            pass
        return ip, round(latency, 1)
    except Exception:
        return None


def generate_cloudflare_ips(count: int = 100) -> list[str]:
    """
    Generate a list of Cloudflare IPs to scan.
    Always includes known-good IPs first, then samples from CF ranges.
    Uses efficient indexing to avoid memory spikes on large CIDR blocks.
    """
    ips: set[str] = set(KNOWN_GOOD_IPS)
    remaining = max(0, count - len(ips))

    if remaining > 0:
        per_range = max(1, remaining // len(CLOUDFLARE_RANGES))
        for cidr in CLOUDFLARE_RANGES:
            try:
                network = ipaddress.IPv4Network(cidr)
                num_addresses = network.num_addresses
                # We need to sample from num_addresses, but skip network/broadcast
                # num_addresses includes them. We'll pick random indices.
                sample_count = min(per_range, num_addresses)
                for _ in range(sample_count):
                    # random.randrange(num_addresses) gives an index in the network
                    ip_obj = network[random.randrange(num_addresses)]
                    ips.add(str(ip_obj))
            except Exception:
                continue

    result = list(ips)
    random.shuffle(result)
    return result[:count]


async def scan_ips(
    ips: list[str],
    port: int = 443,
    concurrency: int = 100,
    timeout: float = 2.0,
    progress_callback=None,
) -> list[tuple[str, float]]:
    """
    Scan a list of IPs concurrently.
    Returns sorted list of (ip, latency_ms) for reachable IPs.
    """
    semaphore = asyncio.Semaphore(concurrency)

    async def bounded(ip: str):
        async with semaphore:
            result = await check_ip(ip, port, timeout)
            if progress_callback:
                progress_callback()
            return result

    results = await asyncio.gather(*[bounded(ip) for ip in ips])
    working = [r for r in results if r is not None]
    return sorted(working, key=lambda x: x[1])


def scan_sync(ips: list[str], **kwargs) -> list[tuple[str, float]]:
    """Synchronous wrapper for scan_ips."""
    return asyncio.run(scan_ips(ips, **kwargs))


# ─────────────────────────── Cache ───────────────────────────────

import json as _json
from pathlib import Path as _Path
from datetime import datetime as _dt, timezone as _tz

_CACHE_FILE = _Path.home() / ".blackout-kit" / "scan_cache.json"
_CACHE_MAX_AGE_HOURS = 12


def save_cache(results: list[tuple[str, float]]):
    """Save scan results to disk cache safely."""
    try:
        _CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "timestamp": _dt.now(_tz.utc).isoformat(),
            "results": [[ip, ms] for ip, ms in results],
        }
        import tempfile
        import os
        fd, path = tempfile.mkstemp(dir=_CACHE_FILE.parent, suffix=".tmp")
        with os.fdopen(fd, "w") as f:
            _json.dump(data, f, indent=2)
        os.replace(path, _CACHE_FILE)
    except Exception:
        pass


def load_cache(max_age_hours: float = _CACHE_MAX_AGE_HOURS) -> list[tuple[str, float]] | None:
    """
    Load cached scan results if they are still fresh.
    Returns None if cache is missing or too old.
    """
    if not _CACHE_FILE.exists():
        return None
    try:
        data  = _json.loads(_CACHE_FILE.read_text())
        ts    = _dt.fromisoformat(data["timestamp"])
        age_h = (_dt.now(_tz.utc) - ts).total_seconds() / 3600
        if age_h > max_age_hours:
            return None
        return [(r[0], r[1]) for r in data["results"]]
    except Exception:
        return None


def cache_age_str() -> str | None:
    """Return human-readable age of the cache, or None if no cache."""
    if not _CACHE_FILE.exists():
        return None
    try:
        data = _json.loads(_CACHE_FILE.read_text())
        ts   = _dt.fromisoformat(data["timestamp"])
        secs = int((_dt.now(_tz.utc) - ts).total_seconds())
        if secs < 60:
            return f"{secs}s ago"
        if secs < 3600:
            return f"{secs // 60}m ago"
        return f"{secs // 3600}h ago"
    except Exception:
        return None
