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
    Always prioritizes custom user IPs, then known-good IPs, then samples from CF ranges.
    """
    custom_ips = []
    
    # 1. From settings
    try:
        from .. import settings as cfg
        custom_ips.extend(cfg.get("sni_custom_ips") or [])
    except Exception:
        pass
        
    # 2. From data/custom_ips.txt
    try:
        from pathlib import Path
        custom_file = Path(__file__).parent.parent.parent / "data" / "custom_ips.txt"
        if custom_file.exists():
            lines = custom_file.read_text(encoding="utf-8").splitlines()
            for line in lines:
                cleaned = line.strip()
                if cleaned and not cleaned.startswith("#"):
                    custom_ips.append(cleaned)
    except Exception:
        pass

    # Unique list preserving order of custom IPs
    seen = set()
    unique_custom = []
    for ip in custom_ips:
        if ip not in seen:
            seen.add(ip)
            unique_custom.append(ip)

    ips: set[str] = set(KNOWN_GOOD_IPS)
    ips.difference_update(seen)
    
    remaining = max(0, count - len(unique_custom) - len(ips))

    if remaining > 0:
        per_range = max(1, remaining // len(CLOUDFLARE_RANGES))
        for cidr in CLOUDFLARE_RANGES:
            try:
                network = ipaddress.IPv4Network(cidr)
                num_addresses = network.num_addresses
                sample_count = min(per_range, num_addresses)
                for _ in range(sample_count):
                    ip_obj = network[random.randrange(num_addresses)]
                    ip_str = str(ip_obj)
                    if ip_str not in seen:
                        ips.add(ip_str)
            except Exception:
                continue

    result = list(ips)
    random.shuffle(result)
    
    final_list = unique_custom + result
    return final_list[:count]


async def scan_ips(
    ips: list[str],
    port: int = 443,
    concurrency: int = 100,
    timeout: float = 2.0,
    progress_callback=None,
) -> list[tuple[str, float]]:
    """
    Scan a list of IPs concurrently using the high-performance Go DLL.
    Returns sorted list of (ip, latency_ms) for reachable IPs.
    """
    return scan_sync(ips, port=port, concurrency=concurrency, timeout=timeout, progress_callback=progress_callback)


def scan_sync(ips: list[str], port: int = 443, concurrency: int = 100, timeout: float = 2.0, progress_callback=None) -> list[tuple[str, float]]:
    """Synchronous wrapper using Go DLL."""
    from ..core import get_core_dll
    import ctypes
    dll = get_core_dll()
    if not dll:
        # Fallback if DLL fails to load (very unlikely now)
        return []

    if progress_callback:
        progress_callback()

    ips_str = ",".join(ips)
    c_res_ptr = dll.ScanIPsC(ips_str.encode("utf-8"), port, concurrency, int(timeout * 1000))
    if not c_res_ptr:
        return []

    c_res_str = ctypes.cast(c_res_ptr, ctypes.c_char_p).value
    if not c_res_str:
        return []

    result_str = c_res_str.decode("utf-8")
    if not result_str:
        return []

    results = []
    for chunk in result_str.split(","):
        chunk = chunk.strip()
        if not chunk or "|" not in chunk:
            continue
        try:
            ip, lat_str = chunk.split("|", 1)
            ip = ip.strip()
            lat = float(lat_str.strip())
            results.append((ip, lat))
        except (ValueError, IndexError) as e:
            import logging
            logging.debug(f"Malformed IP scan result chunk: {chunk!r} ({e})")
            continue

    return results


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
        try:
            with os.fdopen(fd, "w") as f:
                _json.dump(data, f, indent=2)
            os.replace(path, _CACHE_FILE)
        except Exception:
            try:
                os.unlink(path)
            except OSError:
                pass
            raise
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
