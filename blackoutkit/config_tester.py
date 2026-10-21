"""Batch tester for saved proxy configs — the desktop counterpart of the
mobile app's library tester.

Each saved config points at a server address (host:port). The cheapest
honest signal of "is this server alive and how fast is it" is a real TCP
connect to that endpoint with a bounded timeout, run concurrently across
all configs. This is not a full tunnel test (that needs an engine start
per config); it is the prefilter that answers "which servers are worth
connecting to", ranked by latency. `blackout fast` uses it to pick the
best config, and `blackout test` prints the full picture.
"""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from .config.manager import load_configs

DEFAULT_TIMEOUT_S = 3.0
DEFAULT_CONCURRENCY = 32

# Protocols whose servers listen on UDP first. A TCP connect probe cannot
# see them at all - "timeout" there is a limitation of the probe, not a dead
# server, and reporting it as unreachable is a lie the user pays for.
# AnyTLS and ShadowTLS are NOT here: they are TCP+TLS obfuscators, so the
# probe sees them normally. AWG (WireGuard family) is UDP.
_UDP_FIRST_PROTOCOLS = frozenset({"hysteria2", "hy2", "tuic", "awg"})


@dataclass
class ConfigTestResult:
    index: int                 # position in the saved config list
    protocol: str
    address: str
    port: int
    name: str
    latency_ms: float | None   # None == unreachable
    error: str = ""

    @property
    def alive(self) -> bool:
        return self.latency_ms is not None


def _probe(address: str, port: int, timeout: float) -> tuple[float | None, str]:
    try:
        start = time.monotonic()
        with socket.create_connection((address, port), timeout=timeout):
            latency = (time.monotonic() - start) * 1000.0
        return latency, ""
    except socket.timeout:
        return None, "timeout"
    except OSError as exc:
        return None, str(exc)


def test_configs(
    timeout: float = DEFAULT_TIMEOUT_S,
    concurrency: int = DEFAULT_CONCURRENCY,
) -> list[ConfigTestResult]:
    """Probe every saved config concurrently; results in list order."""
    configs = load_configs()
    results: list[ConfigTestResult] = []
    targets: list[tuple[int, str, int, str, str]] = []

    for i, c in enumerate(configs):
        protocol = getattr(c, "protocol", "?") or "?"
        address = getattr(c, "address", "") or ""
        port = getattr(c, "port", 0)
        name = getattr(c, "name", "") or ""
        if isinstance(address, str) and address.strip() and isinstance(port, int) and 1 <= port <= 65535:
            if protocol.lower() in _UDP_FIRST_PROTOCOLS:
                # Not TCP-testable: report honestly instead of faking a death.
                results.append(ConfigTestResult(i, protocol, address.strip(), port, name, None, "udp"))
                continue
            targets.append((i, protocol, address.strip(), port, name))
        else:
            results.append(ConfigTestResult(i, protocol, address, port, name, None, "no address"))

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futures = {
            pool.submit(_probe, address, port, timeout): (i, protocol, address, port, name)
            for (i, protocol, address, port, name) in targets
        }
        for future, (i, protocol, address, port, name) in futures.items():
            latency, error = future.result()
            results.append(ConfigTestResult(i, protocol, address, port, name, latency, error))

    results.sort(key=lambda r: r.index)
    return results


def pick_best(results: list[ConfigTestResult]) -> ConfigTestResult | None:
    """Lowest-latency reachable config, or None when nothing answers."""
    reachable = [r for r in results if r.alive]
    if not reachable:
        return None
    return min(reachable, key=lambda r: r.latency_ms)
