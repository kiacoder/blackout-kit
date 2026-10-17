"""Batch config verification — does each config actually load a website?

The mobile client learned this the hard way: a config whose port opens proves
nothing. A REALITY server that rejects the handshake accepts TCP, opens its
listener and then closes every request with EOF, so "the port is open" and
"the tunnel works" are different questions.

This module asks the second question for every saved config, the same way the
phone does: start the config in its own short-lived core on a private port,
fetch a real URL through it, record the latency, shut the core down. Checks run
in parallel, so N configs cost roughly one config's worth of wall time.

Usage:
    python -m blackoutkit.config_check            # all saved configs
    python -m blackoutkit.config_check --workers 2
    python -m blackoutkit.config_check --json
"""

from __future__ import annotations

import argparse
import concurrent.futures as futures
import json
import socket
import sys
import time
from dataclasses import asdict, dataclass

# Two independent endpoints: one blocked host should not condemn a good config.
CHECK_URLS = (
    "http://www.gstatic.com/generate_204",
    "http://cp.cloudflare.com/generate_204",
)


@dataclass
class CheckResult:
    index: int
    name: str
    protocol: str
    address: str
    ok: bool
    latency_ms: float | None
    error: str = ""


def _free_port() -> int:
    """Ask the OS for an unused loopback port."""
    probe = socket.socket()
    try:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]
    finally:
        probe.close()


def _check_one(index: int, config, timeout: float) -> CheckResult:
    """Start one config in a private core and fetch a real URL through it."""
    from .engines.xray import XRayEngine

    socks_port = _free_port()
    http_port = _free_port()
    engine = XRayEngine(
        proxy_config=config,
        socks_port=socks_port,
        http_port=http_port,
    )
    started = time.monotonic()
    try:
        if not engine._start_single():
            return CheckResult(
                index, config.name or "", config.protocol,
                f"{config.address}:{config.port}", False, None,
                "the core did not start for this config",
            )
        ok, reason = engine._verify_proxy()
        elapsed = (time.monotonic() - started) * 1000
        return CheckResult(
            index, config.name or "", config.protocol,
            f"{config.address}:{config.port}", ok,
            round(elapsed, 1) if ok else None,
            "" if ok else reason,
        )
    except Exception as exc:  # a broken config must not abort the batch
        return CheckResult(
            index, getattr(config, "name", ""), getattr(config, "protocol", "?"),
            f"{getattr(config, 'address', '?')}:{getattr(config, 'port', '?')}",
            False, None, f"{type(exc).__name__}: {exc}"[:160],
        )
    finally:
        engine.stop()


def check_configs(configs, workers: int = 4, timeout: float = 6.0) -> list[CheckResult]:
    """Check every config in parallel; results stay in saved order."""
    if not configs:
        return []
    results: list[CheckResult] = []
    with futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        pending = {
            pool.submit(_check_one, index, config, timeout): index
            for index, config in enumerate(configs)
        }
        for future in futures.as_completed(pending):
            index = pending[future]
            try:
                results.append(future.result())
            except Exception as exc:
                config = configs[index]
                results.append(CheckResult(
                    index, getattr(config, "name", ""),
                    getattr(config, "protocol", "?"), "", False, None,
                    f"{type(exc).__name__}: {exc}"[:160],
                ))
    return sorted(results, key=lambda item: item.index)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m blackoutkit.config_check",
        description="Test every saved config by fetching a real website through it.",
    )
    parser.add_argument("--workers", type=int, default=4, help="parallel cores (default 4)")
    parser.add_argument("--timeout", type=float, default=6.0, help="per-request timeout")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    from .config.manager import load_configs

    configs = load_configs()
    if getattr(configs, "error", None):
        print(f"Could not read saved configs: {configs.error}", file=sys.stderr)
        return 2
    if not configs:
        print("No configs saved. Use 'blackout config add <uri>' first.", file=sys.stderr)
        return 2

    started = time.monotonic()
    results = check_configs(configs, workers=args.workers, timeout=args.timeout)
    elapsed = time.monotonic() - started

    if args.json:
        print(json.dumps(
            {
                "schema_version": 1,
                "elapsed_s": round(elapsed, 2),
                "checked": len(results),
                "working": sum(1 for r in results if r.ok),
                "results": [asdict(r) for r in results],
            },
            indent=2,
        ))
        return 0

    working = [r for r in results if r.ok]
    print(f"\nChecked {len(results)} config(s) in {elapsed:.1f}s — "
          f"{len(working)} carry traffic\n")
    header = f"{'#':>2}  {'Config':<17} {'Proto':<8} {'Result':<9} {'Latency':>9}  Detail"
    print(header)
    print("-" * len(header))
    for r in results:
        status = "WORKS" if r.ok else "DEAD"
        latency = f"{r.latency_ms:.0f} ms" if r.latency_ms is not None else "-"
        detail = "" if r.ok else r.error[:70]
        print(f"{r.index + 1:>2}  {r.name[:17]:<17} {r.protocol:<8} {status:<9} {latency:>9}  {detail}")

    if working:
        best = min(working, key=lambda r: r.latency_ms or 1e9)
        print(f"\nFastest: {best.name or best.address} ({best.latency_ms:.0f} ms)")
    else:
        print("\nNo config carries traffic right now. Check the servers or your upstream network.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
