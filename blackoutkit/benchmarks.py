"""Local performance benchmarks (Roadmap Phase 5).

Two numbers matter for the daemon budget:

* **Daemon RSS** — target < 80 MB.
* **IPC round-trip p99** — target < 10 ms.

Everything here is best-effort and read-only: it never starts an engine or
changes networking. When the daemon is not running the affected metric reports
``available: False`` with a reason instead of guessing.
"""
from __future__ import annotations

from typing import Any, Optional

from rich.markup import escape

DAEMON_RSS_BUDGET_MB = 80.0
IPC_P99_BUDGET_MS = 10.0


# ─────────────────────────────── pure helpers ────────────────────────────────

def percentile(values: list[float], pct: float) -> Optional[float]:
    """Nearest-rank percentile. Returns None for an empty input.

    ``pct`` is 0–100. Uses the nearest-rank method (no interpolation) so the
    result is always one of the observed samples — appropriate for latency
    where a real measurement is more meaningful than an interpolated one.
    """
    if not values:
        return None
    if pct <= 0:
        return min(values)
    if pct >= 100:
        return max(values)
    import math

    ordered = sorted(values)
    rank = math.ceil((pct / 100.0) * len(ordered)) - 1
    rank = max(0, min(rank, len(ordered) - 1))
    return ordered[rank]


def summarize(timings_ms: list[float]) -> dict[str, Optional[float]]:
    """Return count/min/mean/p50/p95/p99/max for a list of latencies (ms)."""
    if not timings_ms:
        return {
            "count": 0, "min_ms": None, "mean_ms": None,
            "p50_ms": None, "p95_ms": None, "p99_ms": None, "max_ms": None,
        }
    return {
        "count": len(timings_ms),
        "min_ms": min(timings_ms),
        "mean_ms": sum(timings_ms) / len(timings_ms),
        "p50_ms": percentile(timings_ms, 50),
        "p95_ms": percentile(timings_ms, 95),
        "p99_ms": percentile(timings_ms, 99),
        "max_ms": max(timings_ms),
    }


# ──────────────────────────────── measurements ───────────────────────────────

def measure_daemon_rss() -> dict[str, Any]:
    """RSS (bytes) of the running daemon, identified via its PID lease.

    The daemon is located through ``blackoutkit.daemon.get_pid()`` (PID file +
    lease identity), **not** by matching process names: in a frozen build the
    CLI itself is ``blackout.exe`` (a name match would self-report the CLI as
    the daemon), and in a dev run the daemon is ``pythonw.exe`` (a name match
    would miss it entirely).
    """
    empty = {"rss_bytes": None, "rss_mb": None, "pids": []}
    try:
        import psutil
    except Exception as exc:  # pragma: no cover - psutil is a hard dependency
        return {"available": False, "reason": f"psutil unavailable: {exc}", **empty}

    try:
        from . import daemon as daemon_mod

        pid = daemon_mod.get_pid()
    except Exception as exc:
        return {"available": False, "reason": f"daemon lookup failed: {exc}", **empty}

    if not pid:
        return {"available": False, "reason": "daemon not running", **empty}

    try:
        rss = int(psutil.Process(pid).memory_info().rss)
    except Exception as exc:
        return {"available": False, "reason": f"daemon pid {pid} unreadable: {exc}",
                "rss_bytes": None, "rss_mb": None, "pids": [pid]}
    return {"available": True, "rss_bytes": rss, "rss_mb": rss / (1024 * 1024), "pids": [pid]}


def measure_ipc_latency(
    samples: int = 20,
    *,
    endpoint: Optional[str] = None,
    connect_timeout: float = 2.0,
) -> dict[str, Any]:
    """Time N ping round-trips against the core IPC endpoint, best-effort."""
    import time

    try:
        from . import v2_ipc

        client = v2_ipc.CoreClient(endpoint=endpoint, connect_timeout=connect_timeout)
    except Exception as exc:
        return {"available": False, "reason": f"IPC client unavailable: {exc}"}

    timings: list[float] = []
    try:
        client.connect()
        # Best-effort handshake first: some core builds reject requests until
        # the session is handshaken. A failure here is not fatal — still try ping.
        try:
            client.handshake()
        except Exception:
            pass
        for _ in range(max(1, samples)):
            started = time.perf_counter()
            client.ping()
            timings.append((time.perf_counter() - started) * 1000.0)
    except Exception as exc:
        return {"available": False, "reason": f"IPC not reachable: {exc}"}
    finally:
        try:
            client.close()
        except Exception:
            pass

    summary = summarize(timings)
    summary["available"] = True
    return summary


def run_benchmarks(
    samples: int = 20,
    *,
    ipc_timeout: float = 2.0,
) -> dict[str, Any]:
    """Collect the Phase 5 benchmark set and evaluate the budgets."""
    import psutil

    vm = psutil.virtual_memory()
    daemon = measure_daemon_rss()
    # Only probe IPC when a daemon is actually running: otherwise the connect
    # loop retries for the whole timeout and reports a confusing reason.
    if daemon.get("available"):
        ipc = measure_ipc_latency(samples, connect_timeout=ipc_timeout)
    else:
        ipc = {"available": False, "reason": "daemon not running"}

    rss_ok: Optional[bool] = None
    if daemon.get("available") and daemon.get("rss_mb") is not None:
        rss_ok = daemon["rss_mb"] < DAEMON_RSS_BUDGET_MB

    ipc_ok: Optional[bool] = None
    if ipc.get("available") and ipc.get("p99_ms") is not None:
        ipc_ok = ipc["p99_ms"] < IPC_P99_BUDGET_MS

    return {
        "system": {
            "cpu_percent": psutil.cpu_percent(interval=None),
            "memory_percent": float(vm.percent),
        },
        "daemon": daemon,
        "ipc": ipc,
        "budgets": {"daemon_rss_mb": DAEMON_RSS_BUDGET_MB, "ipc_p99_ms": IPC_P99_BUDGET_MS},
        "within_budget": {"daemon_rss": rss_ok, "ipc_latency": ipc_ok},
    }


def render_benchmarks(result: dict[str, Any], console) -> None:
    """Render a benchmark result as a Rich table."""
    from .theme import make_table

    table = make_table("Performance Benchmarks", [
        ("Metric", "cyan"), ("Value", "white"), ("Budget", "dim"), ("Within budget", ""),
    ], [])

    daemon = result.get("daemon", {})
    if daemon.get("available") and daemon.get("rss_mb") is not None:
        rss_val = f"{daemon['rss_mb']:.1f} MB"
        rss_ok = result["within_budget"].get("daemon_rss")
        rss_state = "[success]yes[/success]" if rss_ok else "[error]no[/error]"
    else:
        rss_val, rss_state = "[dim]daemon not running[/dim]", "[dim]—[/dim]"
    table.add_row("Daemon RSS", rss_val, f"< {result['budgets']['daemon_rss_mb']:.0f} MB", rss_state)

    ipc = result.get("ipc", {})
    if ipc.get("available"):
        ipc_val = f"p99 {ipc['p99_ms']:.2f} ms (n={ipc['count']})"
        ipc_ok = result["within_budget"].get("ipc_latency")
        ipc_state = "[success]yes[/success]" if ipc_ok else "[error]no[/error]"
    else:
        # Reason comes from exception text — escape it so a stray "[...]" token
        # is not swallowed as markup.
        ipc_val = f"[dim]{escape(ipc.get('reason', 'unavailable'))}[/dim]"
        ipc_state = "[dim]—[/dim]"
    table.add_row("IPC latency", ipc_val, f"p99 < {result['budgets']['ipc_p99_ms']:.0f} ms", ipc_state)

    console.print(table)
    console.print(
        "[muted]Read-only: this starts no engines and changes no networking. "
        "Metrics for a stopped daemon report as unavailable rather than guessed.[/muted]"
    )
