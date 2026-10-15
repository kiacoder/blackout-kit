"""REST API for Blackout Kit (Roadmap Phase 5 — REST API expansion).

Exposes read-only, JSON endpoints over the same local data the CLI already
uses:

* ``GET /api/health``      — liveness probe.
* ``GET /api/metrics``     — system + daemon metrics (CPU, memory, blackout procs).
* ``GET /api/connections`` — active connections, filterable by ``process``/``port``.
* ``GET /api/bandwidth``   — aggregate + per-NIC byte counters.

Design notes
------------
* The collector functions (:func:`collect_metrics`, :func:`collect_connections`,
  :func:`collect_bandwidth`) have **no FastAPI dependency** — they can be unit
  tested and reused (e.g. by the desktop bridge) on their own.
* The API is **read-only** and never starts engines, changes networking, or
  reads secret material.
* ``fastapi``/``uvicorn`` are an optional extra (``pip install
  "blackout-kit[api]"``). Importing this module without them still works;
  ``app`` is simply ``None``.

Run it with::

    pip install "blackout-kit[api]"
    uvicorn blackoutkit.api:app --host 127.0.0.1 --port 8765
"""
from __future__ import annotations

from typing import Any, Optional

try:  # optional dependency — the collectors below work without it
    from fastapi import FastAPI, Query
    from fastapi.responses import JSONResponse

    _FASTAPI_AVAILABLE = True
except Exception:  # pragma: no cover - exercised only when fastapi is absent
    FastAPI = None  # type: ignore
    Query = None  # type: ignore
    JSONResponse = None  # type: ignore
    _FASTAPI_AVAILABLE = False


# ─────────────────────────────── collectors ──────────────────────────────────

def _blackout_processes() -> list[dict[str, Any]]:
    """Return running Blackout-related processes with their RSS, best-effort."""
    procs: list[dict[str, Any]] = []
    try:
        import psutil
    except Exception:
        return procs

    for proc in psutil.process_iter(["pid", "name", "memory_info"]):
        try:
            name = (proc.info.get("name") or "").lower()
            if "blackout" not in name:
                continue
            mem = proc.info.get("memory_info")
            rss = int(mem.rss) if mem is not None else None
            procs.append({"pid": proc.info.get("pid"), "name": proc.info.get("name"), "rss_bytes": rss})
        except Exception:
            continue
    return procs


def collect_metrics() -> dict[str, Any]:
    """System + daemon metrics. Always returns a JSON-serialisable dict."""
    try:
        import psutil
    except Exception as exc:  # pragma: no cover - psutil is a hard dependency
        return {"available": False, "reason": f"psutil unavailable: {exc}"}

    try:
        vm = psutil.virtual_memory()
        procs = _blackout_processes()
        return {
            "available": True,
            "cpu_percent": psutil.cpu_percent(interval=None),
            "cpu_count": psutil.cpu_count(),
            "memory": {
                "total_bytes": int(vm.total),
                "used_bytes": int(vm.used),
                "percent": float(vm.percent),
            },
            "daemon": {
                "running": bool(procs),
                "processes": procs,
                "rss_bytes": sum(p["rss_bytes"] for p in procs if p.get("rss_bytes")),
            },
        }
    except Exception as exc:
        return {"available": False, "reason": f"metrics collection failed: {exc}"}


def collect_connections(
    established_only: bool = False,
    process: Optional[str] = None,
    port: Optional[int] = None,
) -> dict[str, Any]:
    """Active TCP/UDP connections, optionally filtered by process name / port."""
    try:
        from . import tools as net_tools

        conns = net_tools.get_active_connections(established_only=established_only)
    except Exception as exc:
        return {"available": False, "reason": f"connection listing failed: {exc}"}

    if process:
        needle = process.lower()
        conns = [c for c in conns if needle in str(c.get("process", "")).lower()]
    if port is not None:
        conns = [
            c for c in conns
            if c.get("local_port") == port or c.get("remote_port") == port
        ]
    return {"available": True, "count": len(conns), "connections": conns}


def collect_bandwidth() -> dict[str, Any]:
    """Aggregate and per-NIC byte counters via psutil."""
    try:
        import psutil

        totals = psutil.net_io_counters(pernic=False)
        per_nic = psutil.net_io_counters(pernic=True)
    except Exception as exc:
        return {"available": False, "reason": f"bandwidth collection failed: {exc}"}

    return {
        "available": True,
        "totals": {
            "bytes_sent": int(totals.bytes_sent),
            "bytes_recv": int(totals.bytes_recv),
            "packets_sent": int(totals.packets_sent),
            "packets_recv": int(totals.packets_recv),
        },
        "per_nic": {
            name: {"bytes_sent": int(c.bytes_sent), "bytes_recv": int(c.bytes_recv)}
            for name, c in per_nic.items()
        },
    }


# ───────────────────────────────── app ───────────────────────────────────────

def create_app() -> "FastAPI":
    """Build and return the FastAPI application.

    Raises RuntimeError if fastapi is not installed.
    """
    if not _FASTAPI_AVAILABLE:
        raise RuntimeError(
            "fastapi is not installed; run: pip install \"blackout-kit[api]\""
        )

    from . import __version__ as _version

    api = FastAPI(
        title="Blackout Kit API",
        version=_version,
        description="Read-only local REST API for Blackout Kit.",
    )

    @api.get("/api/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "version": _version}

    @api.get("/api/metrics")
    def metrics() -> dict[str, Any]:
        return collect_metrics()

    @api.get("/api/connections")
    def connections(
        process: Optional[str] = Query(default=None, description="filter by process name substring"),
        port: Optional[int] = Query(default=None, description="filter by local or remote port"),
        established: bool = Query(default=False, description="only ESTABLISHED sockets"),
    ) -> dict[str, Any]:
        return collect_connections(established_only=established, process=process, port=port)

    @api.get("/api/bandwidth")
    def bandwidth() -> dict[str, Any]:
        return collect_bandwidth()

    return api


if _FASTAPI_AVAILABLE:
    app = create_app()
else:  # pragma: no cover
    app = None
