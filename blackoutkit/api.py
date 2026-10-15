"""REST API for Blackout Kit (Roadmap Phase 5 — REST API expansion).

Exposes read-only, JSON endpoints over the same local data the CLI already
uses:

* ``GET /api/health``      — liveness probe.
* ``GET /api/metrics``     — system + daemon metrics (CPU, memory, daemon RSS).
* ``GET /api/connections`` — active connections, filterable by ``process``/``port``.
* ``GET /api/bandwidth``   — aggregate + per-NIC byte counters.

Design notes
------------
* The collector functions (:func:`collect_metrics`, :func:`collect_connections`,
  :func:`collect_bandwidth`) have **no FastAPI dependency** — they can be unit
  tested and reused (e.g. by the desktop bridge) on their own.
* The API is **read-only** and never starts engines, changes networking, or
  reads secret material.
* **Security:** the API has **no authentication** and exposes local system
  data (process names, connections, NIC counters). It is therefore
  **loopback-only by default** — :func:`create_app` installs a middleware that
  returns ``403`` for non-loopback clients. To intentionally serve remote
  clients (behind your own auth/proxy), set ``BLACKOUT_API_ALLOW_REMOTE=1``.
  Even then, prefer ``--host 127.0.0.1``; :func:`create_app` logs a warning
  when it detects a non-loopback ``--host`` on the command line.
* ``fastapi``/``uvicorn`` are an optional extra (``pip install
  "blackout-kit[api]"``). Importing this module without them still works;
  ``app`` is simply ``None``.

Run it with::

    pip install "blackout-kit[api]"
    uvicorn blackoutkit.api:app --host 127.0.0.1 --port 8765
"""
from __future__ import annotations

import logging
from typing import Any, Optional

_log = logging.getLogger(__name__)

try:  # optional dependency — the collectors below work without it
    from fastapi import FastAPI, Query

    _FASTAPI_AVAILABLE = True
except Exception:  # pragma: no cover - exercised only when fastapi is absent
    FastAPI = None  # type: ignore
    Query = None  # type: ignore
    _FASTAPI_AVAILABLE = False


# ─────────────────────────────── collectors ──────────────────────────────────

def _daemon_info() -> dict[str, Any]:
    """Daemon presence + RSS, identified via the daemon PID lease (not by name).

    Name matching is wrong here: a frozen CLI is ``blackout.exe`` (would match
    "blackout" and report the CLI itself), while a dev daemon is ``pythonw.exe``
    (would not match). ``daemon.get_pid()`` reads the PID file + lease identity.
    """
    try:
        from . import daemon as daemon_mod

        pid = daemon_mod.get_pid()
    except Exception:
        pid = None

    if not pid:
        return {"running": False, "pid": None, "rss_bytes": None}
    try:
        import psutil

        rss = int(psutil.Process(pid).memory_info().rss)
    except Exception:
        rss = None
    return {"running": True, "pid": pid, "rss_bytes": rss}


def collect_metrics() -> dict[str, Any]:
    """System + daemon metrics. Always returns a JSON-serialisable dict."""
    try:
        import psutil
    except Exception as exc:  # pragma: no cover - psutil is a hard dependency
        return {"available": False, "reason": f"psutil unavailable: {exc}"}

    try:
        vm = psutil.virtual_memory()
        return {
            "available": True,
            "cpu_percent": psutil.cpu_percent(interval=None),
            "cpu_count": psutil.cpu_count(),
            "memory": {
                "total_bytes": int(vm.total),
                "used_bytes": int(vm.used),
                "percent": float(vm.percent),
            },
            "daemon": _daemon_info(),
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

def _warn_if_public_host() -> None:
    """Best-effort warning when the server is launched on a non-loopback host."""
    import sys

    argv = sys.argv
    host: Optional[str] = None
    for i, arg in enumerate(argv):
        if arg == "--host" and i + 1 < len(argv):
            host = argv[i + 1]
        elif arg.startswith("--host="):
            host = arg.split("=", 1)[1]
    if host and host not in ("127.0.0.1", "localhost", "::1"):
        _log.warning(
            "Blackout API is bound to %s — it exposes local process/connection "
            "data with NO authentication. Use 127.0.0.1 unless you understand "
            "the exposure.", host,
        )


def _install_loopback_guard(api: "FastAPI") -> None:
    """Deny non-loopback clients unless ``BLACKOUT_API_ALLOW_REMOTE=1``.

    The API has no authentication and exposes local process/connection data, so
    it is loopback-only by default. Operators who deliberately want remote
    access (behind their own proxy/auth) can opt in via the env var.
    """
    import os

    if os.environ.get("BLACKOUT_API_ALLOW_REMOTE") == "1":
        return

    from fastapi import Request
    from fastapi.responses import JSONResponse

    @api.middleware("http")
    async def _loopback_only(request: Request, call_next):
        client = getattr(request, "client", None)
        host = getattr(client, "host", None)
        is_loopback = (
            host == "testclient"  # Starlette TestClient synthetic host
            or host in ("::1", "localhost")
            or (isinstance(host, str) and host.startswith("127."))
        )
        if not is_loopback:
            return JSONResponse(
                {"detail": "remote access disabled; set BLACKOUT_API_ALLOW_REMOTE=1 to override"},
                status_code=403,
            )
        return await call_next(request)


def create_app() -> "FastAPI":
    """Build and return the FastAPI application.

    Raises RuntimeError if fastapi is not installed.
    """
    if not _FASTAPI_AVAILABLE:
        raise RuntimeError(
            "fastapi is not installed; run: pip install \"blackout-kit[api]\""
        )

    _warn_if_public_host()

    from . import __version__ as _version

    api = FastAPI(
        title="Blackout Kit API",
        version=_version,
        description="Read-only local REST API for Blackout Kit.",
    )
    _install_loopback_guard(api)

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
