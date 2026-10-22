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

# Guards against subscribing a second webhook observer when create_app() runs
# more than once in a process (e.g. tests).
_WEBHOOK_OBSERVER_INSTALLED = False

try:  # optional dependency — the collectors below work without it
    # NOTE: imported at module level (not inside create_app) because this file
    # uses `from __future__ import annotations`: FastAPI resolves the endpoint
    # parameter annotations (e.g. `websocket: WebSocket`) against module
    # globals, so a function-local import would make WebSocket resolve as a
    # query parameter instead.
    from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect

    _FASTAPI_AVAILABLE = True
except Exception:  # pragma: no cover - exercised only when fastapi is absent
    FastAPI = None  # type: ignore
    Query = None  # type: ignore
    WebSocket = None  # type: ignore
    WebSocketDisconnect = None  # type: ignore
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
    except Exception:  # pragma: no cover - psutil is a hard dependency
        # Log the detail server-side; never echo exception text to the client.
        _log.warning("metrics: psutil unavailable", exc_info=True)
        return {"available": False, "reason": "psutil unavailable"}

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
    except Exception:
        _log.warning("metrics collection failed", exc_info=True)
        return {"available": False, "reason": "metrics collection failed"}


def collect_connections(
    established_only: bool = False,
    process: Optional[str] = None,
    port: Optional[int] = None,
) -> dict[str, Any]:
    """Active TCP/UDP connections, optionally filtered by process name / port."""
    try:
        from . import tools as net_tools

        conns = net_tools.get_active_connections(established_only=established_only)
    except Exception:
        _log.warning("connection listing failed", exc_info=True)
        return {"available": False, "reason": "connection listing failed"}

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
    except Exception:
        _log.warning("bandwidth collection failed", exc_info=True)
        return {"available": False, "reason": "bandwidth collection failed"}

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


def _remote_access_allowed() -> bool:
    import os

    return os.environ.get("BLACKOUT_API_ALLOW_REMOTE") == "1"


def _is_loopback_host(host: object) -> bool:
    """Whether a client host is loopback (or the TestClient synthetic host)."""
    return (
        host == "testclient"  # Starlette TestClient synthetic host
        or host in ("::1", "localhost")
        or (
            isinstance(host, str)
            and (host.startswith("127.") or host.startswith("::ffff:127."))
        )
    )


def _mutation_token() -> str:
    """Shared secret required for state-changing API calls from non-loopback."""
    import os as _os

    return _os.environ.get("BLACKOUT_API_TOKEN", "").strip()


def _require_mutation_auth(request) -> None:
    """Refuse mutations from non-loopback clients unless they present the token.

    The API has no user accounts. Loopback callers are the local user and keep
    the zero-friction path; once ``BLACKOUT_API_ALLOW_REMOTE=1`` exposes the
    API to the network, an unauthenticated POST could register a webhook that
    exfiltrates every event. Fails closed: remote + no configured token means
    mutations are denied outright.
    """
    from fastapi import HTTPException

    client = getattr(request, "client", None)
    if _is_loopback_host(getattr(client, "host", None)):
        return
    token = _mutation_token()
    if not token:
        raise HTTPException(
            status_code=403,
            detail="remote mutations are disabled; set BLACKOUT_API_TOKEN to allow them",
        )
    header = request.headers.get("authorization", "")
    presented = header[7:].strip() if header.lower().startswith("bearer ") else ""
    if not presented or not _secrets_equal(presented, token):
        raise HTTPException(status_code=401, detail="invalid or missing bearer token")


def _secrets_equal(left: str, right: str) -> bool:
    """Constant-time comparison for the API token."""
    import hmac as _hmac

    return _hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def _install_loopback_guard(api: "FastAPI") -> None:
    """Deny non-loopback clients unless ``BLACKOUT_API_ALLOW_REMOTE=1``.

    The API has no authentication and exposes local process/connection data, so
    it is loopback-only by default. Operators who deliberately want remote
    access (behind their own proxy/auth) can opt in via the env var. This
    middleware covers HTTP; the WebSocket endpoint re-checks explicitly.
    """
    if _remote_access_allowed():
        return

    from fastapi import Request
    from fastapi.responses import JSONResponse

    @api.middleware("http")
    async def _loopback_only(request: Request, call_next):
        client = getattr(request, "client", None)
        if not _is_loopback_host(getattr(client, "host", None)):
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

    from fastapi import Request  # noqa: F401 - used in handler annotations below

    from . import __version__ as _version

    api = FastAPI(
        title="Blackout Kit API",
        version=_version,
        description="Read-only local REST API for Blackout Kit.",
    )
    _install_loopback_guard(api)

    # Deliver published events to any registered webhooks. Subscribed once per
    # process; delivery happens on a daemon thread so a slow endpoint cannot
    # stall the event bus.
    global _WEBHOOK_OBSERVER_INSTALLED
    if not _WEBHOOK_OBSERVER_INSTALLED:
        try:
            from . import events as events_mod
            from .webhooks import WebhookRegistry, make_webhook_observer

            events_mod.bus_or_default().subscribe(
                make_webhook_observer(WebhookRegistry())
            )
            _WEBHOOK_OBSERVER_INSTALLED = True
        except Exception as exc:  # pragma: no cover - fastapi/events missing
            _log.warning("Webhook observer not installed: %s", exc)

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

    # ── v2: events, webhooks, plugins, live streaming ───────────────────────

    @api.get("/api/v2/events")
    def events_v2(
        limit: int = Query(default=50, ge=1, le=500),
        type: Optional[str] = Query(default=None, description="event type prefix filter"),
    ) -> dict[str, Any]:
        from . import events as events_mod

        return {"events": events_mod.merged_recent_events(limit=limit, type_prefix=type)}

    @api.get("/api/v2/webhooks")
    def webhooks_list() -> dict[str, Any]:
        from .webhooks import WebhookRegistry

        return {"webhooks": [h.to_dict() for h in WebhookRegistry().list()]}

    @api.post("/api/v2/webhooks")
    def webhooks_add(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        from fastapi import HTTPException

        from .webhooks import Webhook, WebhookRegistry, validate_webhook_url

        # State change: when the operator has opened the API to the network,
        # require the shared token. Loopback callers keep working unchanged.
        _require_mutation_auth(request)

        url = str(payload.get("url") or "").strip()
        if not url:
            raise HTTPException(status_code=400, detail="url is required")
        try:
            url = validate_webhook_url(url)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        prefixes = payload.get("event_prefixes") or []
        if not isinstance(prefixes, list):
            raise HTTPException(status_code=400, detail="event_prefixes must be a list")
        hook = Webhook(
            url=url,
            event_prefixes=tuple(str(p) for p in prefixes),
            enabled=bool(payload.get("enabled", True)),
            secret=(str(payload["secret"]) if payload.get("secret") else None),
        )
        WebhookRegistry().add(hook)
        return {"added": url}

    @api.delete("/api/v2/webhooks")
    def webhooks_remove(
        request: Request,
        url: str = Query(..., description="webhook URL to remove"),
    ) -> dict[str, Any]:
        from .webhooks import WebhookRegistry

        _require_mutation_auth(request)
        return {"removed": WebhookRegistry().remove(url)}

    @api.get("/api/v2/plugins")
    def plugins_v2() -> dict[str, Any]:
        from dataclasses import asdict

        from .plugins import PluginManager

        manager = PluginManager()
        return {"enabled": manager.enabled, "plugins": [asdict(m) for m in manager.list()]}

    @api.get("/api/v2/devices")
    def devices_v2() -> dict[str, Any]:
        from .enterprise import DeviceRegistry

        return DeviceRegistry().dashboard()

    @api.get("/api/v2/compliance")
    def compliance_v2(
        framework: str = Query(default="gdpr", description="gdpr|hipaa|soc2"),
    ) -> dict[str, Any]:
        from fastapi import HTTPException

        from .enterprise import evaluate

        try:
            return evaluate(framework)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @api.websocket("/api/v2/ws/events")
    async def ws_events(websocket: WebSocket) -> None:
        import asyncio

        from . import events as events_mod

        # HTTP middleware does not cover WebSockets — enforce loopback here too.
        if not _remote_access_allowed() and not _is_loopback_host(
            getattr(websocket.client, "host", None)
        ):
            await websocket.close(code=1008)
            return
        await websocket.accept()
        seen: set[str] = set()
        try:
            await websocket.send_json({"type": "stream.connected"})
            while True:
                for event in events_mod.merged_recent_events(limit=200):
                    event_id = event.get("event_id")
                    if event_id and event_id not in seen:
                        seen.add(event_id)
                        await websocket.send_json(event)
                await asyncio.sleep(1.0)
        except WebSocketDisconnect:
            return
        except Exception:  # pragma: no cover - client vanished mid-send
            return

    return api


if _FASTAPI_AVAILABLE:
    app = create_app()
else:  # pragma: no cover
    app = None
