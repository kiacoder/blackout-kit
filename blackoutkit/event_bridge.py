"""
Blackout Kit - Opt-in local event bridge (Server-Sent Events).

Streams sanitized Blackout Kit events to local consumers (dashboards, avatar
hosts, external agent runtimes) over HTTP SSE.

Security boundary, by design:

- OFF unless explicitly started via `blackout events serve` or a consumer
  that the user configured
- binds to 127.0.0.1 only; refusing non-loopback bind addresses is the
  default behavior and requires an explicit opt-out flag
- serves sanitized events only; secrets never enter the event bus in the
  first place (see events.py)
- GET endpoints only; no control surface, so a consumer can observe but
  never act on Blackout Kit through the bridge

SSE was chosen over WebSocket because it needs no upgrade handshake or
dependency, works with curl and every browser, and the stream is strictly
server-to-client.
"""
from __future__ import annotations

import json
import queue
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from . import events as ev

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8787
_HEARTBEAT_SECONDS = 15
_QUEUE_SIZE = 200
_REPLAY_LIMIT = 20


class _BridgeState:
    """Per-server subscription registry shared with request handlers."""

    def __init__(self, bus: ev.EventBus, *, replay: int) -> None:
        self.bus = bus
        self.replay = replay
        self.clients: set[queue.Queue[ev.Event]] = set()
        self.lock = threading.Lock()
        self._unsubscribe_by_channel: dict[queue.Queue[ev.Event], Any] = {}

    def subscribe(self) -> queue.Queue[ev.Event]:
        channel: queue.Queue[ev.Event] = queue.Queue(maxsize=_QUEUE_SIZE)
        with self.lock:
            self.clients.add(channel)

        def forward(event: ev.Event) -> None:
            try:
                channel.put_nowait(event)
            except queue.Full:
                # Drop oldest for slow consumers rather than blocking engines.
                try:
                    channel.get_nowait()
                    channel.put_nowait(event)
                except (queue.Empty, queue.Full):
                    pass

        unsubscribe = self.bus.subscribe(forward)
        self._unsubscribe_by_channel[channel] = unsubscribe
        return channel

    def unsubscribe(self, channel: queue.Queue[ev.Event]) -> None:
        with self.lock:
            self.clients.discard(channel)
        unsubscribe = self._unsubscribe_by_channel.pop(channel, None)
        if unsubscribe is not None:
            unsubscribe()


def _sse_payload(event: ev.Event) -> str:
    data = json.dumps(event.to_dict(), ensure_ascii=False)
    return f"event: {event.type}\ndata: {data}\n\n"


def make_handler(state: _BridgeState):
    class BridgeHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
            # Keep the bridge quiet on stdout; bind failures still surface.
            pass

        def do_GET(self) -> None:  # noqa: N802 - stdlib naming
            path = self.path.split("?", 1)[0]
            if path == "/health":
                body = json.dumps({
                    "service": "blackout-event-bridge",
                    "status": "ok",
                    "clients": len(state.clients),
                }).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
                return
            if path == "/events":
                self._serve_events()
                return
            self.send_response(404)
            self.end_headers()

        def _serve_events(self) -> None:
            channel = state.subscribe()
            # Dead clients must not hold handler threads forever: writes to a
            # stalled peer raise within this window, and the heartbeat interval
            # is short enough to keep live connections healthy.
            try:
                self.connection.settimeout(30)
            except OSError:
                pass
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            try:
                for event in ev.merged_recent_events(limit=state.replay, bus=state.bus):
                    self.wfile.write(_sse_payload(ev.Event.from_raw(event)).encode("utf-8"))
                self.wfile.write(b": stream\n\n")
                self.wfile.flush()
                while True:
                    try:
                        event = channel.get(timeout=_HEARTBEAT_SECONDS)
                    except queue.Empty:
                        self.wfile.write(b": ping\n\n")
                        self.wfile.flush()
                        continue
                    self.wfile.write(_sse_payload(event).encode("utf-8"))
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, TimeoutError, OSError):
                pass
            finally:
                state.unsubscribe(channel)

    return BridgeHandler


class EventBridgeServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def start_bridge(
    *,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    bus: ev.EventBus | None = None,
    replay: int = _REPLAY_LIMIT,
) -> tuple[EventBridgeServer, _BridgeState]:
    """Start the loopback SSE bridge; returns the server (call serve_forever)."""
    resolved = host or DEFAULT_HOST
    if resolved not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError(
            "The event bridge refuses non-loopback bind addresses by design; "
            "exposing engine events beyond this machine is a supported no."
        )
    active_bus = bus if bus is not None else ev.bus_or_default()
    state = _BridgeState(active_bus, replay=replay)
    server = EventBridgeServer((resolved, port), make_handler(state))
    return server, state


__all__ = [
    "DEFAULT_HOST",
    "DEFAULT_PORT",
    "EventBridgeServer",
    "start_bridge",
]
