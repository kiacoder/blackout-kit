"""
Blackout Kit - Python client for the v2 control channel (blackout-core).

Speaks the framed, versioned JSON protocol from engine/v2/pkg/ipc over the
platform transport: a Windows named pipe (byte mode) or a Unix domain socket.

Frame layout (must stay in lockstep with pkg/ipc/frame.go):

    +--------+--------+----------------------+
    | magic  | length | JSON body            |
    | 4 bytes| 4 bytes| `length` bytes       |
    +--------+--------+----------------------+

magic is the ASCII string "BKV2" and length is a big-endian uint32.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import uuid
from pathlib import Path

API_VERSION = "2.0.0"
MAX_FRAME_SIZE = 4 * 1024 * 1024  # mirrors ipc.MaxFrameSize
_FRAME_MAGIC = b"BKV2"
_HEADER_SIZE = 8

_DEFAULT_WINDOWS_PIPE = r"\\.\pipe\blackout_ipc"


class IPCError(Exception):
    """Structured error reported by the daemon (code + message)."""

    def __init__(self, code: str, message: str = ""):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}" if message else code)


class IPCProtocolError(Exception):
    """The peer violated the framing or envelope contract."""


def default_endpoint() -> str:
    """Return the platform's default control endpoint."""
    if sys.platform == "win32":
        return _DEFAULT_WINDOWS_PIPE
    return str(Path(tempfile.gettempdir()) / "blackout_ipc")


def validate_endpoint(addr: str) -> str:
    """Return a normalized endpoint or raise ValueError."""
    addr = (addr or "").strip()
    if not addr:
        raise ValueError("IPC endpoint is empty")
    if addr.startswith(r"\\.\pipe" + "\\") or addr.startswith("//./pipe/"):
        if sys.platform != "win32":
            raise ValueError(f"pipe endpoint {addr!r} requires windows")
        return addr
    if sys.platform == "win32":
        raise ValueError(f"{addr!r} is not a windows pipe path; expected \\\\.\\pipe\\<name>")
    if addr.startswith("\\\\.\\") or addr.startswith("//./"):
        raise ValueError(f"{addr!r} is a windows-style path on a non-windows platform")
    return addr


def encode_envelope(kind: str, *, method: str = "", id: str = "",
                    params: dict | None = None, payload: dict | None = None,
                    version: str = API_VERSION) -> bytes:
    """Encode one protocol envelope as JSON bytes."""
    env: dict = {"v": version, "kind": kind}
    if kind == "request":
        if not method:
            raise ValueError("request envelope requires a method")
        env["method"] = method
    if id:
        env["id"] = id
    if params is not None:
        env["params"] = params
    if payload is not None:
        env["payload"] = payload
    return json.dumps(env, separators=(",", ":")).encode("utf-8")


def decode_envelope(raw: bytes) -> dict:
    """Decode one JSON envelope body and enforce the base contract."""
    try:
        env = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IPCProtocolError(f"unparseable envelope body: {exc}") from exc
    if not isinstance(env, dict):
        raise IPCProtocolError("envelope is not a JSON object")
    if not env.get("v"):
        raise IPCProtocolError("envelope is missing 'v'")
    kind = env.get("kind")
    if kind not in ("request", "response", "event"):
        raise IPCProtocolError(f"unknown kind {kind!r}")
    return env


def encode_frame(body: bytes) -> bytes:
    """Wrap one envelope body in the BKV2 length-prefixed frame."""
    if len(body) > MAX_FRAME_SIZE:
        raise IPCProtocolError(f"frame length {len(body)} exceeds limit {MAX_FRAME_SIZE}")
    return _FRAME_MAGIC + len(body).to_bytes(4, "big") + body


def read_exact(read, count: int) -> bytes:
    """Read exactly count bytes from a file-like or socket object."""
    chunks = []
    remaining = count
    while remaining:
        chunk = read(remaining)
        if not chunk:
            raise IPCProtocolError("connection closed mid-frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_frame(read) -> dict:
    """Read one complete frame and return its decoded envelope."""
    header = read_exact(read, _HEADER_SIZE)
    if header[:4] != _FRAME_MAGIC:
        raise IPCProtocolError("bad frame magic")
    length = int.from_bytes(header[4:8], "big")
    if length > MAX_FRAME_SIZE:
        raise IPCProtocolError(f"declared frame length {length} exceeds limit {MAX_FRAME_SIZE}")
    body = read_exact(read, length) if length else b""
    return decode_envelope(body)


def write_frame(write, env_bytes: bytes) -> None:
    """Encode and write one frame in a single call."""
    write(encode_frame(env_bytes))


class CoreClient:
    """A single IPC session to one blackout-core daemon.

    The client is not thread-safe by design; each engine instance owns exactly
    one session, matching how the v1 ctypes ABI was used.
    """

    def __init__(self, endpoint: str | None = None, connect_timeout: float = 10.0):
        self.endpoint = validate_endpoint(endpoint or default_endpoint())
        self.connect_timeout = connect_timeout
        self._io = None
        self._write_lock = threading.Lock()
        self._id_counter = 0

    # ── transport ────────────────────────────────────────────────────────
    def connect(self) -> None:
        """Open the transport, retrying briefly while the daemon boots."""
        if self._io is not None:
            return
        deadline = self.connect_timeout
        last_error: Exception | None = None
        while deadline > 0:
            try:
                self._io = self._open_transport()
                return
            except OSError as exc:
                last_error = exc
                deadline -= 0.2
                import time
                time.sleep(0.2)
        raise OSError(f"could not connect to blackout-core at {self.endpoint}: {last_error}")

    def _open_transport(self):
        if sys.platform == "win32":
            # Byte-mode named pipe: plain file I/O maps to CreateFile/ReadFile/
            # WriteFile, which is all the framed protocol needs.
            return open(self.endpoint, "r+b", buffering=0)
        import socket
        family = socket.AF_UNIX
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(self.connect_timeout)
        sock.connect(self.endpoint)
        sock.settimeout(None)
        return sock

    def close(self) -> None:
        io = self._io
        self._io = None
        if io is None:
            return
        try:
            if hasattr(io, "close"):
                io.close()
        except OSError:
            pass

    # ── frame I/O ────────────────────────────────────────────────────────
    def _read(self, count: int) -> bytes:
        assert self._io is not None
        if hasattr(self._io, "recv"):
            data = self._io.recv(count)
        else:
            data = self._io.read(count)
        if not data:
            raise IPCProtocolError("transport returned no data")
        return data

    def _write(self, data: bytes) -> None:
        assert self._io is not None
        if hasattr(self._io, "write"):
            self._io.write(data)
        else:  # raw socket
            self._io.sendall(data)

    def _request(self, method: str, params: dict | None = None) -> dict:
        """Send one request and return the matching response envelope."""
        self.connect()
        self._id_counter += 1
        request_id = f"py-{os.getpid()}-{self._id_counter}-{uuid.uuid4().hex[:8]}"
        with self._write_lock:
            write_frame(self._write, encode_envelope(
                "request", method=method, id=request_id, params=params))
            while True:
                env = read_frame(self._read)
                if env.get("kind") == "event":
                    continue  # telemetry: not the answer to anything
                if env.get("id") != request_id:
                    continue  # a response to an earlier session's request
                break
        if env.get("error"):
            err = env["error"]
            raise IPCError(str(err.get("code", "internal_error")), str(err.get("message", "")))
        if env.get("kind") != "response":
            raise IPCProtocolError(f"expected response, got {env.get('kind')!r}")
        return env

    # ── typed calls ──────────────────────────────────────────────────────
    def handshake(self) -> dict:
        env = self._request("handshake", {
            "api_version": API_VERSION,
            "client_name": "blackoutkit-python",
            "client_version": _client_version(),
        })
        return env.get("payload") or {}

    def ping(self) -> bool:
        env = self._request("ping")
        return bool((env.get("payload") or {}).get("ok"))

    def start(self, engine: str, config: dict | None = None) -> dict:
        env = self._request("start", {"engine": engine, "config": config or {}})
        return env.get("payload") or {}

    def stop(self) -> dict:
        env = self._request("stop")
        return env.get("payload") or {}

    def status(self) -> dict:
        env = self._request("status")
        return env.get("payload") or {}

    def tune(self, params: dict) -> dict:
        env = self._request("tune", params)
        return env.get("payload") or {}

    def shutdown(self) -> dict:
        env = self._request("shutdown")
        return env.get("payload") or {}


def _client_version() -> str:
    try:
        from . import __version__
        return __version__
    except Exception:
        return "0.0.0"
