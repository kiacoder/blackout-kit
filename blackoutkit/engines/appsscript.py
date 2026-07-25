"""
Blackout Kit - Google Apps Script HTTP Relay engine.

Uses Google's own servers as an HTTP relay (domain fronting through Google).

HOW IT WORKS:
  Your traffic:  Client → [HTTP to localhost:8087] → Local relay server
                       → [HTTPS to script.google.com] → GAS script
                       → GAS fetches target URL → returns response

WHY IT WORKS IN IRAN:
  - The ISP sees traffic to script.google.com (Google = allowed ✓)
  - The actual content (target URL + response) is hidden inside the HTTPS tunnel
  - Iran cannot block script.google.com without breaking ALL of Google

WHAT IT BYPASSES:
  ✓ IP blocking (your IP connects to Google, not the blocked server)
  ✓ DNS poisoning (you never DNS-resolve the blocked domain locally)
  ✓ SNI filtering (the TLS SNI is "script.google.com", not the target)
  ✗ NOT suitable for real-time or WebSocket connections
  ✗ HTTP/HTTPS browsing only (no V2Ray/XRay tunneling)

WHEN TO USE:
  Use this as a fallback when all other engines fail.
  It's slower than SNI/GoodbyeDPI but works even if all VPN ports are blocked.

GAS RELAY IDs:
  Add deployment IDs to data/gas_ids.txt (one per line).
  The engine rotates through them automatically.
  Get community IDs from: https://github.com/kiacoder/blackout-kit

REQUIREMENTS:
  - No binary needed — pure Python
  - Internet access (to reach script.google.com)
  - GAS deployment IDs in data/gas_ids.txt

PORTS:
  HTTP proxy: 8087 (configurable via gas_proxy_port setting)
"""
import base64
import http.server
import json
import random
import socketserver
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from .base import Engine, BINS_DIR

# ── GAS endpoint builder ─────────────────────────────────────────

GAS_BASE_URL  = "https://script.google.com/macros/s/{id}/exec"
DATA_DIR      = Path(__file__).parent.parent.parent / "data"
GAS_IDS_FILE  = DATA_DIR / "gas_ids.txt"

# Community-shared relay IDs (from meme.txt — public relay pool)
BUILTIN_GAS_IDS = [
    "AKfycbz7OZqlYLryyaWBA9fJ1_Nb8pfay6F_MckzQKKu4EmY_73SGC9LQev-NjsIETRhN6racA",
    "AKfycbzCiGK9pLrrAHAK7bqjo2iWrUYwEclZOs02vFaHZ_laP2IrOVR5Iq4-lSZvUs6GNVK5Vw",
    "AKfycbxgptfudtQ4bei3ycpV1AVfkwaHWSqzaM3Z2VdJYhj3PHHcBcFChDjlRkn9WSuNHNCtEA",
    "AKfycbyIHoLEPmFgAInQvI8RnbyKg6YGSgmwsnyaSszt-devJ_KR-EfbsxNmwKwGZUvft_Wj-w",
    "AKfycbw5mkS1i-84bvo6ut_ktuEJlH8RERWk0ch6USD09pzBqpAneSHAXHlk5hSHIky4-ERaZg",
    "AKfycbx64P7bbP10yTp_T1TsDXrdr04tVm9BCvNlt5qkYHvSzEf5RacsaGuNWf14-odZ878wZw",
    "AKfycbwcG9hdcCoAVmSFs8c79b5eHq2-z7QyTt-FWjuH6xtGe1Yi8FUSDTAkhklBESJS2R4kw",
    "AKfycbyvHxHkr2wxiLBEcWXL3v9z3lrYVRQ0TccLcavPx9XiIz3DNdchgPiub2bwVkfBI8rLcQ",
    "AKfycbxqofqb3mtxcB9WWfevhFzpsI7l8JdBMqoE7v3sB3cbpl3IOcUnzxRH46e4XiJQk3tDZw",
    "AKfycbySHrpjSEj6Ukt8qYDcFiaHuzuX3F-5sY1Sp33dLpqVljqfYJhDnxbRAA5xXR96MmgIEw",
]

REQUEST_TIMEOUT = 20  # seconds per GAS request


def _load_gas_ids() -> list[str]:
    """Load relay IDs from file (if present), fall back to built-in list."""
    ids = list(BUILTIN_GAS_IDS)
    if GAS_IDS_FILE.exists():
        try:
            file_ids = [
                line.strip() for line in GAS_IDS_FILE.read_text().splitlines()
                if line.strip() and not line.startswith("#")
            ]
            if file_ids:
                ids = file_ids + ids  # File IDs take priority
        except Exception:
            pass
    return ids


def _relay_request(gas_id: str, target_url: str, method: str,
                   headers: dict, body: bytes | None) -> dict | None:
    """
    Send one HTTP request through a single GAS relay endpoint.
    Returns dict with {status, headers, body_b64} or None on failure.
    """
    payload = json.dumps({
        "url":     target_url,
        "method":  method.upper(),
        "headers": {k: v for k, v in headers.items()
                    if k.lower() not in ("host", "proxy-connection",
                                         "proxy-authorization", "connection")},
        "body":    base64.b64encode(body).decode() if body else "",
    }).encode()

    gas_url = GAS_BASE_URL.format(id=gas_id)
    req = urllib.request.Request(
        gas_url,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        },
    )
    try:
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT, context=ctx) as resp:
            raw = resp.read()
        return json.loads(raw)
    except Exception:
        return None


# ── HTTP proxy request handler ───────────────────────────────────

class _GASProxyHandler(http.server.BaseHTTPRequestHandler):
    """Handles incoming browser proxy requests and relays through GAS."""

    gas_ids: list[str] = []
    _id_lock = threading.Lock()
    _current_idx = 0

    @classmethod
    def next_id(cls) -> str:
        with cls._id_lock:
            idx = cls._current_idx % len(cls.gas_ids)
            cls._current_idx += 1
            return cls.gas_ids[idx]

    def log_message(self, format, *args):
        pass  # Suppress default HTTP server logs

    def _send_error_response(self, code: int, message: str):
        body = message.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _do_relay(self, method: str):
        """Common relay logic for GET, POST, PUT, DELETE, etc."""
        # Build the target URL
        if self.path.startswith("http://") or self.path.startswith("https://"):
            target_url = self.path
        else:
            host = self.headers.get("Host", "")
            target_url = f"http://{host}{self.path}"

        # Read request body
        body = None
        content_len = int(self.headers.get("Content-Length", 0))
        if content_len > 0:
            body = self.rfile.read(content_len)

        # Try relay IDs in round-robin order; skip failed ones
        tried = 0
        max_tries = min(3, len(self.gas_ids))
        result = None

        while tried < max_tries:
            gas_id = self.next_id()
            result = _relay_request(
                gas_id, target_url, method,
                dict(self.headers), body,
            )
            if result is not None:
                break
            tried += 1

        if result is None:
            self._send_error_response(502, "GAS relay failed — all endpoints unreachable")
            return

        # Write response back to client
        status  = result.get("status", 200)
        headers = result.get("headers", {})
        body_b64 = result.get("body") or ""

        try:
            resp_body = base64.b64decode(body_b64)
        except Exception:
            resp_body = body_b64.encode()

        self.send_response(status)
        for key, val in headers.items():
            if key.lower() in ("transfer-encoding", "connection"):
                continue
            if isinstance(val, list):
                for v in val:
                    self.send_header(key, v)
            else:
                self.send_header(key, str(val))
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)

    def do_GET(self):     self._do_relay("GET")
    def do_POST(self):    self._do_relay("POST")
    def do_PUT(self):     self._do_relay("PUT")
    def do_DELETE(self):  self._do_relay("DELETE")
    def do_HEAD(self):    self._do_relay("HEAD")
    def do_OPTIONS(self): self._do_relay("OPTIONS")
    def do_PATCH(self):   self._do_relay("PATCH")

    def do_CONNECT(self):
        """
        HTTPS CONNECT tunneling is not supported through GAS.
        Inform the client to use HTTP or switch to the SNI/XRay engine.
        """
        self.send_response(405)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(
            b"CONNECT (HTTPS tunneling) is not supported by the GAS relay engine.\n"
            b"Use the SNI or XRay engine for HTTPS browsing.\n"
            b"The GAS engine handles HTTP traffic only.\n"
        )


class SilentThreadingTCPServer(socketserver.ThreadingTCPServer):
    """Threading TCP Server that suppresses stdout tracebacks on client disconnect."""
    def handle_error(self, request, client_address):
        pass


# ── Engine class ─────────────────────────────────────────────────

class AppsScriptEngine(Engine):
    """
    Google Apps Script HTTP Relay.
    No binary required — runs a pure Python proxy server.
    """
    name = "appsscript"
    description = "Google Apps Script relay — domain-fronts through Google (HTTP only)"

    def __init__(self, proxy_port: int = 0):
        super().__init__()
        from .. import settings as cfg
        s = cfg.load()
        self.proxy_port = proxy_port or s.get("gas_proxy_port", 8087)
        self._server: socketserver.TCPServer | None = None
        self._server_thread: threading.Thread | None = None
        self._running = False

    def _verify_relay(self, gas_id: str) -> bool:
        """Quick test: can we reach the GAS endpoint at all?"""
        result = _relay_request(
            gas_id,
            "http://cp.cloudflare.com/",
            "GET", {}, None,
        )
        return result is not None and result.get("status", 0) in (200, 204)

    def start(self) -> bool:
        ids = _load_gas_ids()
        if not ids:
            return False

        # Shuffle for load balancing and verify at least one ID works
        random.shuffle(ids)
        working_ids = []
        for gid in ids[:5]:  # Test at most 5 to keep startup fast
            if self._verify_relay(gid):
                working_ids.append(gid)

        if not working_ids:
            # Fall back to all IDs without verification (maybe network is partial)
            working_ids = ids

        # Configure the handler class
        _GASProxyHandler.gas_ids       = working_ids
        _GASProxyHandler._current_idx  = 0

        try:
            # Allow quick port reuse after restart
            socketserver.TCPServer.allow_reuse_address = True
            self._server = SilentThreadingTCPServer(
                ("127.0.0.1", self.proxy_port),
                _GASProxyHandler,
            )
        except OSError:
            return False  # Port in use

        self._running = True
        self._server_thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )
        self._server_thread.start()
        return True

    def stop(self):
        self._running = False
        if self._server:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                pass
            self._server = None
        super().stop()

    def is_running(self) -> bool:
        return (
            self._running
            and self._server_thread is not None
            and self._server_thread.is_alive()
        )

    @property
    def pid(self) -> int | None:
        return None  # Pure Python server, no subprocess
