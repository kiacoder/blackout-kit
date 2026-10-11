"""
Blackout Kit - v2 socks-tunnel engine.

Runs the Go `blackout-core` v2 daemon and drives its loopback SOCKS5 tunnel
over the local IPC channel. The daemon owns the actual outbound shaping
(fake-SNI rewrite + randomized SNI-boundary segmentation); this engine is the
Python-side supervisor: launch, start over IPC, keep-alive probing, and stop.

Out of scope by architecture (see changelog 1.4.0): no raw packets, no forged
TCP flags, no zero-window injection, no FEC frames on the wire.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from .. import BINS_DIR
from .. import v2_ipc
from .base import Engine

_TAIL_TIMEOUT = 3.0  # seconds to wait for the tunnel to accept after IPC start


class SocksTunnelEngine(Engine):
    name = "socks-tunnel"
    description = "v2 loopback SOCKS5 tunnel with ClientHello shaping (blackout-core daemon)"

    def __init__(self):
        super().__init__()
        self._client: v2_ipc.CoreClient | None = None
        self._listen: tuple[str, int] | None = None

    # ── binary discovery ─────────────────────────────────────────────────
    def find_core_binary(self) -> Path | None:
        """Locate the blackout-core daemon binary.

        Order: explicit BLACKOUT_CORE_BIN override, then the shared bins/
        directory, then a locally built dist/ output.
        """
        override = os.environ.get("BLACKOUT_CORE_BIN", "").strip()
        if override:
            candidate = Path(override)
            if candidate.is_file():
                return candidate
            self._log.error("BLACKOUT_CORE_BIN points at a missing file: %s", override)
        names = ["blackout-core.exe", "blackout-core"] if sys.platform == "win32" else ["blackout-core"]
        found = self.find_binary(names, system_names=names)
        if found:
            return found
        for dist_dir in (BINS_DIR.parent / "dist", BINS_DIR / "dist"):
            for name in names:
                candidate = dist_dir / name
                if candidate.is_file():
                    return candidate
        return None

    # ── endpoint ─────────────────────────────────────────────────────────
    def _endpoint(self) -> str:
        if sys.platform == "win32":
            return rf"\\.\pipe\blackout_ipc_socks_{os.getpid()}"
        return str(Path(self._config_dir) / "blackout-core.ipc")

    # ── lifecycle ────────────────────────────────────────────────────────
    def start(self) -> bool:
        """Launch blackout-core and start the loopback socks-tunnel over IPC."""
        from .. import settings as cfg

        binary = self.find_core_binary()
        if binary is None:
            self._log.error(
                "blackout-core binary not found. Install it with: blackout bins download "
                "blackout-core — or build it with: go -C engine/v2 build -o bins/blackout-core.exe "
                "./cmd/blackout-core (or set BLACKOUT_CORE_BIN)."
            )
            return False

        settings = cfg.load()
        port = int(settings.get("v2_tunnel_port", 18080))
        if not self.check_port_free(port):
            return False
        self._listen = ("127.0.0.1", port)

        endpoint = self._endpoint()
        command = self.binary_command(binary, "--endpoint", endpoint)
        if not self.start_process(command):
            return False
        if not self.wait_for_process():
            return False

        client = v2_ipc.CoreClient(endpoint, connect_timeout=10.0)
        try:
            client.connect()
            client.handshake()
            result = client.start("socks-tunnel", {"listen": f"127.0.0.1:{port}"})
        except (v2_ipc.IPCError, v2_ipc.IPCProtocolError, OSError) as exc:
            self._log.error("Could not start socks-tunnel over IPC: %s", exc)
            client.close()
            super().stop()
            return False

        self._client = client
        self._health_check_addr = self._listen

        fake_sni = str(settings.get("sni_fake_sni", "") or "").strip()
        if fake_sni:
            try:
                client.tune({"engine": "socks-tunnel", "fake_sni": fake_sni})
            except (v2_ipc.IPCError, v2_ipc.IPCProtocolError) as exc:
                # Tunnel is live; tuning the fake SNI is best-effort.
                self._log.warning("socks-tunnel started; fake-SNI tune rejected: %s", exc)

        self._log.info(
            "socks-tunnel running at %s:%d (status=%s, listen=%s)",
            self._listen[0], self._listen[1],
            result.get("status", "unknown"), result.get("listen", "?"),
        )
        return True

    def stop(self):
        """Stop the tunnel over IPC (force-closes live sessions), then kill the daemon."""
        client = self._client
        self._client = None
        if client is not None:
            try:
                client.stop()
            except Exception as exc:
                self._log.debug("IPC stop failed during engine stop: %s", exc)
            finally:
                client.close()
        super().stop()

    def is_running(self) -> bool:
        if self._client is None:
            return False
        if self._process is not None and self._process.poll() is not None:
            return False
        if self._health_check_addr is not None:
            import socket
            host, port = self._health_check_addr
            try:
                with socket.create_connection((host, port), timeout=1.0):
                    return True
            except OSError:
                return False
        return True

    def status(self) -> dict:
        """Best-effort daemon status snapshot; empty dict when not connected."""
        if self._client is None:
            return {}
        try:
            return self._client.status()
        except Exception:
            return {}
