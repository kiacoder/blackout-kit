"""
Blackout Kit - Neighbor Internet engine.

Connect to the internet via a nearby device running Blackout Kit.
This is for the scenario: YOUR internet is blocked, but a neighbor's is not.

═══════════════════════════════════════════════════════════════════════
  HOW IT WORKS (simple version)
═══════════════════════════════════════════════════════════════════════

  SHARER (has internet):
    1. Runs Blackout Kit normally (SNI/GoodbyeDPI/etc.)
    2. Enables neighbor-share mode → broadcasts a UDP beacon on LAN
    3. Creates a WiFi hotspot (optional) so guests can join

  GUEST (no internet):
    1. Connects to sharer's WiFi hotspot (phone/laptop nearby)
    2. Runs 'blackout neighbor connect' → discovers sharer automatically
    3. Routes all traffic through sharer's proxy
    4. Internet works!

  Discovery uses UDP multicast (no internet needed — works purely on LAN).
  The sharer's proxy is accessed via SOCKS5 chaining.

═══════════════════════════════════════════════════════════════════════

Commands:
  blackout neighbor discover   — Scan LAN for nearby sharers
  blackout neighbor connect    — Auto-discover + use a neighbor's proxy
  blackout neighbor share      — Announce your proxy to nearby devices
"""
import socket
import struct
import threading
import time
from .base import Engine

# UDP multicast group — same on all Blackout Kit instances for auto-discovery
MCAST_GROUP      = "239.255.42.99"
MCAST_PORT       = 51820
BEACON_INTERVAL  = 5    # seconds between beacons
DISCOVERY_TIMEOUT = 8   # seconds to wait for a beacon

# Magic prefix — prevents false positives from other multicast traffic
BEACON_PREFIX = b"BLACKOUTKIT:v1:"


class NeighborShareEngine(Engine):
    """
    Share mode: Broadcasts a LAN beacon so nearby guests can discover you.
    Does NOT start a proxy itself — you must already be running an engine.
    Also rebinds the proxy to 0.0.0.0 so LAN devices can reach it.
    """
    name = "neighbor-share"
    description = "Share your bypass proxy with nearby LAN devices"

    def __init__(self, proxy_port: int = 0):
        super().__init__()
        from .. import settings as cfg
        s = cfg.load()
        self.target_port = proxy_port or s.get("xray_http_port", 10809)
        self.listen_port = s.get("neighbor_proxy_port", 10809)
        if self.listen_port == self.target_port:
            # If the proxy is already bound to 0.0.0.0, binding again will fail.
            # But the Go forwarder needs to bind on listen_port.
            # If they match, we could either assume the existing proxy is accessible,
            # or we offset the listen port. Let's offset it so the Go reverse proxy is always used.
            self.listen_port = self.target_port + 1
        
        self._running   = False

    def start(self) -> bool:
        from ..core import get_core_dll
        dll = get_core_dll()
        if not dll:
            self._log.error("Core DLL missing! Ensure blackout_core.dll is built.")
            return False

        self._log.info("Starting high-performance Go reverse proxy for LAN sharing...")
        if dll.StartNeighborC(self.listen_port, self.target_port) == 0:
            self._dll_stop_func = dll.StopNeighborC
            self._running = True
            self._log.info("Neighbor LAN sharing active on port %d (forwarding to %d)", self.listen_port, self.target_port)
            return True
        else:
            self._log.error("Native DLL StartNeighborC failed")
            return False

    def stop(self):
        self._running = False
        super().stop()

    def is_running(self) -> bool:
        return self._running


class NeighborConnectEngine(Engine):
    """
    Guest mode: Discovers a nearby Blackout Kit sharer via LAN multicast
    and keeps a heartbeat connection alive to their proxy.

    After start(), the caller should configure their outbound proxy to:
      SOCKS5 / HTTP →  self.peer_host : self.peer_port

    (In Blackout Kit, we chain through a second XRay/sing-box instance
     that proxies through the discovered peer. The peer's proxy is
     effectively your gateway to the internet.)
    """
    name = "neighbor"
    description = "Neighbor internet — route through a nearby Blackout Kit device"

    def __init__(self, peer_host: str = "", peer_port: int = 0):
        super().__init__()
        # Allow manual specification (e.g. blackout neighbor connect --host 192.168.1.5)
        self.peer_host = peer_host
        self.peer_port = peer_port
        self._running  = False
        self._thread: threading.Thread | None = None

    # ── Discovery ─────────────────────────────────────────────────

    @staticmethod
    def discover(timeout: float = DISCOVERY_TIMEOUT) -> tuple[str, int] | None:
        """
        Listen for a LAN beacon from a NeighborShareEngine.
        Returns (host_ip, proxy_port) on success, None on timeout.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.settimeout(timeout)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("", MCAST_PORT))

            mreq = struct.pack("4sL", socket.inet_aton(MCAST_GROUP), socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    data, addr = sock.recvfrom(256)
                    if data.startswith(BEACON_PREFIX):
                        port_part = data[len(BEACON_PREFIX):]
                        port      = int(port_part.decode())
                        return addr[0], port
                except socket.timeout:
                    pass
                except Exception:
                    pass
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass
        return None

    # ── Heartbeat ─────────────────────────────────────────────────

    def _heartbeat_loop(self):
        """Keep checking that the peer proxy is reachable."""
        while self._running:
            try:
                with socket.create_connection((self.peer_host, self.peer_port), timeout=5):
                    pass
                time.sleep(10)
            except Exception:
                # Peer went offline
                self._running = False
                break

    # ── Engine interface ─────────────────────────────────────────

    def start(self) -> bool:
        if not self.peer_host or not self.peer_port:
            return False

        # Verify the peer is reachable before claiming success
        try:
            with socket.create_connection((self.peer_host, self.peer_port), timeout=5):
                pass
        except Exception:
            return False

        self._running = True
        self._thread  = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._thread.start()
        return True

    def stop(self):
        self._running = False
        super().stop()

    def is_running(self) -> bool:
        return self._running and self._thread is not None and self._thread.is_alive()
