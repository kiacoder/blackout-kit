"""
Blackout Kit - Psiphon engine.
Uses the current blackout_warp.dll runtime path for the active Psiphon implementation.
Source installs still need that local runtime asset available.
"""
from .. import settings as cfg
from .base import Engine

_STARTUP_TIMEOUT = 60.0


class PsiphonEngine(Engine):
    name = "psiphon"
    description = "Psiphon multi-protocol VPN — ultimate fallback"

    def __init__(self, country: str | None = None, http_port: int | None = None, socks_port: int | None = None):
        super().__init__()
        s = cfg.load()
        self.country    = country    or s["psiphon_country"]
        self.http_port  = http_port  or s["psiphon_http_port"]
        self.socks_port = socks_port or s["psiphon_socks_port"]
        # Go DLL only opens SOCKS port for psiphon, not HTTP port
        self._health_check_addr = ("127.0.0.1", self.socks_port)

    def start(self) -> bool:
        # The DLL opens a SOCKS listener and nothing else. Logging http_port as
        # if it were being served invited users to point a browser at a port
        # with no listener behind it.
        self._log.info(
            "Starting Psiphon  country=%s  socks_port=%d  (no HTTP proxy: "
            "the native engine serves SOCKS only)",
            self.country, self.socks_port,
        )
        if self.http_port:
            self._log.warning(
                "psiphon_http_port=%d is not used by this engine; "
                "point applications at the SOCKS proxy instead.",
                self.http_port,
            )

        from ..core import get_warp_dll
        dll = get_warp_dll()
        if not dll:
            self._log.error(
                "WARP DLL missing! blackout_warp.dll is required for Psiphon."
            )
            return False

        self._log.info("Launching Psiphon via native DLL")
        c_country = (self.country or "DE").encode("utf-8")
        # Pass 0: there is no HTTP inbound, so claiming a port here would only
        # make the DLL print a warning about a listener it cannot create.
        if dll.StartPsiphonC(self.socks_port, 0, c_country) == 0:
            self._dll_stop_func = dll.StopPsiphonC
            if not self.wait_for_port(self.socks_port, timeout=_STARTUP_TIMEOUT):
                self._log.error("Psiphon started via DLL but SOCKS port %d never opened.", self.socks_port)
                self.stop()
                return False
            self._log.info("Psiphon ready  socks=127.0.0.1:%d  country=%s.", self.socks_port, self.country)
            return True
        else:
            self._log.error("Native DLL StartPsiphonC failed")
            return False
