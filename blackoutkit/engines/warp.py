"""
Blackout Kit - Cloudflare WARP engine.
Uses our own blackout_warp.dll (Go) for WARP+ tunneling.
No external binary downloads needed.
"""
from .base import Engine
from .. import settings as cfg

_STARTUP_TIMEOUT = 20.0


class WARPEngine(Engine):
    name = "warp"
    description = "Cloudflare WARP — clean residential-class IP, bypasses most captchas"

    def __init__(self, socks_port: int | None = None, country: str | None = None):
        super().__init__()
        s = cfg.load()
        self.socks_port = socks_port or 1080
        self.country    = country or s.get("psiphon_country", "DE")
        self._health_check_addr = ("127.0.0.1", self.socks_port)

    def start(self) -> bool:
        self._log.info(
            "Starting WARP  socks_port=%d  country=%s",
            self.socks_port, self.country,
        )

        from ..core import get_warp_dll
        dll = get_warp_dll()
        if not dll:
            self._log.error(
                "WARP DLL missing! blackout_warp.dll is required.\n"
                "  Build from engine/warp/ with: cd engine/warp && go build -buildmode=c-shared -o ../../bins/blackout_warp.dll .\n"
                "  Or check bins/ for the pre-built DLL."
            )
            return False

        self._log.info("Launching WARP via native DLL")
        c_country = (self.country or "none").encode("utf-8")
        if dll.StartWarpC(self.socks_port, c_country) == 0:
            self._dll_stop_func = dll.StopWarpC
            if not self.wait_for_port(self.socks_port, timeout=_STARTUP_TIMEOUT):
                self._log.error("WARP started via DLL but SOCKS port %d never opened.", self.socks_port)
                self.stop()
                return False
            self._log.info("WARP ready  socks5=127.0.0.1:%d  country=%s.", self.socks_port, self.country)
            return True
        else:
            self._log.error("Native DLL StartWarpC failed")
            return False
