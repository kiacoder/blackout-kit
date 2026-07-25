"""
Blackout Kit - SingBox Proxy Engine (Hysteria2 & TUIC).
Uses sing-box library inside blackout_core.dll.
"""
import json
import time
from pathlib import Path
from .base import Engine
from .. import settings as cfg

class SingBoxProxyEngine(Engine):
    name = "singbox_proxy"
    description = "SingBox Proxy Core — runs Hysteria2 / TUIC natively"

    def __init__(self, proxy_config=None, socks_port: int | None = None):
        super().__init__()
        s = cfg.load()
        self.proxy_config = proxy_config
        if not self.proxy_config:
            try:
                from ..config.manager import load_configs
                for c in load_configs():
                    if c.protocol in ("hysteria2", "tuic"):
                        self.proxy_config = c
                        break
            except Exception:
                pass
        self.socks_port = socks_port or s["xray_socks_port"]
        self._health_check_addr = ("127.0.0.1", self.socks_port)

    def _generate_config(self) -> dict:
        pc = self.proxy_config
        outbound = {
            "type": pc.protocol,  # "hysteria2" or "tuic"
            "tag": "proxy",
            "server": pc.address,
            "server_port": pc.port,
            "tls": {
                "enabled": True,
                "server_name": pc.sni or pc.address,
                "insecure": pc.insecure,
            }
        }

        if pc.protocol == "hysteria2":
            outbound["password"] = pc.password
        elif pc.protocol == "tuic":
            outbound["uuid"] = pc.uuid
            outbound["password"] = pc.password

        if pc.alpn:
            outbound["tls"]["alpn"] = [a.strip() for a in pc.alpn.split(",")]

        return {
            "log": {"level": "warn"},
            "inbounds": [
                {
                    "type": "socks",
                    "tag": "socks-in",
                    "listen": "127.0.0.1",
                    "listen_port": self.socks_port,
                    "sniff": True
                }
            ],
            "outbounds": [
                outbound,
                {"type": "direct", "tag": "direct"}
            ]
        }

    def start(self) -> bool:
        self._log.info(
            "Starting %s (%s)  socks_port=%d",
            self.proxy_config.protocol.upper(),
            self.proxy_config.display_name(),
            self.socks_port
        )

        config = self._generate_config()
        config_path = self._config_dir / f"singbox_{self.proxy_config.protocol}_config.json"
        config_path.write_text(json.dumps(config, indent=2))

        from ..core import get_core_dll
        dll = get_core_dll()
        if not dll:
            self._log.error("Core DLL missing! Ensure blackout_core.dll exists.")
            return False

        c_path = str(config_path).encode("utf-8")
        if dll.StartSingBoxC(c_path) == 0:
            self._dll_stop_func = dll.StopSingBoxC
            if not self.wait_for_port(self.socks_port, timeout=10.0):
                self._log.error("Singbox proxy started via DLL but SOCKS port %d never opened.", self.socks_port)
                self.stop()
                return False
            self._log.info("%s ready  socks5://127.0.0.1:%d", self.proxy_config.protocol.upper(), self.socks_port)
            return True
        else:
            self._log.error("Native DLL StartSingBoxC failed")
            return False
