"""
Blackout Kit - SingBox Proxy Engine (Hysteria2 & TUIC).
Uses sing-box library inside blackout_core.dll.
"""
import json
import sys

from .base import Engine
from .xray import LINUX_RUNNER_NAMES
from .. import settings as cfg


class SingBoxProxyEngine(Engine):
    name = "singbox_proxy"
    description = "SingBox Proxy Core — runs Hysteria2 / TUIC natively"
    supported_protocols = ("hysteria2", "tuic")

    def __init__(self, proxy_config=None, socks_port: int | None = None, protocol: str | None = None):
        super().__init__()
        s = cfg.load()
        self.requested_protocol = (protocol or getattr(self, "protocol", None) or "").lower() or None
        if self.requested_protocol and self.requested_protocol not in self.supported_protocols:
            raise ValueError(
                f"Unsupported sing-box protocol '{self.requested_protocol}'. "
                f"Expected one of: {', '.join(self.supported_protocols)}"
            )
        self.proxy_config = proxy_config
        if self.proxy_config and self.requested_protocol and self.proxy_config.protocol != self.requested_protocol:
            raise ValueError(
                f"Proxy config protocol '{self.proxy_config.protocol}' does not match requested "
                f"protocol '{self.requested_protocol}'."
            )
        if not self.proxy_config:
            try:
                from ..config.manager import load_configs
                for c in load_configs():
                    if c.protocol not in self.supported_protocols:
                        continue
                    if self.requested_protocol and c.protocol != self.requested_protocol:
                        continue
                    self.proxy_config = c
                    break
            except Exception:
                pass
        self.socks_port = socks_port or s["xray_socks_port"]
        self._health_check_addr = ("127.0.0.1", self.socks_port)

    def _generate_config(self) -> dict:
        pc = self.proxy_config
        server = pc.address
        if sys.platform.startswith("linux"):
            from .. import security as sec

            server = sec.linux_cached_endpoint(pc.address, pc.port) or pc.address
        outbound = {
            "type": pc.protocol,
            "tag": "proxy",
            "server": server,
            "server_port": pc.port,
            "tls": {
                "enabled": True,
                "server_name": pc.sni or pc.address,
                "insecure": pc.insecure,
            },
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
                    "sniff": True,
                }
            ],
            "outbounds": [
                outbound,
                {"type": "direct", "tag": "direct"},
            ],
        }

    def start(self) -> bool:
        if not self.proxy_config:
            wanted = self.requested_protocol or "hysteria2/tuic"
            self._log.error("No %s config found. Add one with 'blackout config add <uri>'.", wanted)
            return False

        if self.proxy_config.protocol not in self.supported_protocols:
            self._log.error(
                "Unsupported config protocol '%s' for sing-box proxy engine.",
                self.proxy_config.protocol,
            )
            return False

        if self.requested_protocol and self.proxy_config.protocol != self.requested_protocol:
            self._log.error(
                "Selected config protocol '%s' does not match requested '%s'.",
                self.proxy_config.protocol,
                self.requested_protocol,
            )
            return False

        if not self.check_port_free(self.socks_port):
            return False

        self._log.info(
            "Starting %s (%s)  socks_port=%d",
            self.proxy_config.protocol.upper(),
            self.proxy_config.display_name(),
            self.socks_port,
        )

        config_json = json.dumps(self._generate_config(), separators=(",", ":")).encode("utf-8")

        if sys.platform.startswith("linux"):
            runner = self.find_binary(LINUX_RUNNER_NAMES)
            if not runner:
                self._log.error("Linux sing-box proxy requires the managed blackout-engine runner.")
                return False
            config_path = self._config_dir / "singbox_proxy_config.json"
            config_path.write_bytes(config_json)
            if not self.start_process(self.binary_command(runner, "sing-box", "--config", str(config_path))):
                return False
            if not self.wait_for_port(self.socks_port, timeout=10.0):
                self._log.error("Sing-box runner did not open SOCKS port %d.", self.socks_port)
                self.stop()
                return False
            self._log.info("%s ready via Linux runner  socks5://127.0.0.1:%d", self.proxy_config.protocol.upper(), self.socks_port)
            return True

        from ..core import get_core_dll
        dll = get_core_dll()
        if not dll:
            self._log.error("Core DLL missing! Ensure blackout_core.dll exists.")
            return False

        if dll.StartSingBoxC(config_json) == 0:
            self._dll_stop_func = dll.StopSingBoxC
            if not self.wait_for_port(self.socks_port, timeout=10.0):
                self._log.error("Singbox proxy started via DLL but SOCKS port %d never opened.", self.socks_port)
                self.stop()
                return False
            self._log.info("%s ready  socks5://127.0.0.1:%d", self.proxy_config.protocol.upper(), self.socks_port)
            return True

        self._log.error("Native DLL StartSingBoxC failed")
        return False


class Hysteria2Engine(SingBoxProxyEngine):
    name = "hysteria2"
    description = "Hysteria2 QUIC proxy via sing-box"
    protocol = "hysteria2"


class TuicEngine(SingBoxProxyEngine):
    name = "tuic"
    description = "TUIC QUIC proxy via sing-box"
    protocol = "tuic"
