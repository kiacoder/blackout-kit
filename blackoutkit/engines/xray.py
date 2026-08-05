"""
Blackout Kit - XRay/V2Ray core engine.
Manages the xray.exe process with dynamic config generation.
Supports Trojan and VLESS protocols over WebSocket+TLS.
Works alongside the SNI engine (outbound → 127.0.0.1:40443).

Legendary upgrade:
  - cert_bypass integration: allowInsecure is now mode-aware instead of hardcoded True
      SPEED   → always True (no change from before)
      PRIVATE → True but proactively probes cert in background and warns if bad
      LEGEND  → False when cert is known-bad (hard fail); True when unknown/valid
  - Background stderr monitor: scans xray output for cert error phrases
    and records them in the cert store even in "none" log level mode
"""
import json
import subprocess
import threading
from pathlib import Path
from .base import Engine, BINS_DIR
from .. import settings as cfg
from .. import security as _sec
from .. import cert_bypass as _cb

XRAY_BIN_NAMES = [
    "xray.exe",
    "xray-windows-64.exe",
    "xray-core.exe",
]


class XRayEngine(Engine):
    name = "xray"
    description = "XRay proxy core — routes traffic through SNI spoofer"

    def __init__(self, proxy_config=None, socks_port: int | None = None, http_port: int | None = None):
        super().__init__()
        s = cfg.load()
        self.proxy_config = proxy_config
        if not self.proxy_config:
            try:
                from ..config.manager import load_configs
                for c in load_configs():
                    if c.protocol in ("vless", "trojan", "vmess"):
                        self.proxy_config = c
                        break
            except Exception:
                pass
        self.socks_port   = socks_port or s["xray_socks_port"]
        self.http_port    = http_port  or s["xray_http_port"]
        self._health_check_addr = ("127.0.0.1", self.http_port)

    def generate_config(self) -> dict:
        s    = cfg.load()
        mode = _sec.get_current_mode()
        config = {
            "log": {
                "loglevel": "warning",
                "access": "none",
                "error": "none"
            },
            "inbounds": [
                {
                    "tag": "socks-in",
                    "port": self.socks_port,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {"auth": "noauth", "udp": True},
                    "sniffing": {"enabled": True, "destOverride": ["http", "tls", "fakedns"] if s.get("xray_doh_dns") else ["http", "tls"]},
                },
                {
                    "tag": "http-in",
                    "port": self.http_port,
                    "listen": "127.0.0.1",
                    "protocol": "http",
                    "settings": {},
                    "sniffing": {"enabled": True, "destOverride": ["http", "tls", "fakedns"] if s.get("xray_doh_dns") else ["http", "tls"]},
                },
            ],
            "outbounds": [],
            "routing": {
                "domainStrategy": "IPIfNonMatch",
                "rules": []
            }
        }

        # ── DNS Leak Protection (DoH) ─────────────────────────────
        if s.get("xray_doh_dns"):
            config["dns"] = {
                "servers": [
                    "https+local://cloudflare-dns.com/dns-query",
                    "https+local://dns.google/dns-query",
                    "1.1.1.1",
                    "8.8.8.8",
                    "localhost"
                ],
                "queryStrategy": "UseIP"
            }
            # Route all DNS queries (udp/tcp 53) directly to proxy
            config["routing"]["rules"].append({
                "type": "field",
                "port": 53,
                "network": "udp,tcp",
                "outboundTag": "proxy"
            })

        # ── Smart Split Tunneling ─────────────────────────────────
        if s.get("xray_split_tunnel"):
            config["routing"]["rules"].extend([
                {
                    "type": "field",
                    "ip": [
                        "127.0.0.0/8",
                        "10.0.0.0/8",
                        "172.16.0.0/12",
                        "192.168.0.0/16",
                        "::1/128",
                        "fc00::/7",
                        "fe80::/10"
                    ],
                    "outboundTag": "direct"
                },
                {
                    "type": "field",
                    "domain": [
                        "regexp:.*\\.ir$",
                        "regexp:.*\\.gov\\.ir$",
                        "regexp:.*\\.ac\\.ir$",
                        "regexp:.*\\.co\\.ir$"
                    ],
                    "outboundTag": "direct"
                }
            ])

        # Default catch-all rule to route everything else to proxy
        config["routing"]["rules"].append({
            "type": "field",
            "network": "tcp,udp",
            "outboundTag": "proxy"
        })

        if self.proxy_config:
            outbound = self._build_outbound(self.proxy_config)
        else:
            # Fall back to the xray_config.json shipped with SNI-Spoofer if present
            fallback = BINS_DIR / "xray_config.json"
            if fallback.exists():
                try:
                    existing = json.loads(fallback.read_text())
                    config["outbounds"] = existing.get("outbounds", [])
                    # Ensure the first outbound is tagged 'proxy' so our routing rules work
                    if config["outbounds"] and not any(o.get("tag") == "proxy" for o in config["outbounds"]):
                        config["outbounds"][0]["tag"] = "proxy"
                    # Add direct/block if missing
                    tags = [o.get("tag") for o in config["outbounds"]]
                    if "direct" not in tags:
                        config["outbounds"].append({"tag": "direct", "protocol": "freedom"})
                    if "block" not in tags:
                        config["outbounds"].append({"tag": "block", "protocol": "blackhole"})
                    return config
                except (json.JSONDecodeError, OSError):
                    pass  # Corrupt/unreadable fallback — fall through to default
            outbound = self._default_outbound()

        # ── LEGEND Mode: Chain to Tor ────────────────────────────
        if mode == "legend":
            # Add Tor SOCKS outbound
            tor_outbound = {
                "tag": "tor-out",
                "protocol": "socks",
                "settings": {
                    "servers": [{
                        "address": "127.0.0.1",
                        "port": 9050
                    }]
                }
            }
            config["outbounds"].append(tor_outbound)
            # Link main proxy outbound to Tor
            outbound["proxySettings"] = {"tag": "tor-out"}
            self._log.info("LEGEND mode: Chaining XRay outbound through Tor (127.0.0.1:9050)")

        config["outbounds"].insert(0, outbound)
        config["outbounds"].extend([
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block",  "protocol": "blackhole"},
        ])
        return config

    def _build_outbound(self, c) -> dict:
        s    = cfg.load()
        mode = _sec.get_current_mode()
        allow_insecure, _warn = _cb.should_allow_insecure(c.address, c.port, mode)
        
        # ── Fragment Mode (TIC 2026 Evasion) ─────────────────────
        # Only active if xray_fragment is set in settings
        frag = s.get("xray_fragment")
        fragment_settings = None
        if frag and "," in frag:
            try:
                packets, length = frag.split(",")
                fragment_settings = {
                    "packets": packets,
                    "length": length,
                    "system": "tls"
                }
            except Exception:
                pass

        stream = {
            "network":  "ws",
            "security": "tls",
            "tlsSettings": {
                "serverName":    c.sni,
                "fingerprint":   s["xray_fingerprint"],
                "allowInsecure": allow_insecure,
            },
            "wsSettings": {
                "path":    c.path or "/",
                "headers": {"Host": c.host or c.sni},
            },
        }


        if fragment_settings:
            stream["tlsSettings"]["fragment"] = fragment_settings
            self._log.debug("TLS Fragmentation enabled: %s", frag)

        if c.protocol == "trojan":
            return {
                "tag":      "proxy",
                "protocol": "trojan",
                "settings": {"servers": [{"address": c.address, "port": c.port, "password": c.password}]},
                "streamSettings": stream,
                "mux": {"enabled": s["xray_mux_enabled"]},
            }
        if c.protocol == "vless":
            return {
                "tag":      "proxy",
                "protocol": "vless",
                "settings": {"vnext": [{"address": c.address, "port": c.port,
                                         "users": [{"id": c.uuid, "encryption": "none"}]}]},
                "streamSettings": stream,
                "mux": {"enabled": s["xray_mux_enabled"]},
            }
        self._log.warning("Protocol '%s' is unsupported, falling back to trojan", c.protocol)
        return self._default_outbound()

    def _default_outbound(self) -> dict:
        """Use the built-in Trojan config from the SNI-Spoofer package."""
        s = cfg.load()
        out = {
            "tag":      "proxy",
            "protocol": "trojan",
            "settings": {"servers": [{"address": "127.0.0.1", "port": s["sni_listen_port"], "password": "humanity"}]},
            "streamSettings": {
                "network":  "ws",
                "security": "tls",
                "tlsSettings": {
                    "serverName":    "www.creationlong.org",
                    "fingerprint":   s["xray_fingerprint"],
                },
                "wsSettings": {"path": "/assignment", "headers": {"Host": "www.creationlong.org"}},
            },
        }
        return out

    def start(self) -> bool:

        # Fail fast if either port is already occupied — avoids silent false-success
        if not self.check_port_free(self.socks_port) or not self.check_port_free(self.http_port):
            return False

        # ── Per-mode cert policy (before config generation) ───────
        mode = _sec.get_current_mode()
        if self.proxy_config and self.proxy_config.address not in _cb.LOCAL_ADDRS:
            host = self.proxy_config.address
            port = self.proxy_config.port

            if mode == "legend":
                # Synchronous probe — LEGEND hard-fails on known-bad certs
                record = _cb.check_host_cert(host, port, timeout=3.0)
                if not record.cert_ok and not record.manually_allowed:
                    if record.error and "Connection" in record.error:
                        # Network error (not a cert issue) — allow anyway
                        self._log.debug("Cert probe network error for %s:%d: %s (allowing)", host, port, record.error)
                    else:
                        self._log.error(
                            "LEGEND mode: cert verification FAILED for %s:%d — %s  "
                            "Connection refused. To override: blackout tools cert-check %s --allow",
                            host, port, record.error, host,
                        )
                        return False

            elif mode == "private":
                # Background probe — connects immediately but warns if cert is bad
                def _probe(h: str, p: int) -> None:
                    rec = _cb.check_host_cert(h, p, timeout=3.0)
                    if not rec.cert_ok:
                        self._log.warning(
                            "PRIVATE mode cert warning for %s:%d: %s  "
                            "(allowInsecure=True, connection proceeding)",
                            h, p, rec.error,
                        )
                threading.Thread(
                    target=_probe, args=(host, port),
                    daemon=True, name=f"cert-probe-{host}",
                ).start()

            # SPEED: no probe, allowInsecure=True always — zero overhead

        config      = self.generate_config()
        config_path = self._config_dir / "xray_config.json"
        config_path.write_text(json.dumps(config, indent=2))

        from ..core import get_core_dll
        dll = get_core_dll()
        if not dll:
            self._log.error("Core DLL missing! Ensure blackout_core.dll is built.")
            return False

        self._log.info("Launching XRay via native DLL")
        c_path = str(config_path).encode("utf-8")
        if dll.StartXrayC(c_path) == 0:
            self._dll_stop_func = dll.StopXrayC
            
            if not self.wait_for_port(self.http_port, timeout=10.0):
                self._log.error("XRay started natively via DLL but HTTP port %d never opened within 10s.", self.http_port)
                self.stop()
                return False

            self._start_cert_monitor(mode)
            self._log.info(
                "XRay ready natively socks=%d  http=%d.",
                self.socks_port, self.http_port,
            )
            return True
        else:
            self._log.error("Native DLL StartXrayC failed")
            return False

    def _start_cert_monitor(self, mode: str) -> None:
        """
        Daemon thread that reads xray stderr and records any cert error phrases.
        For PRIVATE mode, also logs a warning to the engine logger.
        """
        proc = self._process

        def _reader() -> None:
            if proc is None or proc.stderr is None:
                return
            try:
                for raw_line in proc.stderr:
                    line = raw_line.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    snippet = _cb.scan_xray_line(line)
                    if snippet:
                        # Best-effort: try to extract host from the log line
                        import re
                        m = re.search(r"(?:dial|connect)\s+(?:tcp\s+)?(\S+):(\d+)", line)
                        if m:
                            h, p = m.group(1), int(m.group(2))
                            rec = _cb.get_record(h, p)
                            if rec is None:
                                # Record without a full probe — just note the error
                                _cb.save_record(_cb.HostCertRecord(
                                    host=h, port=p, checked_at=__import__("time").time(),
                                    cert_ok=False, subject="", issuer="", expires="",
                                    days_left=0, self_signed=False, error=snippet,
                                ))
                        if mode == "private":
                            self._log.warning("Cert issue in xray output: %s", snippet)
            except (ValueError, OSError):
                pass  # Pipe closed — process exited

        threading.Thread(
            target=_reader, daemon=True, name="xray-cert-monitor",
        ).start()
