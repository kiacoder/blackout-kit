"""
Blackout Kit - XRay/V2Ray core engine.
Manages the xray.exe process with dynamic config generation.
Supports Trojan and VLESS protocols over TLS and REALITY transports.
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
import sys
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
LINUX_RUNNER_NAMES = ["blackout-engine"]


class XRayEngine(Engine):
    name = "xray"
    description = "XRay proxy core — routes traffic through SNI spoofer"

    def __init__(self, proxy_config=None, socks_port: int | None = None, http_port: int | None = None):
        super().__init__()
        s = cfg.load()
        self.proxy_config = proxy_config
        if not self.proxy_config:
            try:
                from ..config.manager import select_proxy_config
                compatible = ("vless", "trojan", "vmess")
                if sys.platform.startswith("linux"):
                    compatible = ("vless", "trojan")
                self.proxy_config = select_proxy_config(compatible)
            except Exception:
                pass
        if sys.platform.startswith("linux") and self.proxy_config and self.proxy_config.protocol == "vmess":
            self._log.warning("Linux XRay currently supports VLESS and Trojan configs; skipping VMess.")
            self.proxy_config = None
            try:
                from ..config.manager import load_configs
                self.proxy_config = next(
                    (c for c in load_configs() if c.protocol in ("vless", "trojan")),
                    None,
                )
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
            from ..country_profiles import bypass_domains_for
            country_code = s.get("country", "")
            bypass_domains = bypass_domains_for(country_code)
            domain_rules = []
            for entry in bypass_domains:
                if entry.startswith("domain:"):
                    domain_rules.append(entry.replace("domain:", ""))
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
                    "domain": domain_rules,
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

        # ── Fragment Mode (TIC 2026 Evasion) ─────────────────────
        frag = s.get("xray_fragment")
        if frag and "," in frag:
            try:
                parts = frag.split(",")
                fragment_settings = {}
                if len(parts) == 2:
                    fragment_settings = {"packets": "tlshello", "length": parts[0], "interval": parts[1]}
                elif len(parts) >= 3:
                    fragment_settings = {"packets": parts[0], "length": parts[1], "interval": parts[2]}
                
                if fragment_settings:
                    frag_outbound = {
                        "tag": "fragment-out",
                        "protocol": "freedom",
                        "settings": {
                            "fragment": fragment_settings
                        }
                    }
                    config["outbounds"].append(frag_outbound)
                    # Route proxy traffic through the fragment outbound via dialerProxy
                    outbound.setdefault("streamSettings", {}).setdefault("sockopt", {})["dialerProxy"] = "fragment-out"
                    self._log.info("TLS Record-Layer Fragmentation enabled: %s", frag)
            except Exception as e:
                self._log.error("Failed to parse xray_fragment: %s", e)

        config["outbounds"].insert(0, outbound)
        config["outbounds"].extend([
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block",  "protocol": "blackhole"},
        ])
        return config

    def _build_outbound(self, c) -> dict:
        s = cfg.load()
        is_reality = c.is_reality()
        validation_error = c.reality_validation_error()
        if validation_error:
            raise ValueError(validation_error)

        target_ip = c.address
        if sys.platform.startswith("linux"):
            cached = _sec.linux_cached_endpoint(c.address, c.port)
            if cached:
                target_ip = cached

        if target_ip == c.address:
            from ..tools import resolve_doh
            resolved = resolve_doh(c.address)
            if resolved and resolved != c.address:
                target_ip = resolved
                self._log.debug("DoH Bootstrap: resolved %s -> %s", c.address, target_ip)
            elif not resolved:
                self._log.warning("DoH Bootstrap failed to resolve %s", c.address)
        elif target_ip != c.address:
            self._log.debug("Using prevalidated Linux endpoint for configured proxy host")

        stream = {"network": c.transport}
        if c.transport == "ws":
            stream["wsSettings"] = {
                "path": c.path or "/",
                "headers": {"Host": c.host or c.sni},
            }
        elif c.transport == "grpc":
            stream["grpcSettings"] = {"serviceName": c.service_name}
        elif c.transport in ("xhttp", "splithttp"):
            xhttp_settings = {
                "path": c.path or "/",
                "host": c.host or c.sni,
            }
            if c.xhttp_mode:
                xhttp_settings["mode"] = c.xhttp_mode
            stream["xhttpSettings"] = xhttp_settings

        if is_reality:
            stream["security"] = "reality"
            stream["realitySettings"] = {
                "show": False,
                "fingerprint": c.fp or s["xray_fingerprint"],
                "serverName": c.sni,
                "publicKey": c.public_key,
                "shortId": c.short_id,
                "spiderX": c.spider_x,
            }
        else:
            mode = _sec.get_current_mode()
            allow_insecure, _warn = _cb.should_allow_insecure(c.address, c.port, mode)
            stream["security"] = "tls"
            stream["tlsSettings"] = {
                "serverName": c.sni,
                "fingerprint": c.fp or s["xray_fingerprint"],
            }

        if c.protocol == "trojan":
            return {
                "tag": "proxy",
                "protocol": "trojan",
                "settings": {"servers": [{"address": target_ip, "port": c.port, "password": c.password}]},
                "streamSettings": stream,
                "mux": {"enabled": s["xray_mux_enabled"]},
            }
        if c.protocol == "vless":
            user = {"id": c.uuid, "encryption": "none"}
            if c.flow:
                user["flow"] = c.flow
            return {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {"vnext": [{"address": target_ip, "port": c.port, "users": [user]}]},
                "streamSettings": stream,
                "mux": {"enabled": s["xray_mux_enabled"]},
            }
        self._log.warning("Protocol '%s' is unsupported, falling back to trojan", c.protocol)
        return self._default_outbound()

    def _is_reality_config(self) -> bool:
        return bool(self.proxy_config and self.proxy_config.is_reality())

    def _validate_proxy_config(self) -> bool:
        if not self.proxy_config:
            return True
        validation_error = self.proxy_config.reality_validation_error()
        if validation_error:
            self._log.error("%s", validation_error)
            return False
        return True

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

        if not self._validate_proxy_config():
            return False

        # ── Per-mode cert policy (before config generation) ───────
        mode = _sec.get_current_mode()
        if (
            self.proxy_config
            and not self._is_reality_config()
            and self.proxy_config.address not in _cb.LOCAL_ADDRS
        ):
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

        if sys.platform.startswith("linux") and (
            not self.proxy_config
            or self.proxy_config.address in {"127.0.0.1", "0.0.0.0", "localhost", "::1"}
        ):
            self._log.error(
                "Linux XRay requires a direct VLESS or Trojan configuration; "
                "the Windows SNI fallback and VMess runtime path are unavailable on Linux."
            )
            return False

        config = self.generate_config()
        config_path = self._config_dir / "xray_config.json"
        config_path.write_text(json.dumps(config, indent=2))

        if sys.platform.startswith("linux"):
            runner = self.find_binary(LINUX_RUNNER_NAMES)
            if not runner:
                self._log.error(
                    "Linux XRay requires the managed blackout-engine runner. "
                    "Install the Linux release asset or build it from engine/."
                )
                return False
            self._log.info("Launching XRay through the Linux blackout-engine runner")
            if not self.start_process(self.binary_command(runner, "xray", "--config", str(config_path))):
                return False
            if not self.wait_for_port(self.http_port, timeout=10.0):
                self._log.error("XRay runner did not open HTTP port %d within 10s.", self.http_port)
                self.stop()
                return False
            self._log.info("XRay ready via Linux runner socks=%d http=%d.", self.socks_port, self.http_port)
            return True

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

            if not self._is_reality_config():
                self._start_cert_monitor(mode)
            self._log.info(
                "XRay ready natively socks=%d  http=%d.",
                self.socks_port, self.http_port,
            )
            return True
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
