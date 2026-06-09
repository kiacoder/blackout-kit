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
        self.socks_port   = socks_port or s["xray_socks_port"]
        self.http_port    = http_port  or s["xray_http_port"]

    def generate_config(self) -> dict:
        s    = cfg.load()
        mode = _sec.get_current_mode()
        config = {
            "log": {"loglevel": s["xray_log_level"]},
            "inbounds": [
                {
                    "tag": "socks-in",
                    "port": self.socks_port,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {"auth": "noauth", "udp": True},
                    "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
                },
                {
                    "tag": "http-in",
                    "port": self.http_port,
                    "listen": "127.0.0.1",
                    "protocol": "http",
                    "settings": {},
                },
            ],
            "outbounds": [],
        }

        if self.proxy_config:
            outbound = self._build_outbound(self.proxy_config)
        else:
            # Fall back to the xray_config.json shipped with SNI-Spoofer if present
            fallback = BINS_DIR / "xray_config.json"
            if fallback.exists():
                try:
                    existing = json.loads(fallback.read_text())
                    # Keep inbounds but use existing outbounds
                    config["outbounds"] = existing.get("outbounds", [])
                    # If legend mode, we still want to try to chain Tor if possible,
                    # but custom configs might conflict. For now, we trust the custom config.
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
                "allowInsecure": allow_insecure,
                "fingerprint":   s["xray_fingerprint"],
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
        raise ValueError(f"Unsupported protocol: {c.protocol}")

    def _default_outbound(self) -> dict:
        """Use the built-in Trojan config from the SNI-Spoofer package."""
        s = cfg.load()
        return {
            "tag":      "proxy",
            "protocol": "trojan",
            "settings": {"servers": [{"address": "127.0.0.1", "port": s["sni_listen_port"], "password": "humanity"}]},
            "streamSettings": {
                "network":  "ws",
                "security": "tls",
                "tlsSettings": {
                    "serverName":    "www.creationlong.org",
                    "allowInsecure": True,
                    "fingerprint":   s["xray_fingerprint"],
                },
                "wsSettings": {"path": "/assignment", "headers": {"Host": "www.creationlong.org"}},
            },
        }

    def start(self) -> bool:
        binary = self.find_binary(XRAY_BIN_NAMES)
        if not binary:
            return False

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
        config_path = BINS_DIR / "active_xray_config.json"
        config_path.write_text(json.dumps(config, indent=2))

        engine_bin = BINS_DIR / "blackout-engine.exe"
        if engine_bin.exists():
            cmd = [str(engine_bin), "xray", "--config", str(config_path)]
        else:
            cmd = [str(binary), "run", "-c", str(config_path)]

        try:
            self._process = subprocess.Popen(
                cmd,
                cwd=str(BINS_DIR),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
        except Exception as exc:
            self._log.error("Failed to launch xray: %s", exc)
            return False

        # Verify XRay actually opened its HTTP listener — without this check
        # start() would return True even if xray silently exited on bad config.
        if not self.wait_for_port(self.http_port, timeout=10.0):
            if not self.check_process_alive():
                self._log.error(
                    "XRay exited before HTTP port %d opened (rc=%s).",
                    self.http_port,
                    self._process.returncode if self._process else "?",
                )
            else:
                self._log.error(
                    "XRay started but HTTP port %d never opened within 10s. "
                    "Check xray_config.json or run 'blackout doctor'.",
                    self.http_port,
                )
            self.stop()
            return False

        # ── Background stderr cert monitor ────────────────────────
        self._start_cert_monitor(mode)
        self._log.info(
            "XRay ready  socks=%d  http=%d  (pid=%s).",
            self.socks_port, self.http_port, self._process.pid,
        )
        return True

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
