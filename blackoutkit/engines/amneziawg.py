"""
Blackout Kit - AmneziaWG engine (native userspace core).

AmneziaWG is a WireGuard variant with junk-packet obfuscation that resists DPI.
This engine drives the bundled **awg-go** core (source: ``core/amneziawg-go``,
built as ``bins/awg-go.exe`` / ``bins/awg-go``): a pure-Go AmneziaWG client that
terminates the tunnel in wireguard-go's in-process netstack and exposes a local
SOCKS5 proxy. No TUN device, no admin rights, no sing-box outbound patch needed.

Config sources (first match wins):
  - ``awg_config_file`` setting → path to a standard AmneziaWG ``.conf``
  - engine argument ``config_file=...``
  - an ``awg://`` URI — either base64 of the whole .conf
    (``awg://<base64url>``) or query parameters
    (``awg://?private_key=..&address=..&endpoint=..&jc=..&h1=..``)

Obfuscation parameters (Jc, Jmin, Jmax, S1-S4, H1-H4, I1-I5, …) are forwarded
verbatim to the core's UAPI; keys are converted from base64 (.conf) to hex.
"""
import base64
import logging
import subprocess
import sys
import urllib.parse
from pathlib import Path

from .. import settings as cfg
from .base import Engine

_log = logging.getLogger(__name__)

# .conf keys (lowercased) that carry AmneziaWG obfuscation.
_AWG_OBF_KEYS = (
    "jc", "jmin", "jmax",
    "s1", "s2", "s3", "s4",
    "h1", "h2", "h3", "h4",
    "i1", "i2", "i3", "i4", "i5",
    "headerprotectionkey", "contentpaddingaddition",
    "rekeyaftertime", "rekeytimeout", "rejectaftertime",
    "keepalivetimeout", "maxhandshakeattempts",
    "randomtrailers", "disablecookies",
)

_BINARY_NAMES = ["awg-go.exe", "awg-go"]

# ------------------------------------------------------------------------
# Both Blackout Kit servers, embedded as source so they ship inside the
# PyInstaller binary without data-file packaging rules. _resolve_config
# accepts these names (srv1 / srv2) anywhere a .conf path is expected.
_BUNDLED_SERVERS = {
    "srv1": {"endpoint": "185.215.244.95:39006", "conf": '[Interface]\nPrivateKey = UNBwpTq0F6stv42+0TF5cKzupK5r70C8wDT+AMJ/9Vg=\nAddress = 10.10.10.2/32\nDNS = 1.1.1.1\nJc = 4\nJmin = 50\nJmax = 1000\nS1 = 30\nS2 = 60\nH1 = 12345678\nH2 = 87654321\nH3 = 11223344\nH4 = 44332211\n\n[Peer]\nPublicKey = c8SsKn2DulCR/BrPszJrwB7w+nMVpk9QG9ZQicEunRM=\nEndpoint = 185.215.244.95:39006\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25'},
    "srv2": {"endpoint": "185.208.172.212:39006", "conf": '[Interface]\nPrivateKey = YF/RzsWYLrqAOO7eBSKmDjcHHm+MtrZNeA9eUKmS8nM=\nAddress = 10.10.10.3/32, fd42:42:42::3/128\nDNS = 1.1.1.1, 2606:4700:4700::1111\nMTU = 1280\nJc = 4\nJmin = 50\nJmax = 1000\nS1 = 30\nS2 = 60\nH1 = 12345678\nH2 = 87654321\nH3 = 11223344\nH4 = 44332211\n\n[Peer]\nPublicKey = gbQ0+EbwPQFkgTMJEyq25RwnSh87HJKpIPz5A6gUzwE=\nEndpoint = 185.208.172.212:39006\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25'},
}


def _bundled_conf_path(config_dir: Path, name: str) -> Path:
    """Writes the bundled preset ``name`` to disk and returns its path."""
    out = config_dir / ("awg-%s.conf" % name)
    out.write_text(_BUNDLED_SERVERS[name]["conf"] + "\n", encoding="utf-8")
    return out


def _parse_awg_conf(path: Path) -> dict:
    """Parse an AmneziaWG .conf file into a flat ``section.key`` dict."""
    text = path.read_text(encoding="utf-8", errors="replace")
    section = ""
    fields: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            fields[f"{section}.{key.strip().lower()}"] = value.strip()
    return fields


def _conf_summary(fields: dict) -> str:
    """Short human summary used in log lines."""
    endpoint = fields.get("peer.endpoint", "?")
    obf = [k for k in _AWG_OBF_KEYS if f"interface.{k}" in fields]
    obf_txt = ", ".join(obf) if obf else "none (plain WireGuard)"
    return f"endpoint={endpoint} obfuscation=[{obf_txt}]"


def _conf_from_uri(uri: str) -> str:
    """Materialize an ``awg://`` URI into .conf text."""
    body = uri[len("awg://"):]
    if body.startswith("?"):
        q = urllib.parse.parse_qs(body[1:])
        flat = {k.lower(): v[0] for k, v in q.items() if v}

        def get(*names, default=""):
            for n in names:
                if n in flat:
                    return flat[n]
            return default

        lines = ["[Interface]"]
        for key, qname in (("PrivateKey", "private_key"), ("Address", "address"),
                           ("DNS", "dns"), ("MTU", "mtu")):
            val = get(qname)
            if val:
                lines.append(f"{key} = {val}")
        for obf in _AWG_OBF_KEYS:
            if obf in flat:
                canonical = {
                    "jc": "Jc", "jmin": "Jmin", "jmax": "Jmax",
                    "s1": "S1", "s2": "S2", "s3": "S3", "s4": "S4",
                    "h1": "H1", "h2": "H2", "h3": "H3", "h4": "H4",
                    "i1": "I1", "i2": "I2", "i3": "I3", "i4": "I4", "i5": "I5",
                    "headerprotectionkey": "HeaderProtectionKey",
                    "contentpaddingaddition": "ContentPaddingAddition",
                    "rekeyaftertime": "RekeyAfterTime",
                    "rekeytimeout": "RekeyTimeout",
                    "rejectaftertime": "RejectAfterTime",
                    "keepalivetimeout": "KeepaliveTimeout",
                    "maxhandshakeattempts": "MaxHandshakeAttempts",
                    "randomtrailers": "RandomTrailers",
                    "disablecookies": "DisableCookies",
                }.get(obf, obf.upper())
                lines.append(f"{canonical} = {flat[obf]}")
        lines.append("")
        lines.append("[Peer]")
        for key, qname in (("PublicKey", "public_key"), ("PresharedKey", "preshared_key"),
                           ("Endpoint", "endpoint"), ("AllowedIPs", "allowed_ips"),
                           ("PersistentKeepalive", "keepalive")):
            val = get(qname)
            if val:
                lines.append(f"{key} = {val}")
        return "\n".join(lines) + "\n"

    # base64 payload: urlsafe or standard, padding optional
    padded = body + "=" * (-len(body) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode())
    except Exception:
        raw = base64.b64decode(padded.encode())
    return raw.decode("utf-8", errors="replace")


class AmneziaWGEngine(Engine):
    name = "awg"
    description = "AmneziaWG — native userspace obfuscated WireGuard with local SOCKS5"
    protocol = "awg"

    def __init__(self, config_file: str = "", socks_port: int | None = None):
        super().__init__()
        s = cfg.load()
        self.config_file = config_file or s.get("awg_config_file", "")
        if not self.config_file:
            # Library fallback: an awg:// URI saved via `blackout config add`
            # is a first-class config, same as on mobile. The explicit setting
            # still wins when present.
            try:
                from ..config.manager import select_proxy_config

                library_pick = select_proxy_config(("awg",))
                if library_pick is not None and library_pick.raw_uri.startswith("awg://"):
                    self.config_file = library_pick.raw_uri
            except Exception:
                pass
        # Dedicated ports (awg_socks_port / awg_http_port): the awg core must not
        # fight an XRay/v2rayN instance already bound to xray_socks_port (10808).
        self.socks_port = socks_port or s.get("awg_socks_port", 11080)
        self.http_port = s.get("awg_http_port", 11081)
        self._health_check_addr = ("127.0.0.1", self.socks_port)
        self._log_path = self._config_dir / "awg-core.log"
        self._ready_path = self._config_dir / "awg-ready.txt"
        self.proxy_config = None
        self.requested_protocol = None

    # ------------------------------------------------------------ config
    def _resolve_config(self) -> Path | None:
        src = (self.config_file or "").strip()
        if not src:
            self._log.error(
                "AmneziaWG needs a config. Both bundled servers are available:"
                "  blackout settings set awg_config_file srv1   # 185.215.244.95:39006"
                "  blackout settings set awg_config_file srv2   # 185.208.172.212:39006"
                "or set a full .conf path or an awg:// URI."
            )
            return None
        # Bundled presets: "srv1" / "srv2" (tolerate prefixes/suffixes such as
        # "awg-srv1", "SRV2", "srv1.conf") resolve to the embedded configs.
        probe = src.lower().removesuffix(".conf")
        for name in _BUNDLED_SERVERS:
            if probe == name or probe.endswith("-" + name) or probe.endswith("_" + name):
                endpoint = _BUNDLED_SERVERS[name]["endpoint"]
                self._log.info("Using bundled server %s (%s)", name, endpoint)
                return _bundled_conf_path(self._config_dir, name)
        if src.startswith("awg://"):
            try:
                text = _conf_from_uri(src)
            except Exception as exc:
                self._log.error("Could not decode awg:// URI: %s", exc)
                return None
            out = self._config_dir / "awg.conf"
            out.write_text(text, encoding="utf-8")
            return out
        path = Path(src).expanduser()
        if not path.is_file():
            self._log.error("AmneziaWG config not found: %s", path)
            return None
        return path

    def _log_tail(self, limit: int = 1200) -> str:
        try:
            return self._log_path.read_text(encoding="utf-8", errors="replace")[-limit:]
        except OSError:
            return "(no core output captured)"

    # ------------------------------------------------------------ lifecycle
    def start(self) -> bool:
        binary = self.find_binary(_BINARY_NAMES)
        if binary is None:
            return False

        conf = self._resolve_config()
        if conf is None:
            return False

        try:
            summary = _conf_summary(_parse_awg_conf(conf))
        except OSError as exc:
            self._log.error("Could not read AmneziaWG config: %s", exc)
            return False

        if not self.check_port_free(self.socks_port):
            return False
        if self.http_port and not self.check_port_free(self.http_port):
            return False

        command = self.binary_command(
            binary,
            "--config", str(conf),
            "--socks", f"127.0.0.1:{self.socks_port}",
            "--http", f"127.0.0.1:{self.http_port}",
            "--ready-file", str(self._ready_path),
        )

        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
        try:
            log_file = open(self._log_path, "w", encoding="utf-8", errors="replace")
            self._process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                start_new_session=sys.platform != "win32",
                creationflags=creationflags,
            )
        except OSError as exc:
            self._log.error("Could not start AmneziaWG core: %s", exc)
            return False

        if not self.wait_for_port(self.socks_port, timeout=12.0):
            code = self._process.poll() if self._process else None
            self._log.error(
                "AmneziaWG core did not open SOCKS port %d (exit=%s). Core output:\n%s",
                self.socks_port, code, self._log_tail(),
            )
            self.stop()
            return False

        if self.http_port and not self.wait_for_port(self.http_port, timeout=5.0):
            self._log.error(
                "AmneziaWG core did not open HTTP port %d. Core output:\n%s",
                self.http_port, self._log_tail(),
            )
            self.stop()
            return False

        if self._process.poll() is not None:
            self._log.error(
                "AmneziaWG core exited immediately (code=%s). Core output:\n%s",
                self._process.returncode, self._log_tail(),
            )
            self.stop()
            return False

        self._log.info(
            "AmneziaWG core up — SOCKS5 127.0.0.1:%d, HTTP 127.0.0.1:%d (%s)",
            self.socks_port, self.http_port, summary,
        )
        return True
