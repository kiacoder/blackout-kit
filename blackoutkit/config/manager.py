"""
Blackout Kit - V2Ray config manager.
Parses vless://, trojan://, and vmess:// URIs.
Loads/saves configs and imports from subscription URLs.
"""
import base64
import json
import os
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from .. import DATA_DIR, vault
CONFIGS_FILE = DATA_DIR / "configs.txt"


@dataclass
class ProxyConfig:
    protocol:  str              # trojan / vless / vmess
    address:   str              # server address
    port:      int              # server port
    password:  str  = ""        # Trojan password
    uuid:      str  = ""        # VLESS / VMess UUID
    sni:       str  = ""        # TLS SNI / serverName
    host:      str  = ""        # HTTP Host header
    path:      str  = "/"       # WebSocket path
    alpn:      str  = ""        # TLS ALPN
    fp:        str  = "chrome"  # TLS fingerprint
    transport: str  = "ws"      # ws / tcp / grpc / xhttp
    security:  str  = "tls"     # tls / reality / none
    public_key: str = ""        # REALITY server public key
    short_id:  str  = ""        # REALITY short ID
    spider_x:  str  = ""        # REALITY spider path
    flow:      str  = ""        # VLESS flow (e.g. xtls-rprx-vision)
    service_name: str = ""      # gRPC service name
    xhttp_mode: str = ""        # XHTTP mode: auto / packet-up / stream-up
    insecure:  bool = True      # allowInsecure
    name:      str  = ""        # Config label (#fragment)
    raw_uri:   str  = ""        # Original URI string

    def is_sni_compatible(self) -> bool:
        """True when the config routes through the local SNI spoofer."""
        return self.address in ("127.0.0.1", "0.0.0.0") and self.port == 40443

    def display_name(self) -> str:
        return self.name or f"{self.protocol}://{self.address}:{self.port}"

    def is_reality(self) -> bool:
        return self.protocol == "vless" and self.security.lower() == "reality"

    def reality_validation_error(self) -> str | None:
        if not self.is_reality():
            return None
        if not self.public_key:
            return "REALITY config is missing the server public key (pbk)."
        if not self.sni:
            return "REALITY config is missing the server name (sni)."
        if self.transport not in {"tcp", "ws", "grpc", "xhttp", "splithttp"}:
            return f"REALITY transport '{self.transport}' is unsupported; use tcp, ws, grpc, or xhttp."
        return None

    def transport_label(self) -> str:
        return "REALITY" if self.is_reality() else self.transport.upper()


# ─────────────────────────── Parsing ────────────────────────────

def parse_v2ray_uri(uri: str) -> "ProxyConfig | None":
    """Parse a V2Ray share URI into a ProxyConfig."""
    uri = uri.strip()
    if not uri:
        return None

    try:
        if uri.startswith(("vless://", "trojan://", "hysteria2://", "tuic://")):
            return _parse_vless_trojan(uri)
        if uri.startswith("vmess://"):
            return _parse_vmess(uri)
    except Exception:
        return None
    return None


def _parse_vless_trojan(uri: str) -> ProxyConfig:
    proto, rest = uri.split("://", 1)

    # Fragment (name)
    name = ""
    if "#" in rest:
        rest, name_enc = rest.rsplit("#", 1)
        name = urllib.parse.unquote(name_enc)

    # credential @ host:port ? params
    at = rest.rfind("@")
    if at < 0:
        raise ValueError("Missing '@' delimiter in URI")
    credential = urllib.parse.unquote(rest[:at])
    host_part  = rest[at + 1:]

    if "?" in host_part:
        host_port_str, params_str = host_part.split("?", 1)
    else:
        host_port_str, params_str = host_part, ""

    host_port_str = host_port_str.rstrip("/")

    # IPv6 support
    if host_port_str.startswith("["):
        bracket_end = host_port_str.index("]")
        host = host_port_str[1:bracket_end]
        try:
            port = int(host_port_str[bracket_end + 2:])
        except (ValueError, IndexError) as e:
            raise ValueError(f"Invalid IPv6 port: {e}")
    else:
        if ":" not in host_port_str:
            raise ValueError("Missing ':' port delimiter in host:port")
        host, port_str = host_port_str.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError as e:
            raise ValueError(f"Invalid port number: {port_str} ({e})")

    p = urllib.parse.parse_qs(params_str, keep_blank_values=True)

    def q(key, default=""):
        vals = p.get(key, [default])
        return urllib.parse.unquote(vals[0]) if vals else default

    insecure_val = q("insecure", "0")
    insecure = insecure_val.lower() in ("1", "true", "yes")

    password = ""
    uuid = ""
    if proto in ("trojan", "hysteria2"):
        password = credential
    elif proto == "vless":
        uuid = credential
    elif proto == "tuic":
        if ":" in credential:
            uuid, password = credential.split(":", 1)
        else:
            uuid = credential

    transport = q("type", "ws").lower()
    if transport == "splithttp":
        transport = "xhttp"

    return ProxyConfig(
        protocol  = proto,
        address   = host,
        port      = port,
        password  = password,
        uuid      = uuid,
        sni       = q("sni"),
        host      = q("host"),
        path      = q("path", "/"),
        alpn      = q("alpn"),
        fp        = q("fp", "chrome"),
        transport = transport,
        security  = q("security", "tls").lower(),
        public_key = q("pbk") or q("publicKey"),
        short_id   = q("sid") or q("shortId"),
        spider_x   = q("spx") or q("spiderX"),
        flow       = q("flow"),
        service_name = q("serviceName"),
        xhttp_mode = q("mode"),
        insecure  = insecure,
        name      = name,
        raw_uri   = uri,
    )


def _parse_vmess(uri: str) -> ProxyConfig:
    b64 = uri[len("vmess://"):]
    padding = 4 - len(b64) % 4
    b64 += "=" * (padding % 4)
    data = json.loads(base64.b64decode(b64).decode("utf-8"))

    return ProxyConfig(
        protocol  = "vmess",
        address   = data.get("add", ""),
        port      = int(data.get("port", 443)),
        uuid      = data.get("id", ""),
        sni       = data.get("sni", data.get("host", "")),
        host      = data.get("host", ""),
        path      = data.get("path", "/"),
        transport = data.get("net", "ws"),
        name      = data.get("ps", ""),
        raw_uri   = uri,
    )


# ─────────────────────────── Load / Save ────────────────────────

def _parse_config_text(text: str) -> list[ProxyConfig]:
    configs = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            config = parse_v2ray_uri(line)
            if config:
                configs.append(config)
    return configs


def load_configs(path: Path | None = None) -> list[ProxyConfig]:
    p = path or CONFIGS_FILE
    if path is None and CONFIGS_FILE == vault.CONFIGS_FILE and vault.config_vault_active():
        try:
            return _parse_config_text(vault.read_config_bytes().decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, vault.VaultError):
            return []
    if not p.exists():
        return []
    try:
        return _parse_config_text(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return []


def save_configs(configs: list[ProxyConfig], path: Path | None = None):
    text = "\n".join(config.raw_uri for config in configs if config.raw_uri)
    if path is None and CONFIGS_FILE == vault.CONFIGS_FILE and vault.config_vault_active():
        vault.write_config_bytes(text.encode("utf-8"))
        return
    p = path or CONFIGS_FILE
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        import tempfile
        import os
        fd, tmp_path = tempfile.mkstemp(dir=p.parent, text=True)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write(text)
            os.replace(tmp_path, str(p))
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    except (OSError, IOError) as e:
        import logging
        logging.error(f"Failed to save proxy configs to {p}: {e}")
        raise


def select_proxy_config(protocols: tuple[str, ...]) -> ProxyConfig | None:
    """
    Select a proxy config compatible with the given protocols, using config rotation.

    Reads BLACKOUT_CONFIG_OFFSET to cycle through compatible configs.
    This enables smart config rotation: when an IP gets blocked, the daemon
    increments the offset and the next engine instance picks a different config.
    """
    try:
        offset = int(os.environ.get("BLACKOUT_CONFIG_OFFSET", "0"))
    except ValueError:
        offset = 0
    configs = load_configs()
    compatible = [c for c in configs if c.protocol in protocols]
    if not compatible:
        return None
    return compatible[offset % len(compatible)]


def add_config(uri: str) -> ProxyConfig:
    c = parse_v2ray_uri(uri)
    if not c:
        raise ValueError("Invalid V2Ray URI")
    existing = load_configs()
    # Avoid duplicates by raw_uri
    if not any(e.raw_uri == c.raw_uri for e in existing):
        existing.append(c)
        save_configs(existing)
    return c


def remove_config(index: int):
    configs = load_configs()
    if not 0 <= index < len(configs):
        raise IndexError(f"Config index {index} out of range")
    del configs[index]
    save_configs(configs)


# ─────────────────────────── Import ─────────────────────────────

def import_from_subscription(url: str) -> list[ProxyConfig]:
    """
    Fetch a V2Ray subscription URL and parse all configs.
    Subscription content may be plain-text or base64-encoded.
    """
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "v2rayN/6.0"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        raw = resp.read()

    # Attempt base64 decode (standard subscription format)
    try:
        decoded = base64.b64decode(raw + b"==").decode("utf-8", errors="ignore")
    except Exception:
        decoded = raw.decode("utf-8", errors="ignore")

    configs = []
    for line in decoded.splitlines():
        c = parse_v2ray_uri(line.strip())
        if c:
            configs.append(c)
    return configs


def import_and_merge(url: str) -> tuple[int, int]:
    """
    Import configs from URL and merge with existing.
    Returns (new_count, total_count).
    """
    new = import_from_subscription(url)
    existing = load_configs()
    existing_uris = {c.raw_uri for c in existing}
    added = [c for c in new if c.raw_uri not in existing_uris]
    merged = existing + added
    save_configs(merged)
    return len(added), len(merged)


# ─────────────────────────── Export/Import Setup ──────────────────────────

def serialize_setup() -> dict:
    """Pack all configs + exportable settings into a portable dict."""
    from .. import settings as cfg

    configs = load_configs()
    current_settings = cfg.load()

    exportable_keys = {
        "selected_engine",
        "security_mode",
        "xray_fingerprint",
        "xray_mux_enabled",
        "gdpi_backend",
        "xray_doh_dns",
    }

    filtered_settings = {
        k: v for k, v in current_settings.items()
        if k in exportable_keys
    }

    return {
        "configs": [c.raw_uri for c in configs if c.raw_uri],
        "settings": filtered_settings,
    }


def deserialize_setup(data: dict) -> tuple[list[ProxyConfig], dict]:
    """Unpack a setup dict and return (configs, settings)."""
    if not isinstance(data, dict):
        raise ValueError("Setup data must be a dict")

    configs_raw = data.get("configs", [])
    if not isinstance(configs_raw, list):
        raise ValueError("'configs' must be a list of URIs")

    configs = []
    for uri in configs_raw:
        c = parse_v2ray_uri(uri)
        if c:
            configs.append(c)

    settings_data = data.get("settings", {})
    if not isinstance(settings_data, dict):
        raise ValueError("'settings' must be a dict")

    return configs, settings_data
