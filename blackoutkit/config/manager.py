"""
Blackout Kit - V2Ray config manager.
Parses vless://, trojan://, and vmess:// URIs.
Loads/saves configs and imports from subscription URLs.
"""
import base64
import json
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from .. import DATA_DIR
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
    transport: str  = "ws"      # ws / tcp / grpc
    insecure:  bool = True      # allowInsecure
    name:      str  = ""        # Config label (#fragment)
    raw_uri:   str  = ""        # Original URI string

    def is_sni_compatible(self) -> bool:
        """True when the config routes through the local SNI spoofer."""
        return self.address in ("127.0.0.1", "0.0.0.0") and self.port == 40443

    def display_name(self) -> str:
        return self.name or f"{self.protocol}://{self.address}:{self.port}"


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
        port = int(host_port_str[bracket_end + 2:])
    else:
        host, port_str = host_port_str.rsplit(":", 1)
        port = int(port_str)

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
        transport = q("type", "ws"),
        insecure  = insecure,
        name      = name,
        raw_uri   = f"{proto}://{rest}#{name}",
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

def load_configs(path: Path | None = None) -> list[ProxyConfig]:
    p = path or CONFIGS_FILE
    if not p.exists():
        return []
    configs = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            c = parse_v2ray_uri(line)
            if c:
                configs.append(c)
    return configs


def save_configs(configs: list[ProxyConfig], path: Path | None = None):
    p = path or CONFIGS_FILE
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        "\n".join(c.raw_uri for c in configs if c.raw_uri),
        encoding="utf-8",
    )


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
