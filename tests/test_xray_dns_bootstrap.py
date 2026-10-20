"""Regression: the DoH chain must not depend on the local resolver.

On filtered networks the local resolver (router -> ISP DNS) returns poisoned
or empty answers for the DoH hostnames themselves, which killed the whole DNS
chain: `https+local://cloudflare-dns.com` needs to resolve `cloudflare-dns.com`
locally BEFORE any DoH query happens. The chain now starts with IP-literal DoH
endpoints, which need no name resolution.
"""
import sys

sys.path.insert(0, r"C:\Users\kiacoder\blackout-kit")

from blackoutkit import settings as settings_module
from blackoutkit.config_check import _free_port
from blackoutkit.engines.xray import XRayEngine


def _build_dns_config(monkeypatch, doh: bool):
    monkeypatch.setattr(
        settings_module, "load",
        lambda: {**settings_module.DEFAULTS, "xray_doh_dns": doh},
    )
    engine = XRayEngine(
        proxy_config=_FakeConfig(),
        socks_port=_free_port(),
        http_port=_free_port(),
    )
    try:
        return engine.generate_config().get("dns")
    finally:
        engine.stop()


class _FakeConfig:
    address = "203.0.113.10"
    port = 443
    name = "fake"
    protocol = "vless"
    security = "tls"
    sni = "example.com"
    uuid = "00000000-0000-0000-0000-000000000001"
    host = ""
    path = "/"
    alpn = ""
    transport = "tcp"
    public_key = ""
    short_id = ""
    spider_x = ""
    flow = ""
    fp = "chrome"
    password = ""
    service_name = ""
    xhttp_mode = ""

    def is_reality(self):
        return False

    def reality_validation_error(self):
        return None

    def get_current_mode(self):
        return "AUTO"

    def linux_cached_endpoint(self):
        return None


def test_doh_servers_are_ip_literals(monkeypatch):
    """No DoH entry may require resolving a hostname through the local resolver."""
    dns = _build_dns_config(monkeypatch, doh=True)
    assert dns is not None
    for server in dns["servers"]:
        if server.startswith("https://"):
            host = server.split("//", 1)[1].split("/", 1)[0]
            assert host.replace(".", "").isdigit(), (
                f"DoH endpoint {host!r} must be an IP literal — a hostname here "
                "depends on the (on filtered networks, poisoned) local resolver"
            )
    assert not any(server.startswith("https+local://") for server in dns["servers"])


def test_no_dns_object_when_doh_disabled(monkeypatch):
    assert _build_dns_config(monkeypatch, doh=False) is None
