"""Tests for country-aware routing/domain heuristics."""
from blackoutkit import country_profiles as cp


def test_ru_profile_has_russian_bypass_domains():
    profile = cp.get_profile("RU")
    assert profile is not None
    assert "domain:yandex.ru" in profile.bypass_domains
    assert "domain:vk.com" in profile.bypass_domains
    assert "domain:ozon.ru" in profile.bypass_domains
    assert "domain:ru" in profile.bypass_domains


def test_ru_profile_has_russian_direct_dns():
    profile = cp.get_profile("RU")
    assert profile is not None
    assert profile.direct_dns == "77.88.8.8"


def test_iran_profile_has_no_bypass_domains_field():
    profile = cp.get_profile("IR")
    assert profile is not None
    assert profile.bypass_domains == []


def test_bypass_domains_for_ru_returns_russian_domains():
    domains = cp.bypass_domains_for("RU")
    assert "domain:yandex.ru" in domains
    assert "domain:vk.com" in domains
    assert "domain:ir" not in domains


def test_bypass_domains_for_ir_returns_iranian_defaults():
    domains = cp.bypass_domains_for("IR")
    assert "domain:ir" in domains
    assert "domain:aparat.com" in domains
    assert "domain:yandex.ru" not in domains


def test_bypass_domains_for_unknown_country_returns_iranian_defaults():
    domains = cp.bypass_domains_for("XX")
    assert "domain:ir" in domains
    assert "domain:yandex.ru" not in domains


def test_bypass_domains_for_none_returns_iranian_defaults():
    domains = cp.bypass_domains_for(None)
    assert "domain:ir" in domains


def test_direct_dns_for_ru_returns_yandex_dns():
    assert cp.direct_dns_for("RU") == "77.88.8.8"


def test_direct_dns_for_ir_returns_default():
    assert cp.direct_dns_for("IR") == "223.5.5.5"


def test_direct_dns_for_unknown_returns_default():
    assert cp.direct_dns_for("XX") == "223.5.5.5"


def test_xray_uses_country_aware_bypass_domains():
    """Verify XRay config generation uses RU domains when country is pinned to RU."""
    from types import SimpleNamespace
    from blackoutkit.engines.xray import XRayEngine

    config_obj = SimpleNamespace(
        protocol="vless",
        address="example.com",
        port=443,
        uuid="test-uuid",
        encryption="none",
        sni="example.com",
        fp="chrome",
        transport="tcp",
        security="tls",
        is_reality=lambda: False,
        reality_validation_error=lambda: None,
        flow="",
        path="/",
        host="",
        service_name="",
        public_key="",
        short_id="",
        spider_x="",
        alpn="",
        insecure=True,
        name="test",
        raw_uri="",
        display_name=lambda: "test",
        transport_label=lambda: "TCP",
        is_sni_compatible=lambda: False,
    )

    import json
    from unittest.mock import patch, MagicMock

    with patch("blackoutkit.settings.load", return_value={
        "xray_fingerprint": "chrome",
        "xray_mux_enabled": False,
        "xray_socks_port": 10808,
        "xray_http_port": 10809,
        "xray_doh_dns": False,
        "xray_split_tunnel": True,
        "country": "RU",
        "xray_fragment": "",
    }), patch("blackoutkit.security.get_current_mode", return_value="speed"), \
         patch("blackoutkit.cert_bypass.should_allow_insecure", return_value=(True, "")), \
         patch("blackoutkit.tools.resolve_doh", return_value=None):
        engine = XRayEngine(proxy_config=config_obj, socks_port=10808, http_port=10809)
        config = engine.generate_config()

    domain_rules = [r for r in config["routing"]["rules"] if r.get("outboundTag") == "direct" and "domain" in r]
    assert domain_rules, "Expected a direct domain bypass rule"
    domains = domain_rules[0]["domain"]
    assert "yandex.ru" in domains
    assert "vk.com" in domains
    # Verify no .ir domains in RU profile (iran-specific domains should not appear)
    assert not any(d.endswith(".ir") or d == "ir" for d in domains)


def test_xray_uses_iranian_domains_when_country_is_ir():
    """Verify XRay config generation uses IR domains when country is pinned to IR."""
    from types import SimpleNamespace
    from blackoutkit.engines.xray import XRayEngine

    config_obj = SimpleNamespace(
        protocol="vless",
        address="example.com",
        port=443,
        uuid="test-uuid",
        encryption="none",
        sni="example.com",
        fp="chrome",
        transport="tcp",
        security="tls",
        is_reality=lambda: False,
        reality_validation_error=lambda: None,
        flow="",
        path="/",
        host="",
        service_name="",
        public_key="",
        short_id="",
        spider_x="",
        alpn="",
        insecure=True,
        name="test",
        raw_uri="",
        display_name=lambda: "test",
        transport_label=lambda: "TCP",
        is_sni_compatible=lambda: False,
    )

    from unittest.mock import patch

    with patch("blackoutkit.settings.load", return_value={
        "xray_fingerprint": "chrome",
        "xray_mux_enabled": False,
        "xray_socks_port": 10808,
        "xray_http_port": 10809,
        "xray_doh_dns": False,
        "xray_split_tunnel": True,
        "country": "IR",
        "xray_fragment": "",
    }), patch("blackoutkit.security.get_current_mode", return_value="speed"), \
         patch("blackoutkit.cert_bypass.should_allow_insecure", return_value=(True, "")), \
         patch("blackoutkit.tools.resolve_doh", return_value=None):
        engine = XRayEngine(proxy_config=config_obj, socks_port=10808, http_port=10809)
        config = engine.generate_config()

    domain_rules = [r for r in config["routing"]["rules"] if r.get("outboundTag") == "direct" and "domain" in r]
    assert domain_rules, "Expected a direct domain bypass rule"
    domains = domain_rules[0]["domain"]
    assert "ir" in domains
    assert "yandex.ru" not in domains
