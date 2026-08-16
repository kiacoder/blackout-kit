from types import SimpleNamespace

from blackoutkit.routing import recommend_routes


def _profile(order):
    return SimpleNamespace(engine_order=order)


def test_explicit_preference_outranks_country_order_when_ready():
    candidates = recommend_routes(
        {"selected_engine": "xray", "engine_order": ["sni", "xray"]},
        country_profile=_profile(["sni", "xray"]),
        installed={"xray": True, "sni-spoofing": True},
        protocols={"vless"},
        platform="win32",
    )

    assert candidates[0].engine == "xray"
    assert candidates[0].ready is True


def test_missing_requirements_mark_candidate_blocked():
    candidates = recommend_routes(
        {"selected_engine": "auto", "engine_order": ["xray"]},
        installed={"sni-spoofing": False},
        protocols=set(),
        platform="win32",
    )

    xray = next(candidate for candidate in candidates if candidate.engine == "xray")
    assert xray.ready is False
    assert "sni-spoofing missing" in xray.blockers
    assert "No compatible saved proxy config" not in xray.blockers


def test_vpn_candidate_requires_configured_settings():
    candidates = recommend_routes(
        {"selected_engine": "auto", "engine_order": ["openvpn"]},
        installed={"openvpn": True},
        platform="win32",
    )

    openvpn = next(candidate for candidate in candidates if candidate.engine == "openvpn")
    assert openvpn.ready is False
    assert "openvpn config not configured" in openvpn.blockers


def test_sni_stack_accepts_the_actual_core_dll_registration():
    candidates = recommend_routes(
        {"selected_engine": "auto", "engine_order": ["sni"]},
        installed={"mhrv": True},
        protocols=set(),
        platform="win32",
    )

    sni = next(candidate for candidate in candidates if candidate.engine == "sni")
    assert sni.ready is True
    assert "sni-spoofing missing" not in sni.blockers
    assert "xray missing" not in sni.blockers


def test_linux_filters_to_supported_engines_and_requires_runner():
    candidates = recommend_routes(
        {"selected_engine": "gdpi", "engine_order": ["gdpi", "xray", "tun"]},
        installed={"linux_engine": False},
        protocols={"vless"},
        platform="linux",
    )

    assert {candidate.engine for candidate in candidates}.issubset({"xray", "tun", "hysteria2", "tuic"})
    assert all("Linux runner missing" in candidate.blockers for candidate in candidates)


def test_linux_order_never_adds_windows_engines():
    candidates = recommend_routes(
        {"selected_engine": "auto", "engine_order": []},
        installed={"linux_engine": True},
        protocols={"vless"},
        platform="linux",
    )

    assert {candidate.engine for candidate in candidates} == {"xray", "tun", "hysteria2", "tuic"}


def test_reality_vless_is_compatible_with_linux_xray_and_tun():
    candidates = recommend_routes(
        {"selected_engine": "auto", "engine_order": ["xray", "tun"]},
        installed={"linux_engine": True},
        protocols={"vless"},
        platform="linux",
    )

    ready = {candidate.engine for candidate in candidates if candidate.ready}
    assert {"xray", "tun"}.issubset(ready)


def test_stability_evidence_prefers_stable_candidate():
    candidates = recommend_routes(
        {"selected_engine": "auto", "engine_order": ["xray", "hysteria2"]},
        installed={"mhrv": True},
        protocols={"vless", "hysteria2"},
        stability_scores={
            "xray": {"stable": False, "avg_ms": 900, "loss_pct": 40, "trend": "degrading"},
            "hysteria2": {"stable": True, "avg_ms": 80, "loss_pct": 0, "trend": "stable"},
        },
        platform="win32",
    )

    assert candidates[0].engine == "hysteria2"
    assert "80ms average" in candidates[0].evidence
