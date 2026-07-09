"""
Blackout Kit - Country profiles for native multi-country support.

Five primary countries with censorship levels, recommended engine orders,
bypass DNS servers, blocked test URLs, and usage notes.
"""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class CountryProfile:
    code: str               # "IR", "US", "GB", "CN", "IQ"
    name: str               # "Iran", "United States", ...
    censorship_level: str   # "extreme" | "high" | "medium" | "low" | "minimal"
    engine_order: list[str] # recommended engine priority for emergency/connect
    bypass_dns: list[tuple[str, str]]  # [(label, ip), ...]
    test_urls: list[str]    # URLs typically blocked there — to verify bypass works
    psiphon_country: str    # preferred Psiphon egress country code
    notes: str              # one-line censorship description


# ──────────────────────────── Profiles ───────────────────────────

_PROFILES: list[CountryProfile] = [
    CountryProfile(
        code             = "IR",
        name             = "Iran",
        censorship_level = "high",
        engine_order     = ["sni", "warp", "psiphon", "gdpi"],
        bypass_dns       = [
            ("Shecan",    "185.51.200.2"),
            ("Electro",   "78.157.42.100"),
            ("403online", "10.202.10.202"),
        ],
        test_urls        = ["twitter.com", "instagram.com", "youtube.com"],
        psiphon_country  = "DE",
            notes            = "SNI spoofing effective; ISP-level DPI — use blackout connect --iran for ArvanCloud SNI + TLS fragment evasion",
    ),
    CountryProfile(
        code             = "US",
        name             = "United States",
        censorship_level = "minimal",
        engine_order     = ["warp", "psiphon"],
        bypass_dns       = [
            ("Cloudflare", "1.1.1.1"),
            ("Quad9",      "9.9.9.9"),
        ],
        test_urls        = [],
        psiphon_country  = "US",
        notes            = "ISP throttling and privacy concerns only",
    ),
    CountryProfile(
        code             = "GB",
        name             = "United Kingdom",
        censorship_level = "low",
        engine_order     = ["gdpi", "warp", "psiphon"],
        bypass_dns       = [
            ("Cloudflare", "1.1.1.1"),
            ("Google",     "8.8.8.8"),
        ],
        test_urls        = ["thepiratebay.org", "yts.mx"],
        psiphon_country  = "NL",
        notes            = "Ofcom ISP content filters on certain sites",
    ),
    CountryProfile(
        code             = "CN",
        name             = "China",
        censorship_level = "extreme",
        engine_order     = ["xray", "psiphon", "warp", "tun"],
        bypass_dns       = [
            ("Alibaba",  "223.5.5.5"),
            ("Tencent",  "119.29.29.29"),
            ("114 DNS",  "114.114.114.114"),
        ],
        test_urls        = ["google.com", "youtube.com", "twitter.com"],
        psiphon_country  = "US",
        notes            = "Great Firewall blocks IPs + SNI — use Xray/V2Ray",
    ),
    CountryProfile(
        code             = "IQ",
        name             = "Iraq",
        censorship_level = "medium",
        engine_order     = ["sni", "warp", "gdpi", "psiphon"],
        bypass_dns       = [
            ("Cloudflare", "1.1.1.1"),
            ("Google",     "8.8.8.8"),
        ],
        test_urls        = ["twitter.com", "facebook.com"],
        psiphon_country  = "DE",
        notes            = "ISP DPI similar to Iran; social media blocks",
    ),
]

# Fast lookup by code
_BY_CODE: dict[str, CountryProfile] = {p.code: p for p in _PROFILES}

# Map of country name strings (as returned by ip-api.com) to ISO codes
_COUNTRY_NAME_MAP: dict[str, str] = {
    "Iran":                "IR",
    "Iran, Islamic Republic of": "IR",
    "United States":       "US",
    "United Kingdom":      "GB",
    "China":               "CN",
    "Iraq":                "IQ",
}


# ──────────────────────────── Public API ─────────────────────────

def get_profile(code: str) -> CountryProfile | None:
    """Get a country profile by ISO code. Case-insensitive ('ir', 'IR' both work)."""
    return _BY_CODE.get(code.upper()) if code else None


def get_all_profiles() -> list[CountryProfile]:
    """Return all 5 country profiles."""
    return list(_PROFILES)


def detect_country(isp_info) -> CountryProfile | None:
    """
    Map an IspInfo object (from network_switcher.get_isp_info) to a CountryProfile.
    Returns None if the country is not one of the 5 primary profiles.
    """
    if isp_info is None:
        return None
    country_str = isp_info.country or ""
    code = _COUNTRY_NAME_MAP.get(country_str)
    if code:
        return _BY_CODE.get(code)
    return None
