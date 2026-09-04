"""
Blackout Kit - Country profiles for native multi-country support.

Built-in profiles with censorship levels, recommended engine orders,
bypass DNS servers, blocked test URLs, and usage notes.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CountryProfile:
    code: str               # "IR", "RU", "US", "GB", "CN", "IQ", "EU"
    name: str               # "Iran", "United States", ...
    censorship_level: str   # "extreme" | "high" | "medium" | "low" | "minimal"
    engine_order: list[str] # recommended engine priority for emergency/connect
    bypass_dns: list[tuple[str, str]]  # [(label, ip), ...]
    test_urls: list[str]    # URLs typically blocked there — to verify bypass works
    psiphon_country: str    # preferred Psiphon egress country code
    notes: str              # one-line censorship description
    bypass_domains: list[str] = field(default_factory=list)  # domains to route direct (not via proxy)
    direct_dns: str = ""    # domestic DNS server for direct-routed domains


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
        code             = "RU",
        name             = "Russia",
        censorship_level = "high",
        engine_order     = ["xray", "hysteria2", "tuic", "awg", "warp", "gdpi", "tun", "psiphon"],
        bypass_dns       = [
            ("Cloudflare", "1.1.1.1"),
            ("Quad9",      "9.9.9.9"),
            ("AdGuard",    "94.140.14.14"),
        ],
        test_urls        = ["instagram.com", "facebook.com", "twitter.com"],
        psiphon_country  = "DE",
        notes            = "Dynamic filtering and throttling environment; start with XRay or QUIC-capable paths and treat DNS as guidance only",
        bypass_domains   = ["domain:ru", "domain:yandex.ru", "domain:vk.com", "domain:ozon.ru", "domain:mail.ru", "domain:avito.ru"],
        direct_dns       = "77.88.8.8",
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
    CountryProfile(
        code             = "EU",
        name             = "Europe (EU)",
        censorship_level = "low",
        engine_order     = ["gdpi", "warp", "wireguard", "psiphon"],
        bypass_dns       = [
            ("Mullvad (Adblock)", "194.242.2.3"),
            ("AdGuard DNS",       "94.140.14.14"),
        ],
        test_urls        = ["thepiratebay.org", "1337x.to"],
        psiphon_country  = "CH",
        notes            = "Strict privacy. Bypasses ISP piracy blocks using GoodbyeDPI + Adblocking DNS.",
    ),
]

# Fast lookup by code
_BY_CODE: dict[str, CountryProfile] = {p.code: p for p in _PROFILES}

# Map country names and fallback ISO codes from ISP lookup APIs to built-in profile codes.
_COUNTRY_NAME_MAP: dict[str, str] = {
    "Iran":                "IR",
    "Iran, Islamic Republic of": "IR",
    "IR":                  "IR",
    "Russia":              "RU",
    "Russian Federation":  "RU",
    "RU":                  "RU",
    "United States":       "US",
    "US":                  "US",
    "United Kingdom":      "GB",
    "GB":                  "GB",
    "China":               "CN",
    "CN":                  "CN",
    "Iraq":                "IQ",
    "IQ":                  "IQ",
    "Portugal":            "EU",
    "PT":                  "EU",
    "Germany":             "EU",
    "DE":                  "EU",
    "France":              "EU",
    "FR":                  "EU",
    "Spain":               "EU",
    "ES":                  "EU",
    "Italy":               "EU",
    "IT":                  "EU",
    "Netherlands":         "EU",
    "NL":                  "EU",
    "Sweden":              "EU",
    "SE":                  "EU",
}


# ──────────────────────────── Public API ─────────────────────────

def get_profile(code: str) -> CountryProfile | None:
    """Get a country profile by ISO code. Case-insensitive ('ir', 'IR' both work)."""
    return _BY_CODE.get(code.upper()) if code else None


def get_all_profiles() -> list[CountryProfile]:
    """Return all configured country profiles."""
    return list(_PROFILES)


# ──────────────────────────── Country-aware routing helpers ──────

_IRAN_BYPASS_DOMAINS = [
    "domain:ir",
    "domain:aparat.com",
    "domain:digikala.com",
    "domain:snapp.ir",
    "domain:divar.ir",
]
_IRAN_DIRECT_DNS = "223.5.5.5"


def bypass_domains_for(code: str | None) -> list[str]:
    """Return the direct-bypass domain list for a country code, or Iran defaults."""
    if not code:
        return list(_IRAN_BYPASS_DOMAINS)
    profile = get_profile(code)
    if profile and profile.bypass_domains:
        return list(profile.bypass_domains)
    return list(_IRAN_BYPASS_DOMAINS)


def direct_dns_for(code: str | None) -> str:
    """Return the domestic direct DNS for a country code, or a global default."""
    if not code:
        return _IRAN_DIRECT_DNS
    profile = get_profile(code)
    if profile and profile.direct_dns:
        return profile.direct_dns
    return _IRAN_DIRECT_DNS


def detect_country(isp_info) -> CountryProfile | None:
    """
    Map an IspInfo object (from network_switcher.get_isp_info) to a CountryProfile.
    Returns None if the country is not one of the built-in profiles.
    """
    if isp_info is None:
        return None
    for value in (getattr(isp_info, "country_code", ""), isp_info.country or ""):
        code = _COUNTRY_NAME_MAP.get(value or "")
        if code:
            return _BY_CODE.get(code)
    return None
