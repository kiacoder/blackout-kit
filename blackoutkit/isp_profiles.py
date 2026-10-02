"""
Blackout Kit - Iranian ISP sub-profiles.

Schema layer on top of the country profiles: national filtering applies
different DPI pressure per carrier, so the general Iran profile can be
specialized per ISP with pre-tuned engine flags.

HONESTY BOUNDARY (project trust rule): the per-carrier values in this module
are STARTING POINTS derived from the general Iran profile. They are not
field-verified per carrier, and no claim is made that a profile is known to
bypass a specific carrier's filtering. Effectiveness depends on the network,
server IP, and current filtering. Detection matches the ASN reported by the
ISP lookup service; mobile carriers also span multiple ASNs, so a mismatch
is always possible.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SCHEMA_VERSION = 1

_FAKE_SNI_BASELINE = "www.snapp.ir"
_XRAY_FRAGMENT_BASELINE = "10-20,30-40"
_XRAY_FINGERPRINT_BASELINE = "chrome"


@dataclass(frozen=True)
class IspProfile:
    """One carrier-specialized preset, applied as transient overrides only.

    All tunables are plain Blackout Kit setting names so the profile can be
    applied through the same temporary environment-override mechanism as the
    --iran/--russia presets; saved settings are never rewritten.
    """

    code: str                       # "ir-mci"
    display_name: str               # "MCI (Hamrahe Aval)"
    carrier: str                    # "MCI"
    country_code: str               # always "IR" today
    access_type: str                # "mobile" | "fixed"
    asn_hints: tuple[str, ...]      # ASN prefixes reported by the ISP lookup
    engine_order: tuple[str, ...]   # preferred engine order for this carrier
    security_mode: str              # "legend" | "private" | "speed"
    fake_sni: str                   # sni_fake_sni baseline for this carrier
    xray_fragment: str              # xray_fragment baseline ("": disabled)
    xray_fingerprint: str           # xray_fingerprint baseline
    notes: str = ""
    extra_overrides: dict[str, Any] = field(default_factory=dict)

    def overrides(self) -> dict[str, Any]:
        """Settings-keyed overrides this profile applies transiently."""
        values: dict[str, Any] = {
            "country": self.country_code,
            "security_mode": self.security_mode,
            "sni_fake_sni": self.fake_sni,
            "xray_fragment": self.xray_fragment,
            "xray_fingerprint": self.xray_fingerprint,
        }
        for key, value in self.extra_overrides.items():
            values[key] = value
        return values

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "code": self.code,
            "display_name": self.display_name,
            "carrier": self.carrier,
            "country_code": self.country_code,
            "access_type": self.access_type,
            "asn_hints": list(self.asn_hints),
            "engine_order": list(self.engine_order),
            "security_mode": self.security_mode,
            "overrides": dict(self.overrides()),
            "notes": self.notes,
        }


_IR_MOBILE_ENGINES = ("legend", "sni", "xray", "tor", "gdpi")
_IR_FIXED_ENGINES = ("legend", "xray", "sni", "gdpi", "tor")

_IR_Tuning_NOTE = (
    "Starting values derived from the general Iran profile; not yet "
    "field-verified on this carrier."
)


def _profile(
    code: str,
    display_name: str,
    carrier: str,
    access_type: str,
    asn_hints: tuple[str, ...],
    *,
    engine_order: tuple[str, ...] = _IR_MOBILE_ENGINES,
    security_mode: str = "legend",
    fake_sni: str = _FAKE_SNI_BASELINE,
    xray_fragment: str = _XRAY_FRAGMENT_BASELINE,
    xray_fingerprint: str = _XRAY_FINGERPRINT_BASELINE,
    notes: str = _IR_Tuning_NOTE,
    extra_overrides: dict[str, Any] | None = None,
) -> IspProfile:
    return IspProfile(
        code=code,
        display_name=display_name,
        carrier=carrier,
        country_code="IR",
        access_type=access_type,
        asn_hints=asn_hints,
        engine_order=engine_order,
        security_mode=security_mode,
        fake_sni=fake_sni,
        xray_fragment=xray_fragment,
        xray_fingerprint=xray_fingerprint,
        notes=notes,
        extra_overrides=dict(extra_overrides or {}),
    )


_IRAN_PROFILES: tuple[IspProfile, ...] = (
    _profile(
        "ir-mci",
        "MCI (Hamrahe Aval)",
        "MCI",
        "mobile",
        ("AS197207",),
    ),
    _profile(
        "ir-irancell",
        "Irancell (MTN)",
        "Irancell",
        "mobile",
        ("AS44244",),
    ),
    _profile(
        "ir-rightel",
        "Rightel",
        "Rightel",
        "mobile",
        ("AS57218",),
    ),
    _profile(
        "ir-tci",
        "TCI (fixed-line)",
        "TCI",
        "fixed",
        ("AS58224", "AS48434"),
        engine_order=_IR_FIXED_ENGINES,
    ),
    _profile(
        "ir-shatel",
        "Shatel (fixed-line)",
        "Shatel",
        "fixed",
        ("AS31549",),
        engine_order=_IR_FIXED_ENGINES,
    ),
)

_PROFILES_BY_CODE: dict[str, IspProfile] = {profile.code: profile for profile in _IRAN_PROFILES}


def list_isp_profiles() -> tuple[IspProfile, ...]:
    """All cataloged ISP sub-profiles, registry order."""
    return _IRAN_PROFILES


def get_isp_profile(code: str | None) -> IspProfile | None:
    """Look up one profile by code (case-insensitive); None when unknown."""
    if not code:
        return None
    return _PROFILES_BY_CODE.get(str(code).strip().lower())


def isp_profile_codes() -> tuple[str, ...]:
    return tuple(_PROFILES_BY_CODE)


def suggest_isp_profiles(code: str | None, *, limit: int = 3) -> tuple[str, ...]:
    """Best-guess profile codes for an unknown input ("did you mean ...").

    Matches on profile code similarity and on carrier-name tokens, so both
    `--profile ir-mcx` (typo) and `--profile mci` (bare carrier name) land on
    `ir-mci`. Best matches first; empty when nothing is close.
    """
    if not code or not str(code).strip():
        return ()
    query = str(code).strip().lower()
    import difflib

    scored: dict[str, float] = {}
    for profile in _IRAN_PROFILES:
        tokens = {profile.code, profile.carrier.lower(), profile.display_name.lower()}
        best = max(
            difflib.SequenceMatcher(None, query, token).ratio()
            for token in tokens
        )
        # A query contained in a code/carrier ("mci" inside "ir-mci") is a
        # strong signal even when edit distance is high.
        if query in profile.code or query == profile.carrier.lower():
            best = max(best, 0.9)
        scored[profile.code] = best
    ranked = sorted(scored.items(), key=lambda item: item[1], reverse=True)
    return tuple(code for code, score in ranked[: max(1, limit)] if score >= 0.6)


def detect_isp_profile(isp_info: Any) -> IspProfile | None:
    """Match an IspInfo-like object against profile ASN hints.

    ASN prefixes compare case-insensitively. Returns None when nothing
    matches or the lookup data has no ASN; detection is best-effort and
    never gates connecting.
    """
    if isp_info is None:
        return None
    asn = str(getattr(isp_info, "asn", "") or "").strip().upper()
    if not asn:
        return None
    for profile in _IRAN_PROFILES:
        for hint in profile.asn_hints:
            if asn == hint.upper() or asn.startswith(hint.upper()):
                return profile
    return None


__all__ = [
    "IspProfile",
    "SCHEMA_VERSION",
    "detect_isp_profile",
    "get_isp_profile",
    "isp_profile_codes",
    "list_isp_profiles",
    "suggest_isp_profiles",
]
