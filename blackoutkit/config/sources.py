"""Built-in public config sources — the CLI counterpart of the mobile app's
TrustedSources list.

Both entries were verified reachable at the time of writing and carry the
same file paths the mobile app uses. They are large (thousands of lines),
so `blackout config fetch` samples them rather than importing everything:
the library is a working set, not an archive.
"""

from __future__ import annotations

TRUSTED_SOURCES: list[dict[str, str]] = [
    {
        "name": "barry-far V2Ray Configs",
        "url": "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt",
        "note": "Large rotating pool: vless, vmess, trojan, ss (~7.5k lines)",
    },
    {
        "name": "V2Ray Aggregator (Eternity)",
        "url": "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity.txt",
        "note": "Aggregated subscription list, updated regularly",
    },
]

# Default cap on NEW configs pulled from public sources per fetch. Mirrors the
# mobile app's 150-config test budget: enough to find fast servers, small
# enough that `blackout test` stays a seconds-long operation.
DEFAULT_FETCH_LIMIT = 150


def find_source(name: str) -> dict[str, str] | None:
    """Look up a trusted source by name (case-insensitive, partial match)."""
    needle = (name or "").strip().lower()
    if not needle:
        return None
    for source in TRUSTED_SOURCES:
        if needle in source["name"].lower():
            return source
    return None
