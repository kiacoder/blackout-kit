"""
Blackout Kit - Russian cellular whitelist awareness.

Russian cellular ISPs (MTS, Beeline, Megafon, Tele2) operate a "whitelist mode"
where only traffic to approved IP ranges passes. The whitelist includes major
Russian tech companies: Yandex, VK, Ozon, Mail.ru, and others.

A proxy server sitting on a whitelisted IP range (or behind a CDN fronting one)
bypasses cellular whitelist mode entirely. A proxy on a non-whitelisted IP will
pass the TCP handshake but die when real data flows.

Source: field-verified 2026-08-19; the whitelist is publicly documented —
search "белые списки список разрешенных ресурсов".

Note: these ranges are approximate and may change. This module is informational
only — it helps users understand risk, not guarantee connectivity.
"""
import ipaddress
import logging

_log = logging.getLogger(__name__)

# Known Russian tech giant IP ranges (approximate, publicly documented)
# These are the major ranges that appear on cellular whitelists.
_WHITELIST_RANGES = [
    # Yandex
    ipaddress.ip_network("77.88.0.0/18"),
    ipaddress.ip_network("93.158.128.0/18"),
    ipaddress.ip_network("95.108.128.0/17"),
    ipaddress.ip_network("5.45.192.0/18"),
    ipaddress.ip_network("5.255.192.0/18"),
    ipaddress.ip_network("37.9.64.0/18"),
    ipaddress.ip_network("178.154.128.0/17"),
    ipaddress.ip_network("100.43.64.0/18"),
    ipaddress.ip_network("199.21.96.0/22"),

    # VK / Mail.ru Group
    ipaddress.ip_network("95.163.0.0/16"),
    ipaddress.ip_network("178.248.128.0/24"),
    ipaddress.ip_network("185.16.148.0/22"),
    ipaddress.ip_network("217.20.144.0/20"),
    ipaddress.ip_network("188.93.0.0/18"),

    # Ozon
    ipaddress.ip_network("185.10.208.0/22"),

    # Russian government/domestic CDN (commonly whitelisted)
    ipaddress.ip_network("194.67.0.0/16"),

    # Major Russian hosting (SpaceWeb, Selectel, etc. — commonly whitelisted)
    ipaddress.ip_network("45.136.0.0/16"),
]


def is_on_whitelist(ip_str: str) -> bool:
    """Return True if the given IP address is in a known Russian whitelist range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in network for network in _WHITELIST_RANGES)
    except (ValueError, TypeError):
        return False


def check_whitelist_status(host: str) -> tuple[bool, str]:
    """
    Check if a host (hostname or IP) is likely on the Russian cellular whitelist.

    Returns (on_whitelist: bool, detail: str).
    Does NOT resolve hostnames — if the host is a domain, returns (False, "unresolved").
    Use after resolving the host to an IP via DoH or DNS.
    """
    if not host:
        return False, "no host provided"

    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False, f"host '{host}' is a domain — resolve to IP first for whitelist check"

    if is_on_whitelist(host):
        return True, f"{host} is on a known Russian cellular whitelist range"
    return False, f"{host} is NOT on known Russian whitelist ranges — may fail on cellular"
