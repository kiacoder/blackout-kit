"""Network URL and IP address validation utilities.

Shared helpers for SSRF prevention, private IP detection, and safe HTTP request handling.
Used by subscription import, threat feeds, adblock, and DoH proxy.
"""
import ipaddress
import logging
import socket
import urllib.request

_log = logging.getLogger(__name__)


def reject_private_host(hostname: str, port: int = 443) -> None:
    """
    Resolve hostname and reject if any result is not a global IP address.
    Raises ValueError with a descriptive message if rejected.
    Used to prevent SSRF attacks that target private/loopback/link-local addresses.
    """
    if not hostname:
        raise ValueError("Hostname must be non-empty")

    # First try to parse as a literal IP
    try:
        addr = ipaddress.ip_address(hostname)
        if not addr.is_global:
            raise ValueError(f"Address {hostname} is not global (loopback={addr.is_loopback}, private={addr.is_private}, link-local={addr.is_link_local})")
        return
    except (ValueError, ipaddress.AddressValueError):
        # Not a literal IP; try hostname resolution
        pass

    # Resolve hostname via system resolver
    try:
        results = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except OSError as e:
        raise ValueError(f"Could not resolve hostname {hostname!r}: {e}") from e

    if not results:
        raise ValueError(f"No addresses resolved for hostname {hostname!r}")

    # Check all resolved addresses
    for info in results:
        try:
            addr = ipaddress.ip_address(info[4][0])
            if not addr.is_global:
                raise ValueError(
                    f"Hostname {hostname!r} resolved to {addr} which is not global "
                    f"(loopback={addr.is_loopback}, private={addr.is_private}, link-local={addr.is_link_local})"
                )
        except (ipaddress.AddressValueError, IndexError) as e:
            raise ValueError(f"Invalid address in resolution results: {e}") from e


class SSRFGuardHTTPSHandler(urllib.request.HTTPSHandler):
    """
    HTTPS handler that re-validates resolved IPs at connection time.

    Prevents DNS rebinding attacks where:
    1. Hostname resolves to a global IP during validation (passes initial check)
    2. At connection time, DNS returns a private IP (TOCTOU window)

    This handler re-resolves the hostname immediately before opening the socket,
    ensuring the actual connection target is validated against SSRF rules.
    """

    def https_open(self, req):
        """Override to re-validate the hostname before opening the connection."""
        # Extract hostname from request URL
        hostname = req.get_host()
        # gethost() returns "host:port" if port is non-standard; split it
        if ":" in hostname:
            hostname = hostname.split(":", 1)[0]

        # Re-validate the hostname against SSRF rules
        try:
            reject_private_host(hostname, port=443)
        except ValueError as e:
            raise urllib.error.URLError(f"SSRF guard: {e}") from e

        # Proceed with the original HTTPS handler
        return super().https_open(req)
