"""
Blackout Kit - Credential redaction for log text.

One scrubbing authority for everything that turns a log line into durable or
exported text: the daemon's own log file (through `RedactingFormatter`) and any
reader of that text, including `blackoutkit.support_bundle`.

Policy: removal, never partial masking. A secret-bearing key keeps its name and
loses its whole value (to end of line, so multi-word values such as
`Authorization: Bearer <jwt>` cannot leak past the first token); a line that
embeds a proxy/VPN/SSH config URI is dropped outright, because a partially
masked URI still leaks infrastructure; any URL with embedded userinfo
credentials loses the credential material while the scheme and host stay
readable for debugging.

The patterns are deliberately conservative and err toward destroying context:
redaction failures are silent, so a pattern that matches too much costs a
debugging line, while a pattern that matches too little costs a credential.
"""
from __future__ import annotations

import logging
import re

from .events import _SECRET_URI_SCHEMES, REDACTED

# Key/value (or key: value) assignments whose name marks the value as a
# credential. The value group runs to end of line on purpose: a bearer token,
# a quoted secret with spaces, or a connection string made of several
# `key=value` pairs must all be consumed, not just the first word.
SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"([\w-]*(?:password|passwd|secret|token|psk|passphrase|api[_-]?key|"
    r"private[_-]?key|authorization|bearer|cookie)[\w-]*)"
    r"\s*[:=]\s*.*",
    re.IGNORECASE,
)

# `scheme://user:pass@host` — the userinfo is the credential. Scheme and host
# are kept so the line is still useful when triaging a failure. The class stops
# at the first `/` so only the authority component is consumed, and it is greedy
# so a password containing `@` (`socks5://bob:p@ss@host`) is eaten in full.
URI_USERINFO_RE = re.compile(r"([a-z][a-z0-9+.\-]*://)[^\s/]+@", re.IGNORECASE)

# An `Authorization`-style header written without a separator, e.g. a bare
# `Bearer <jwt>` or `Basic <base64>` value echoed into a request log.
AUTH_SCHEME_RE = re.compile(
    r"\b(bearer|basic|digest|token)\s+[A-Za-z0-9._~+/=%\-]{8,}",
    re.IGNORECASE,
)


def scrub_line(line: str) -> str | None:
    """Return a safe log line, or None when the line must be dropped.

    Prefer removal over clever masking: a line containing a proxy URI is
    dropped whole; key/value secret assignments keep the key and replace the
    value with the redaction marker.
    """
    lowered = line.lower()
    if any(scheme in lowered for scheme in _SECRET_URI_SCHEMES):
        return None
    scrubbed = SENSITIVE_ASSIGNMENT_RE.sub(lambda m: m.group(1) + "=" + REDACTED, line)
    scrubbed = AUTH_SCHEME_RE.sub(lambda m: m.group(1) + " " + REDACTED, scrubbed)
    scrubbed = URI_USERINFO_RE.sub(lambda m: m.group(1) + REDACTED + "@", scrubbed)
    return scrubbed


def scrub_text(text: str) -> str:
    """Scrub a multi-line log body line by line."""
    lines = [scrubbed for line in text.splitlines() if (scrubbed := scrub_line(line)) is not None]
    return "\n".join(lines)


def scrub_lines(lines: list[str]) -> list[str]:
    return [scrubbed for line in lines if (scrubbed := scrub_line(line)) is not None]


class RedactingFormatter(logging.Formatter):
    """Formatter that redacts credentials before a record reaches its sink.

    Redaction belongs at write time, not only at export time: `daemon.log`,
    `daemon.out` and anything tailing them then never contain a credential in
    the first place. Applied to the daemon's rotating file handler and its
    stderr handler.
    """

    def format(self, record: logging.LogRecord) -> str:
        return scrub_text(super().format(record))


__all__ = [
    "AUTH_SCHEME_RE",
    "REDACTED",
    "SENSITIVE_ASSIGNMENT_RE",
    "URI_USERINFO_RE",
    "RedactingFormatter",
    "scrub_line",
    "scrub_lines",
    "scrub_text",
]
