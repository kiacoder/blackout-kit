"""
Blackout Kit - Sanitized local support bundle (Blackout Operator foundation).

Collects debugging information for bug reports in one inspectable file, with
aggressive redaction:

- passwords, tokens, API keys, private keys, PSKs, and other credentials are
  removed (values replaced, never partially masked)
- proxy/VPN/SSH config URIs are removed whole (their embedded secrets are the
  credential; a partially masked URI still leaks infrastructure details)
- log lines containing those patterns are dropped
- vault contents and the SSH vault are never read into the bundle

Bundles are written only where the user asks. Nothing is uploaded, ever.
`preview()` lets the user inspect exactly what an export will contain before
any file is created.
"""
from __future__ import annotations

import importlib.metadata
import json
import platform as platform_module
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import settings as cfg
from .events import _SECRET_URI_SCHEMES, REDACTED, sanitize_details

BUNDLE_SCHEMA_VERSION = 1

_LOG_TAIL_LINES = 200
_DAEMON_ERROR_LINES = 50

_SENSITIVE_LINE_RE = re.compile(
    r"([\w-]*(?:password|passwd|secret|token|psk|passphrase|"
    r"api[_-]?key|private[_-]?key|authorization)[\w-]*)"
    r"\s*[:=]\s*\S+",
    re.IGNORECASE,
)

# Dependency set surfaced for bug reports; failures degrade to "not installed".
_DEPENDENCIES = (
    "typer", "rich", "httpx", "psutil", "cryptography",
    "customtkinter", "scapy", "yt-dlp", "libtorrent",
)

_EXCLUDED = (
    "saved proxy configuration URIs and vault contents (configs.enc)",
    "SSH vault contents",
    "VPN/PSK/password fields from settings (values redacted)",
    "full daemon configuration dumps",
    "environment variables",
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
    return _SENSITIVE_LINE_RE.sub(lambda m: m.group(1) + "=" + REDACTED, line)


def scrub_text(text: str) -> str:
    """Scrub a multi-line log body line by line."""
    lines = [scrubed for line in text.splitlines() if (scrubed := scrub_line(line)) is not None]
    return "\n".join(lines)


def scrub_lines(lines: list[str]) -> list[str]:
    return [scrubed for line in lines if (scrubed := scrub_line(line)) is not None]


def sanitized_settings() -> dict[str, Any]:
    """Saved settings with sensitive values masked, sanitized twice over."""
    values = cfg.load()
    masked = {
        key: cfg.display_value(key, value)
        for key, value in values.items()
    }
    return sanitize_details(masked)


def _install_method() -> str:
    try:
        dist = importlib.metadata.distribution("blackout-kit")
        return f"pip package ({dist.version})"
    except importlib.metadata.PackageNotFoundError:
        pass
    package_root = Path(__file__).resolve().parent
    if (package_root.parent / "pyproject.toml").is_file():
        return "source checkout"
    return "unknown"


def _dependency_versions() -> dict[str, str]:
    versions: dict[str, str] = {}
    for name in _DEPENDENCIES:
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = "not installed"
    return versions


def _daemon_log_text() -> str:
    try:
        from . import daemon

        return scrub_text(daemon.read_logs(lines=_LOG_TAIL_LINES) or "")
    except Exception as exc:
        return f"[daemon log unavailable: {type(exc).__name__}]"


def _daemon_error_lines() -> list[str]:
    try:
        from . import daemon

        raw_lines = (daemon.read_logs(lines=1000) or "").splitlines()
    except Exception as exc:
        return [f"[daemon log unavailable: {type(exc).__name__}]"]
    errors = [
        line for line in raw_lines
        if "[ERROR]" in line or "[WARNING]" in line
    ]
    return scrub_lines(errors[-_DAEMON_ERROR_LINES:])


def _recovery_history() -> list[dict[str, Any]]:
    try:
        from . import recovery_audit

        return sanitize_details(recovery_audit.history(lines=20))
    except Exception as exc:
        return [{"error": f"{type(exc).__name__}: {exc}"}]


def collect() -> dict[str, Any]:
    """Assemble the full sanitized bundle content."""
    from .snapshot import sanitized_snapshot

    return {
        "bundle_schema_version": BUNDLE_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": "blackout-kit support bundle",
        "system": {
            "platform": sys.platform,
            "os_release": platform_module.release(),
            "machine": platform_module.machine(),
            "python": platform_module.python_version(),
        },
        "install": {"method": _install_method()},
        "versions": {
            "blackout_kit": ".".join(str(part) for part in _package_version()),
            **_dependency_versions(),
        },
        "snapshot": sanitized_snapshot(),
        "daemon_errors": _daemon_error_lines(),
        "logs": {"daemon_tail_lines": _LOG_TAIL_LINES, "daemon_tail": _daemon_log_text()},
        "recovery_history": _recovery_history(),
        "settings": sanitized_settings(),
        "redaction_policy": {
            "strategy": "removal, not partial masking",
            "removed_whole": ["proxy/VPN/SSH config URIs", "credential key/value lines"],
            "marker": REDACTED,
        },
        "excluded": list(_EXCLUDED),
        "uploaded": False,
        "note": "Nothing in this bundle was sent anywhere by Blackout Kit.",
    }


def _package_version() -> tuple[int, ...]:
    from . import get_version

    return get_version()


def preview() -> dict[str, Any]:
    """Describe exactly what an export will contain, without content."""
    full = collect()
    content_sections = ("daemon_errors", "logs", "recovery_history", "settings")
    summarized = dict(full)
    summarized["snapshot"] = {
        "section_count": len(full.get("snapshot", {})),
        "fields": sorted(str(key) for key in full.get("snapshot", {})),
    }
    summarized["daemon_errors"] = {"line_count": len(full.get("daemon_errors") or [])}
    summarized["logs"] = {
        "daemon_tail_lines": (full.get("logs") or {}).get("daemon_tail_lines"),
        "daemon_tail_chars": len((full.get("logs") or {}).get("daemon_tail") or ""),
    }
    summarized["recovery_history"] = {"record_count": len(full.get("recovery_history") or [])}
    summarized["settings"] = {"key_count": len(full.get("settings") or {})}
    summarized["preview"] = True
    summarized["content_sections_redacted_in_preview"] = list(content_sections)
    return summarized


def export_bundle(path: Path) -> Path:
    """Write the full bundle to `path` as JSON; refuses to overwrite."""
    path = Path(path)
    if path.exists():
        raise FileExistsError(f"refusing to overwrite existing file: {path}")
    payload = collect()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return path


def default_bundle_path() -> Path:
    return Path.cwd() / f"blackout-support-bundle-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"


__all__ = [
    "BUNDLE_SCHEMA_VERSION",
    "collect",
    "default_bundle_path",
    "export_bundle",
    "preview",
    "sanitized_settings",
    "scrub_line",
    "scrub_lines",
    "scrub_text",
]
