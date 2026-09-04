"""Redacted, bounded local history for executed recovery operations."""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

from . import APP_DATA_DIR

AUDIT_FILE = APP_DATA_DIR / "recovery_audit.jsonl"
MAX_RECORDS = 100
_SECRET_PATTERN = re.compile(r"(?i)(password|psk|token|secret|uuid)=?[^\s,;]+")
_URI_CREDENTIAL_PATTERN = re.compile(r"([a-z][a-z0-9+.-]*://)[^\s/@]+@", re.IGNORECASE)


def redact(value: object) -> str:
    text = str(value)
    text = _URI_CREDENTIAL_PATTERN.sub(r"\1[hidden]@", text)
    text = _SECRET_PATTERN.sub(lambda match: f"{match.group(1)}=[hidden]", text)
    return text


def _atomic_write(lines: list[str]) -> None:
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
    temporary = AUDIT_FILE.with_suffix(".tmp")
    temporary.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    temporary.replace(AUDIT_FILE)


def record(*, source: str, flags: dict[str, bool], results: list[dict]) -> None:
    """Persist only final recovery outcomes; previews intentionally never call this."""
    try:
        prior = AUDIT_FILE.read_text(encoding="utf-8", errors="replace").splitlines() if AUDIT_FILE.exists() else []
        event = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "source": source,
            "platform": sys.platform,
            "flags": {key: bool(value) for key, value in flags.items()},
            "actions": [
                {
                    "name": redact(step.get("name", "")),
                    "ok": bool(step.get("ok")),
                    "detail": redact(step.get("detail", "")),
                }
                for step in results
            ],
        }
        prior.append(json.dumps(event, ensure_ascii=False, separators=(",", ":")))
        _atomic_write(prior[-MAX_RECORDS:])
    except OSError:
        pass


def history(lines: int = 20) -> list[dict]:
    if not AUDIT_FILE.exists():
        return []
    records = []
    for line in AUDIT_FILE.read_text(encoding="utf-8", errors="replace").splitlines()[-max(1, lines):]:
        try:
            record_data = json.loads(line)
        except json.JSONDecodeError:
            continue
        records.append(record_data)
    return records
