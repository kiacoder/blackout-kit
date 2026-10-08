"""
Blackout Kit - TLS certificate bypass policy.

Legendary features:
  - check_host_cert(): proactive TLS handshake — gets cert details even on failure
  - HostCertRecord: persisted per-host cert status in ~/.blackout-kit/cert_records.json
  - should_allow_insecure(): per-connection policy enforcement
      DEFAULT-DENY: TLS certificate verification is ON unless the user has explicitly
      opted in via the `tls_allow_insecure` setting. We do NOT disable verification by
      default for remote hosts.
      Local addresses (127.0.0.1, localhost) are always exempt — they need allowInsecure
      because the local SNI spoofer never presents a valid cert for the remote hostname.
  - scan_xray_line(): detect cert error phrases in xray stderr output
"""
from __future__ import annotations

import json
import os
import socket
import ssl
import tempfile
import threading
import time
from dataclasses import asdict, dataclass

_TLS12 = getattr(ssl.TLSVersion, "TLS1_2", None)
if _TLS12 is None:
    _TLS12 = ssl.TLSVersion.TLSv1_2
from datetime import datetime, timezone
from pathlib import Path

APP_DATA_DIR = Path.home() / ".blackout-kit"
STORE_FILE   = APP_DATA_DIR / "cert_records.json"

# Addresses that are always exempted from cert checking (local proxy endpoints)
LOCAL_ADDRS = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}

# Phrases in xray/proxy stderr that indicate a TLS cert problem
CERT_ERROR_PATTERNS = (
    "x509:",
    "certificate verify failed",
    "certificate has expired",
    "certificate signed by unknown authority",
    "self signed certificate",
    "self-signed certificate",
    "tls: failed to verify",
    "tls: bad certificate",
    "certificate is valid for",
    "cannot validate certificate",
    "certificate error",
)


# ──────────────────────────── Data model ─────────────────────────

@dataclass
class HostCertRecord:
    host:             str
    port:             int
    checked_at:       float        # Unix timestamp
    cert_ok:          bool         # True = passed strict TLS validation
    subject:          str          # e.g. "CN=*.google.com"
    issuer:           str          # e.g. "CN=WR2, O=Google Trust Services"
    expires:          str          # "YYYY-MM-DD" or "" if unknown
    days_left:        int          # days until expiry (negative = already expired)
    self_signed:      bool         # subject == issuer
    error:            str | None   # error string when cert_ok=False
    manually_allowed: bool = False # user explicitly said "allow this anyway"


# ──────────────────────────── Persistence ────────────────────────

_store_lock = threading.Lock()

def _load_store() -> dict[str, dict]:
    """Load the cert record store from disk. Returns {} only if file genuinely missing."""
    if not STORE_FILE.exists():
        return {}
    try:
        return json.loads(STORE_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, PermissionError, OSError) as exc:
        print(f"[cert_bypass] Warning: failed to read cert store: {exc}")
        return {}


def _save_store(store: dict[str, dict]) -> None:
    """Atomically write the cert store to disk."""
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=str(APP_DATA_DIR),
        prefix="cert_records_", suffix=".tmp", delete=False,
    )
    try:
        tmp.write(json.dumps(store, indent=2))
        tmp.close()
        os.replace(tmp.name, str(STORE_FILE))
    except Exception:
        try:
            os.unlink(tmp.name)
        except Exception:
            pass
        raise


def _store_key(host: str, port: int) -> str:
    return f"{host}:{port}"


def get_record(host: str, port: int = 443) -> HostCertRecord | None:
    """Return the stored cert record for host:port, or None if not yet checked."""
    with _store_lock:
        store = _load_store()
        raw   = store.get(_store_key(host, port))
    if not raw:
        return None
    try:
        return HostCertRecord(**raw)
    except Exception:
        return None


def save_record(record: HostCertRecord) -> None:
    """Persist a cert record to the store (thread-safe + atomic)."""
    with _store_lock:
        store = _load_store()
        store[_store_key(record.host, record.port)] = asdict(record)
        _save_store(store)


def allow_host(host: str, port: int = 443) -> None:
    """
    Manually mark a host:port as allowed even with a bad cert.
    Useful for LEGEND mode users who explicitly trust a specific self-signed server.
    """
    store = _load_store()
    key   = _store_key(host, port)
    if key in store:
        store[key]["manually_allowed"] = True
    else:
        # No record yet — create a placeholder entry
        store[key] = asdict(HostCertRecord(
            host=host, port=port, checked_at=time.time(),
            cert_ok=False, subject="", issuer="", expires="",
            days_left=0, self_signed=False, error="manually allowed without check",
            manually_allowed=True,
        ))
    _save_store(store)


def clear_host(host: str, port: int = 443) -> None:
    """Remove the cert record for host:port."""
    store = _load_store()
    store.pop(_store_key(host, port), None)
    _save_store(store)


def clear_all() -> None:
    """Wipe all stored cert records."""
    _save_store({})


# ──────────────────────────── Policy ─────────────────────────────

def _bypass_enabled() -> bool:
    """
    True ONLY when the user has explicitly opted into insecure TLS bypass.

    Verification is ENABLED by default. We never disable it for remote hosts
    unless `tls_allow_insecure` is explicitly set True in the settings.
    """
    try:
        from . import settings as cfg
        return bool(cfg.load().get("tls_allow_insecure", False))
    except Exception:
        return False


def should_allow_insecure(host: str, port: int, mode: str) -> tuple[bool, str]:
    """
    Determine if xray's tlsSettings.allowInsecure should be True for this connection.

    Returns (allow_insecure: bool, warning_message: str).
    warning_message is "" unless there's something to surface to the user.

    SECURITY: TLS certificate verification is ENABLED by default. We do NOT disable
    it for remote hosts unless the user has explicitly opted in via the
    `tls_allow_insecure` setting. Local proxy endpoints (127.0.0.1 / localhost / ::1)
    are always exempt because the local SNI spoofer never presents a cert that would
    pass host validation for the remote hostname.

    Policy:
      - Local addresses       → always True (loopback spoofer, exempt)
      - tls_allow_insecure    → True (explicit user opt-in to bypass verification)
      - cert record valid     → True (no allowInsecure needed; xray verifies normally)
      - cert manually allowed → True
      - otherwise             → False (default-deny; verification stays on)
    """
    # Local proxy endpoints are always exempt
    if host in LOCAL_ADDRS:
        return True, ""

    # Explicit opt-in bypass flag takes precedence over the default-deny stance.
    if _bypass_enabled():
        return True, "TLS certificate verification disabled by user (tls_allow_insecure=True)"

    record = get_record(host, port)

    # No cert data yet — default to verification ON (False). xray will verify the
    # cert; if it is valid the connection succeeds, otherwise the user must opt in.
    if record is None:
        return False, ""

    # Cert is valid or the user has manually allowed this host → no allowInsecure needed.
    if record.cert_ok or record.manually_allowed:
        return True, ""

    # Known-bad cert with no opt-in → deny (hard fail) and surface the reason.
    reason = record.error or "TLS certificate validation failed"
    return False, f"Refusing insecure connection to {host}:{port} — {reason}"


# ──────────────────────────── Cert probe ─────────────────────────

def _parse_dn(dn_seq: tuple) -> str:
    """Convert SSL cert DN sequence → readable string. e.g. 'CN=*.google.com, O=Google'"""
    parts = []
    for rdn in dn_seq:
        for attr, val in rdn:
            parts.append(f"{attr}={val}")
    return ", ".join(parts)


def check_host_cert(
    host: str,
    port: int = 443,
    timeout: float = 5.0,
) -> HostCertRecord:
    """
    Proactively check the TLS certificate for host:port.

    Always stores the result in the cert record store.
    Returns a HostCertRecord regardless of outcome:
      - Network errors (refused, timeout) → cert_ok=False, error="Connection failed: …"
      - Cert errors (expired, self-signed) → cert_ok=False, error="x509: …"
      - Clean cert → cert_ok=True

    Uses strict context first to detect errors, then lenient context to pull cert
    details even when the strict check fails.
    """
    ts = time.time()

    # ── Try strict TLS handshake ──────────────────────────────────
    ctx_strict  = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx_strict.minimum_version = _TLS12
    ctx_strict.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    cert_ok     = False
    cert_info:  dict = {}
    error:      str | None = None

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            # codeql[py/insecure-protocol-defaults]
            with ctx_strict.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                cert_ok   = True
                cert_info = tls_sock.getpeercert() or {}
    except ssl.SSLCertVerificationError as exc:
        error = str(exc)
    except ssl.SSLError as exc:
        error = str(exc)
    except TimeoutError:
        error = f"Connection timed out after {timeout:.0f}s"
        _existing = get_record(host, port)
        record = HostCertRecord(
            host=host, port=port, checked_at=ts,
            cert_ok=False, subject="", issuer="", expires="",
            days_left=0, self_signed=False, error=error,
            manually_allowed=_existing.manually_allowed if _existing else False,
        )
        save_record(record)
        return record
    except OSError as exc:
        error = f"Connection failed: {exc}"
        _existing = get_record(host, port)
        record = HostCertRecord(
            host=host, port=port, checked_at=ts,
            cert_ok=False, subject="", issuer="", expires="",
            days_left=0, self_signed=False, error=error,
            manually_allowed=_existing.manually_allowed if _existing else False,
        )
        save_record(record)
        return record

    # ── If strict failed, try lenient to still get cert details ──
    if not cert_ok and not cert_info:
        ctx_lenient = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx_lenient.minimum_version = _TLS12
        ctx_lenient.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        ctx_lenient.check_hostname = False
        ctx_lenient.verify_mode    = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=timeout) as raw_sock:
                # codeql[py/insecure-protocol-defaults]
                with ctx_lenient.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                    cert_info = tls_sock.getpeercert() or {}
        except Exception:
            cert_info = {}

    # ── Parse cert fields ─────────────────────────────────────────
    subject   = _parse_dn(cert_info.get("subject",  ()))
    issuer    = _parse_dn(cert_info.get("issuer",   ()))
    expires   = ""
    days_left = 0

    not_after = cert_info.get("notAfter", "")
    if not_after:
        try:
            # Strip trailing timezone abbreviation (e.g. "GMT") before parsing.
            # %Z is unreliable on Windows and raises ValueError for "GMT".
            parts = not_after.split()
            clean = " ".join(parts[:-1]) if parts and parts[-1].isalpha() else not_after
            exp       = datetime.strptime(clean, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
            now       = datetime.now(timezone.utc)
            days_left = (exp - now).days
            expires   = exp.strftime("%Y-%m-%d")
        except Exception:
            pass

    self_signed = bool(subject and issuer and subject == issuer)

    # Preserve manually_allowed if the user already set it for this host
    existing = get_record(host, port)
    manually_allowed = existing.manually_allowed if existing else False

    record = HostCertRecord(
        host=host, port=port, checked_at=ts,
        cert_ok=cert_ok, subject=subject, issuer=issuer,
        expires=expires, days_left=days_left,
        self_signed=self_signed, error=error,
        manually_allowed=manually_allowed,
    )
    save_record(record)
    return record


# ──────────────────────────── Output scanner ─────────────────────

def scan_xray_line(line: str) -> str | None:
    """
    Scan a single line of xray stdout/stderr for TLS cert error phrases.

    Returns the matching error snippet (trimmed) if a cert error is detected,
    or None if the line looks clean.
    Used by the background stderr monitor in XRayEngine.
    """
    lower = line.lower()
    for phrase in CERT_ERROR_PATTERNS:
        idx = lower.find(phrase)
        if idx >= 0:
            # Return a trimmed snippet centred on the match
            start = max(0, idx - 8)
            end   = min(len(line), idx + 120)
            return line[start:end].strip()
    return None
