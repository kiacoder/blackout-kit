"""Machine-bound authenticated storage for Blackout Kit secrets."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

from . import APP_DATA_DIR, DATA_DIR

CONFIGS_FILE = DATA_DIR / "configs.txt"
ENC_CONFIGS_FILE = APP_DATA_DIR / "configs.enc"
ENC_SECRETS_FILE = APP_DATA_DIR / "secrets.enc"
SECRET_KEYS = ("ikev2_password", "ikev2_psk", "softether_password")

_HEADER = b"BKVLT03:"
_HEADER_V2 = b"BKVLT02:"
_PROFILE_HEADER = b"BKPF01:"
_LEGACY_AES_HEADER = b"BKAE01:"
# Legacy (v2) derivation: a constant salt shared by every installation. It is
# kept ONLY to decrypt existing files - see _aes_key's docstring for why a
# constant salt is a weakness and what replaced it.
_PBKDF2_SALT = b"blackout-kit-aes256gcm-2026"
_PBKDF2_ITERS = 100_000
# v3: a fresh random salt per file, and the current OWASP work factor for
# PBKDF2-HMAC-SHA256. A constant salt let two machines with the same identity
# derive the same key and allowed precomputation; a per-file salt removes both.
_V3_ITERS = 600_000
_SALT_LEN = 16
_PROFILE_PBKDF2_ITERS = 300_000
PROFILE_MAX_BYTES = 4 * 1024 * 1024


class VaultError(RuntimeError):
    """Raised when authenticated encrypted storage cannot be read or written."""


_machine_id_cache: tuple[tuple[str, str], list[bytes]] | None = None


def reset_machine_id_cache() -> None:
    """Forget cached machine identities (used by tests and recovery flows)."""
    global _machine_id_cache
    _machine_id_cache = None


def _machine_identity_key() -> tuple[str, str]:
    """Cache key so identity changes (or test patches) invalidate the cache."""
    return (sys.platform, platform.node())


def _windows_smbios_uuid() -> str:
    """Read the SMBIOS UUID, tolerating builds where wmic was removed."""
    result = subprocess.run(
        ["wmic", "csproduct", "get", "UUID"],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    identifiers = [
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip() and line.strip().upper() != "UUID"
    ]
    return identifiers[0] if identifiers else ""


def _windows_smbios_uuid_via_cim() -> str:
    """Read the same SMBIOS UUID through PowerShell CIM (wmic-free fallback)."""
    try:
        result = subprocess.run(
            [
                "powershell", "-NoProfile", "-Command",
                "(Get-CimInstance Win32_ComputerSystemProduct).UUID",
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    for line in result.stdout.splitlines():
        value = line.strip()
        if value and value.upper() not in {"UUID", "NONE", ""}:
            return value
    return ""


# Historical constant fallbacks used by older builds when machine identity
# probing failed. They are decrypt-only recovery candidates and must never be
# used for new writes; a constant key provides no machine binding.
_LEGACY_MACHINE_ID_CONSTANTS: tuple[bytes, ...] = (
    b"blackout-kit-default-machine-id",
    b"blackout-kit-unknown-machine",
)


def machine_id_candidates() -> list[bytes]:
    """Ordered machine identities for key derivation, canonical first.

    The canonical identity is the SMBIOS UUID. On Windows builds where the
    ``wmic`` binary was removed, the same UUID is read through PowerShell CIM
    so vaults written before the removal stay readable. The hostname follows
    so vaults written by builds that silently fell back to it can still be
    recovered, and known historical constant fallbacks come last for
    decrypt-only recovery. Non-Windows behavior is unchanged.
    """
    global _machine_id_cache
    cache_key = _machine_identity_key()
    if _machine_id_cache is not None and _machine_id_cache[0] == cache_key:
        return list(_machine_id_cache[1])

    candidates: list[str] = []
    if sys.platform == "win32":
        for probe in (_windows_smbios_uuid, _windows_smbios_uuid_via_cim):
            try:
                value = probe()
            except Exception:
                value = ""
            if value:
                candidates.append(value)
                break
    hostname = platform.node()
    if hostname:
        candidates.append(hostname)

    encoded: list[bytes] = []
    for value in candidates:
        blob = value.encode()
        if blob not in encoded:
            encoded.append(blob)
    for blob in _LEGACY_MACHINE_ID_CONSTANTS:
        if blob not in encoded:
            encoded.append(blob)
    if not encoded:
        raise VaultError("Machine identity is unavailable")
    _machine_id_cache = (cache_key, encoded)
    return list(encoded)


def _machine_id() -> bytes:
    """Canonical identity for NEW writes (key derivation and encryption).

    Raises when no real machine identity exists: the historical constant
    fallbacks are decrypt-only recovery candidates, and silently encrypting
    with a known constant would forfeit machine binding.
    """
    primary = machine_id_candidates()[0]
    if primary in _LEGACY_MACHINE_ID_CONSTANTS:
        raise VaultError("Machine identity is unavailable")
    return primary


_key_cache: dict[tuple[bytes, bytes, int], bytes] = {}
_KEY_CACHE_LIMIT = 8


def _aes_key(
    machine_id: bytes | None = None,
    salt: bytes = _PBKDF2_SALT,
    iterations: int = _PBKDF2_ITERS,
) -> bytes:
    """Derive the AES-256 key for a machine identity, salt and work factor.

    v3 files pass their own random salt and 600k iterations; v2 files fall back
    to the historical constant salt and 100k so they stay readable. The derived
    key is cached per (identity, salt, iterations): 600k PBKDF2 rounds cost
    real time, and the vault is read on every daemon config rotation.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    identity = machine_id if machine_id is not None else _machine_id()
    cache_key = (identity, salt, iterations)
    cached = _key_cache.get(cache_key)
    if cached is not None:
        return cached
    derived = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    ).derive(identity)
    if len(_key_cache) >= _KEY_CACHE_LIMIT:
        _key_cache.clear()
    _key_cache[cache_key] = derived
    return derived


def _legacy_xor_key(machine_id: bytes | None = None) -> bytes:
    identity = machine_id if machine_id is not None else _machine_id()
    return hashlib.sha256(identity).digest()


def _aad(record: str) -> bytes:
    return f"blackout-kit/vault/{record}/v2".encode("ascii")


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".tmp_")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def secure_remove_plaintext(path: Path) -> None:
    if not path.exists():
        return
    size = path.stat().st_size
    try:
        with path.open("r+b") as handle:
            handle.write(b"\x00" * size)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        pass
    path.unlink(missing_ok=True)


def encrypt_bytes(record: str, plaintext: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    salt = os.urandom(_SALT_LEN)
    nonce = os.urandom(12)
    ciphertext = AESGCM(_aes_key(salt=salt, iterations=_V3_ITERS)).encrypt(
        nonce, plaintext, _aad(record)
    )
    return _HEADER + base64.b64encode(salt + nonce + ciphertext)


def decrypt_bytes(record: str, payload: bytes) -> bytes:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if payload.startswith(_HEADER):
        salt_len, salt, iterations = _SALT_LEN, None, _V3_ITERS
    elif payload.startswith(_HEADER_V2):
        salt_len, salt, iterations = 0, _PBKDF2_SALT, _PBKDF2_ITERS
    else:
        raise VaultError("Encrypted data is not in the current vault format")

    header_len = len(_HEADER)
    try:
        blob = base64.b64decode(payload[header_len:], validate=True)
        if len(blob) <= salt_len + 12:
            raise ValueError("encrypted payload is too short")
    except Exception as exc:
        raise VaultError("Encrypted data cannot be authenticated on this machine") from exc

    file_salt = blob[:salt_len] if salt_len else salt
    nonce = blob[salt_len:salt_len + 12]
    ciphertext = blob[salt_len + 12:]

    last_error: Exception | None = None
    for machine_id in machine_id_candidates():
        try:
            key = _aes_key(machine_id, salt=file_salt, iterations=iterations)
            return AESGCM(key).decrypt(nonce, ciphertext, _aad(record))
        except InvalidTag as exc:
            last_error = exc
        except Exception as exc:
            last_error = exc
    raise VaultError("Encrypted data cannot be authenticated on this machine") from last_error


def _profile_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    if not isinstance(passphrase, str) or not passphrase:
        raise VaultError("A profile passphrase is required")
    if iterations != _PROFILE_PBKDF2_ITERS:
        raise VaultError("Unsupported profile encryption parameters")
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    ).derive(passphrase.encode("utf-8"))


def encrypt_profile(data: dict, passphrase: str) -> bytes:
    """Encrypt a portable profile using a passphrase-derived authenticated key."""
    if not isinstance(data, dict):
        raise VaultError("Profile data must be an object")
    import secrets

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = _profile_key(passphrase, salt, _PROFILE_PBKDF2_ITERS)
    plaintext = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, b"blackout-kit/profile/v1")
    envelope = {
        "version": 1,
        "kdf": "pbkdf2-sha256",
        "iterations": _PROFILE_PBKDF2_ITERS,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    payload = _PROFILE_HEADER + json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("ascii")
    if len(payload) > PROFILE_MAX_BYTES:
        raise VaultError("Encrypted profile exceeds the size limit")
    return payload


def decrypt_profile(payload: bytes, passphrase: str) -> dict:
    """Authenticate and decrypt a portable profile without exposing its contents."""
    if not isinstance(payload, bytes) or len(payload) > PROFILE_MAX_BYTES:
        raise VaultError("Encrypted profile exceeds the size limit")
    if not payload.startswith(_PROFILE_HEADER):
        raise VaultError("Encrypted profile has an unsupported format")
    try:
        envelope = json.loads(payload[len(_PROFILE_HEADER):].decode("ascii"))
        if not isinstance(envelope, dict) or envelope.get("version") != 1 or envelope.get("kdf") != "pbkdf2-sha256":
            raise ValueError("unsupported profile version")
        if envelope.get("iterations") != _PROFILE_PBKDF2_ITERS:
            raise ValueError("unsupported profile parameters")
        salt = base64.b64decode(envelope["salt"], validate=True)
        nonce = base64.b64decode(envelope["nonce"], validate=True)
        ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
        if len(salt) != 16 or len(nonce) != 12 or not ciphertext:
            raise ValueError("invalid profile payload")
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        plaintext = AESGCM(_profile_key(passphrase, salt, envelope["iterations"])).decrypt(
            nonce,
            ciphertext,
            b"blackout-kit/profile/v1",
        )
        data = json.loads(plaintext.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("profile data is not an object")
        return data
    except VaultError:
        raise
    except Exception as exc:
        raise VaultError("Encrypted profile cannot be authenticated with this passphrase") from exc


def _decrypt_legacy_config(payload: bytes) -> bytes:
    try:
        if payload.startswith(_LEGACY_AES_HEADER):
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            blob = base64.b64decode(payload[len(_LEGACY_AES_HEADER):], validate=True)
            if len(blob) <= 12:
                raise ValueError("legacy encrypted payload is too short")
            last_error: Exception | None = None
            for machine_id in machine_id_candidates():
                try:
                    return AESGCM(_aes_key(machine_id)).decrypt(blob[:12], blob[12:], None)
                except Exception as exc:
                    last_error = exc
            raise VaultError("Legacy encrypted configs cannot be read on this machine") from last_error
        encoded = base64.b64decode(payload, validate=True)
        # The XOR format has no authentication tag, so the correct identity
        # cannot be verified cryptographically. A wrong key yields effectively
        # random bytes, which fail strict UTF-8 decoding for any realistic
        # config length; accept the first candidate whose result decodes
        # cleanly. This keeps legacy files readable regardless of which
        # historical machine identity produced them.
        for machine_id in machine_id_candidates():
            key = _legacy_xor_key(machine_id)
            decoded = bytes(value ^ key[index % len(key)] for index, value in enumerate(encoded))
            try:
                text = decoded.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if "\x00" not in text:
                return decoded
        raise VaultError("Legacy encrypted configs cannot be read on this machine")
    except VaultError:
        raise
    except Exception as exc:
        raise VaultError("Legacy encrypted configs cannot be read on this machine") from exc


def config_vault_active(encrypted_path: Path | None = None) -> bool:
    return (encrypted_path or ENC_CONFIGS_FILE).exists()


def secrets_vault_active(encrypted_path: Path | None = None) -> bool:
    return (encrypted_path or ENC_SECRETS_FILE).exists()


def read_config_bytes(encrypted_path: Path | None = None) -> bytes:
    encrypted_path = encrypted_path or ENC_CONFIGS_FILE
    if not encrypted_path.exists():
        raise VaultError("Encrypted proxy configs are missing")
    payload = encrypted_path.read_bytes()
    if payload.startswith(_HEADER):
        return decrypt_bytes("configs", payload)
    return _decrypt_legacy_config(payload)


def write_config_bytes(data: bytes, encrypted_path: Path | None = None) -> None:
    atomic_write(encrypted_path or ENC_CONFIGS_FILE, encrypt_bytes("configs", data))


def read_secrets(encrypted_path: Path | None = None) -> dict[str, str]:
    encrypted_path = encrypted_path or ENC_SECRETS_FILE
    if not encrypted_path.exists():
        return {}
    try:
        decoded = decrypt_bytes("settings-secrets", encrypted_path.read_bytes())
        values = json.loads(decoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, VaultError) as exc:
        raise VaultError("Encrypted settings secrets cannot be read on this machine") from exc
    if not isinstance(values, dict) or any(
        key not in SECRET_KEYS or not isinstance(value, str)
        for key, value in values.items()
    ):
        raise VaultError("Encrypted settings secrets have an invalid format")
    return {key: values.get(key, "") for key in SECRET_KEYS}


def write_secrets(values: dict[str, object], encrypted_path: Path | None = None) -> None:
    secrets = {
        key: str(values.get(key, ""))
        for key in SECRET_KEYS
        if values.get(key, "")
    }
    atomic_write(
        encrypted_path or ENC_SECRETS_FILE,
        encrypt_bytes("settings-secrets", json.dumps(secrets, sort_keys=True).encode("utf-8")),
    )


def record_format(payload: bytes) -> str:
    """Return "v3", "v2", "legacy" (pre-AES-GCM) or "unknown" for a payload."""
    if payload.startswith(_HEADER):
        return "v3"
    if payload.startswith(_HEADER_V2):
        return "v2"
    if payload.startswith(_LEGACY_AES_HEADER):
        return "legacy"
    return "unknown"


def _migrate_one(path: Path, record: str) -> str:
    """Re-encrypt one vault file to v3 when it is still v2. Returns the action."""
    if not path.exists():
        return "absent"
    payload = path.read_bytes()
    current = record_format(payload)
    if current == "v3":
        return "current"
    # Decrypt with whatever format it is (v2, or the pre-GCM legacy path used by
    # read_config_bytes) and write it back as v3.
    if current == "v2":
        plaintext = decrypt_bytes(record, payload)
    elif record == "configs" and current == "legacy":
        plaintext = _decrypt_legacy_config(payload)
    else:
        raise VaultError(f"{path.name} is not in a migratable format ({current})")
    atomic_write(path, encrypt_bytes(record, plaintext))
    return "migrated"


def migrate_legacy_records() -> dict[str, str]:
    """Upgrade v2 vault files to v3 (per-file salt, 600k PBKDF2 rounds).

    Safe to run repeatedly: files already on v3 are left untouched. Returns a
    map of record name -> action taken ("migrated", "current", "absent").
    """
    results: dict[str, str] = {}
    results["configs"] = _migrate_one(ENC_CONFIGS_FILE, "configs")
    results["secrets"] = _migrate_one(ENC_SECRETS_FILE, "settings-secrets")
    return results


def vault_status() -> dict[str, str | bool]:
    try:
        if secrets_vault_active():
            read_secrets()
        if config_vault_active():
            read_config_bytes()
        formats = []
        if ENC_CONFIGS_FILE.exists():
            formats.append(record_format(ENC_CONFIGS_FILE.read_bytes()))
        if ENC_SECRETS_FILE.exists():
            formats.append(record_format(ENC_SECRETS_FILE.read_bytes()))
        unique = sorted(set(formats)) or ["none"]
        detail = "Encrypted storage is available"
        if "v2" in unique or "legacy" in unique:
            detail = (
                "Encrypted storage is available but uses an older key format - "
                "run 'blackout vault migrate'"
            )
        return {
            "active": config_vault_active() or secrets_vault_active(),
            "healthy": True,
            "detail": detail,
            "format": ",".join(unique),
        }
    except VaultError as exc:
        return {"active": True, "healthy": False, "detail": str(exc)}


def settings_vault_status(enabled: bool) -> dict[str, str | bool]:
    if not enabled:
        return {"active": False, "healthy": True, "detail": "Credential vault is not enabled"}
    if not ENC_SECRETS_FILE.exists():
        return {"active": True, "healthy": False, "detail": "Encrypted credential vault is missing"}
    try:
        read_secrets()
        return {"active": True, "healthy": True, "detail": "Encrypted credential storage is available"}
    except VaultError as exc:
        return {"active": True, "healthy": False, "detail": str(exc)}
