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

_HEADER = b"BKVLT02:"
_PROFILE_HEADER = b"BKPF01:"
_LEGACY_AES_HEADER = b"BKAE01:"
_PBKDF2_SALT = b"blackout-kit-aes256gcm-2026"
_PBKDF2_ITERS = 100_000
_PROFILE_PBKDF2_ITERS = 300_000
PROFILE_MAX_BYTES = 4 * 1024 * 1024


class VaultError(RuntimeError):
    """Raised when authenticated encrypted storage cannot be read or written."""


def _machine_id() -> bytes:
    try:
        if sys.platform == "win32":
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
            value = identifiers[0] if identifiers else ""
        else:
            value = platform.node()
        return value.encode() if value else b"blackout-kit-unknown-machine"
    except Exception:
        return b"blackout-kit-default-machine-id"


def _aes_key() -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_PBKDF2_SALT,
        iterations=_PBKDF2_ITERS,
    ).derive(_machine_id())


def _legacy_xor_key() -> bytes:
    return hashlib.sha256(_machine_id()).digest()


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

    nonce = os.urandom(12)
    ciphertext = AESGCM(_aes_key()).encrypt(nonce, plaintext, _aad(record))
    return _HEADER + base64.b64encode(nonce + ciphertext)


def decrypt_bytes(record: str, payload: bytes) -> bytes:
    if not payload.startswith(_HEADER):
        raise VaultError("Encrypted data is not in the current vault format")
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        blob = base64.b64decode(payload[len(_HEADER):], validate=True)
        if len(blob) <= 12:
            raise ValueError("encrypted payload is too short")
        return AESGCM(_aes_key()).decrypt(blob[:12], blob[12:], _aad(record))
    except Exception as exc:
        raise VaultError("Encrypted data cannot be authenticated on this machine") from exc


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
            return AESGCM(_aes_key()).decrypt(blob[:12], blob[12:], None)
        encoded = base64.b64decode(payload, validate=True)
        key = _legacy_xor_key()
        return bytes(value ^ key[index % len(key)] for index, value in enumerate(encoded))
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


def vault_status() -> dict[str, str | bool]:
    try:
        if secrets_vault_active():
            read_secrets()
        if config_vault_active():
            read_config_bytes()
        return {
            "active": config_vault_active() or secrets_vault_active(),
            "healthy": True,
            "detail": "Encrypted storage is available",
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
