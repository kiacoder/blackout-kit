import json

import pytest

from blackoutkit import vault


def test_portable_profile_round_trip():
    payload = {
        "schema_version": 1,
        "configs": ["vless://secret@example.com:443"],
        "settings": {"selected_engine": "xray"},
    }

    encrypted = vault.encrypt_profile(payload, "correct horse battery staple")
    restored = vault.decrypt_profile(encrypted, "correct horse battery staple")

    assert restored == payload
    assert b"secret@example.com" not in encrypted


def test_portable_profile_rejects_wrong_passphrase():
    encrypted = vault.encrypt_profile({"schema_version": 1, "value": "secret"}, "right")

    with pytest.raises(vault.VaultError, match="authenticated"):
        vault.decrypt_profile(encrypted, "wrong")


def test_portable_profile_rejects_tampering():
    encrypted = vault.encrypt_profile({"schema_version": 1, "value": "secret"}, "right")
    tampered = encrypted[:-1] + (b"A" if encrypted[-1:] != b"A" else b"B")

    with pytest.raises(vault.VaultError, match="authenticated"):
        vault.decrypt_profile(tampered, "right")


def test_portable_profile_rejects_unknown_format():
    with pytest.raises(vault.VaultError, match="unsupported format"):
        vault.decrypt_profile(b"not-a-profile", "right")


def test_portable_profile_rejects_oversized_payload(monkeypatch):
    monkeypatch.setattr(vault, "PROFILE_MAX_BYTES", 10)

    with pytest.raises(vault.VaultError, match="size limit"):
        vault.encrypt_profile({"value": "too large"}, "right")
