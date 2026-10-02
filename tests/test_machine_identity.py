"""Tests for the robust machine-identity chain behind vault and obfuscation keys."""
import base64
import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from blackoutkit import vault


@pytest.fixture(autouse=True)
def _fresh_identity_cache():
    vault.reset_machine_id_cache()
    yield
    vault.reset_machine_id_cache()


def test_candidates_on_linux_use_hostname_only():
    with patch.object(sys, "platform", "linux"), patch("platform.node", return_value="linux-host"):
        candidates = vault.machine_id_candidates()
    assert candidates[0] == b"linux-host"
    # Legacy constant recovery candidates are always last, decrypt-only.
    assert candidates[-2] == b"blackout-kit-default-machine-id"
    assert candidates[-1] == b"blackout-kit-unknown-machine"


def test_candidates_on_windows_prefer_smbios_uuid_over_hostname():
    wmic_output = MagicMock(return_value=MagicMock(stdout="UUID\nABCD-1234\n"))
    with patch.object(sys, "platform", "win32"), \
            patch("platform.node", return_value="THINKCOCO"), \
            patch("subprocess.run", wmic_output):
        candidates = vault.machine_id_candidates()
    assert candidates[0] == b"ABCD-1234"
    assert b"THINKCOCO" in candidates


def test_candidates_fall_back_to_cim_when_wmic_missing():
    def fake_run(cmd, **_kwargs):
        if cmd and cmd[0] == "wmic":
            raise FileNotFoundError("wmic removed on this Windows build")
        if cmd and cmd[0] == "powershell":
            return MagicMock(stdout="\n773BB471-DAAF-4A04-ACF2-C4C6E6F94D5B\n")
        return MagicMock(stdout="")

    with patch.object(sys, "platform", "win32"), \
            patch("platform.node", return_value="fallback-host"), \
            patch("subprocess.run", side_effect=fake_run):
        candidates = vault.machine_id_candidates()
    assert candidates[0] == b"773BB471-DAAF-4A04-ACF2-C4C6E6F94D5B"
    assert b"fallback-host" in candidates


def test_encrypt_uses_canonical_identity_decrypt_recovers_all_candidates():
    # Simulate a vault written under the historical constant fallback while
    # the machine now reports a canonical UUID: decryption must still work.
    canonical = b"canonical-machine-uuid"
    historical = b"blackout-kit-default-machine-id"
    plaintext = b'{"configs": []}'
    nonce = b"\x01" * 12
    payload = vault._HEADER + base64.b64encode(
        nonce + AESGCM(vault._aes_key(historical)).encrypt(nonce, plaintext, vault._aad("configs"))
    )

    with patch("blackoutkit.vault.machine_id_candidates", return_value=[canonical, historical]):
        assert vault.decrypt_bytes("configs", payload) == plaintext


def test_decrypt_still_fails_for_unknown_identity():
    plaintext = b"secret-content"
    nonce = b"\x02" * 12
    payload = vault._HEADER + base64.b64encode(
        nonce + AESGCM(vault._aes_key(b"someone-elses-machine")).encrypt(nonce, plaintext, vault._aad("configs"))
    )
    with patch("blackoutkit.vault.machine_id_candidates", return_value=[b"this-machine"]):
        with pytest.raises(vault.VaultError):
            vault.decrypt_bytes("configs", payload)


def test_identity_cache_invalidated_by_platform_or_hostname_change():
    with patch.object(sys, "platform", "linux"), patch("platform.node", return_value="host-a"):
        first = vault.machine_id_candidates()
    with patch.object(sys, "platform", "linux"), patch("platform.node", return_value="host-b"):
        second = vault.machine_id_candidates()
    assert first[0] == b"host-a"
    assert second[0] == b"host-b"


def test_round_trip_write_and_read_with_canonical_identity(tmp_path, monkeypatch):
    monkeypatch.setattr("blackoutkit.settings.APP_DATA_DIR", tmp_path)
    with patch.object(sys, "platform", "linux"), patch("platform.node", return_value="round-trip-host"):
        vault.reset_machine_id_cache()
        vault.write_config_bytes(b'{"configs": ["x"]}', encrypted_path=tmp_path / "configs.enc")
        assert vault.read_config_bytes(tmp_path / "configs.enc") == b'{"configs": ["x"]}'


def test_security_machine_id_delegates_to_candidate_chain():
    from blackoutkit import security as sec

    with patch.object(sys, "platform", "linux"), patch("platform.node", return_value="sec-host"):
        assert sec._get_machine_id() == b"sec-host"


def test_legacy_xor_written_with_hostname_key_still_decrypts():
    # Regression: machines where wmic was removed wrote legacy XOR files keyed
    # by hostname while the new canonical identity is the SMBIOS UUID. The
    # XOR path must try every candidate, not just the primary one.
    import base64
    import hashlib

    hostname_key = hashlib.sha256(b"old-hostname").digest()
    plaintext = b"vless://example-config-line-1\nvless://example-config-line-2\n"
    encoded = base64.b64encode(
        bytes(value ^ hostname_key[index % len(hostname_key)] for index, value in enumerate(plaintext))
    )

    with patch("blackoutkit.vault.machine_id_candidates",
               return_value=[b"new-uuid-identity", b"old-hostname"]):
        assert vault._decrypt_legacy_config(encoded) == plaintext


def test_legacy_xor_garbage_raises_vault_error():
    import base64
    import hashlib

    wrong_key = hashlib.sha256(b"completely-unrelated-key").digest()
    encoded = base64.b64encode(
        bytes(value ^ wrong_key[index % len(wrong_key)] for index, value in enumerate(b"some configs here" * 4))
    )
    with patch("blackoutkit.vault.machine_id_candidates",
               return_value=[b"identity-a", b"identity-b"]):
        with pytest.raises(vault.VaultError):
            vault._decrypt_legacy_config(encoded)


def test_encrypt_refuses_constant_only_identity():
    # The historical constants are decrypt-only: encrypting with a known
    # constant would silently forfeit machine binding.
    with patch.object(sys, "platform", "linux"), patch("platform.node", return_value=""):
        with pytest.raises(vault.VaultError):
            vault._machine_id()
