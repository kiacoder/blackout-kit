import json

from blackoutkit import settings, vault
from blackoutkit.config import manager


def _patch_vault_paths(monkeypatch, tmp_path):
    settings_file = tmp_path / "settings.json"
    configs_file = tmp_path / "configs.txt"
    config_vault = tmp_path / "configs.enc"
    secrets_vault = tmp_path / "secrets.enc"
    monkeypatch.setattr(settings, "APP_DATA_DIR", tmp_path)
    monkeypatch.setattr(settings, "SETTINGS_FILE", settings_file)
    monkeypatch.setattr(vault, "APP_DATA_DIR", tmp_path)
    monkeypatch.setattr(vault, "CONFIGS_FILE", configs_file)
    monkeypatch.setattr(vault, "ENC_CONFIGS_FILE", config_vault)
    monkeypatch.setattr(vault, "ENC_SECRETS_FILE", secrets_vault)
    monkeypatch.setattr(manager, "CONFIGS_FILE", configs_file)
    monkeypatch.setattr(manager.vault, "CONFIGS_FILE", configs_file)
    monkeypatch.setattr(manager.vault, "ENC_CONFIGS_FILE", config_vault)
    monkeypatch.setattr(manager.vault, "ENC_SECRETS_FILE", secrets_vault)
    monkeypatch.setattr(vault, "CONFIGS_FILE", configs_file)
    monkeypatch.setattr(vault, "ENC_CONFIGS_FILE", config_vault)
    monkeypatch.setattr(vault, "ENC_SECRETS_FILE", secrets_vault)
    return settings_file, configs_file, config_vault, secrets_vault


def test_secret_vault_removes_plaintext_and_loads_in_memory(monkeypatch, tmp_path):
    settings_file, _configs_file, _config_vault, secrets_vault = _patch_vault_paths(monkeypatch, tmp_path)
    # Field names come from vault.SECRET_KEYS so no credential-shaped literal
    # appears in this file; all values are fake.
    protected_values = {name: f"fixture-value-{i}" for i, name in enumerate(vault.SECRET_KEYS)}
    protected_values["xray_fingerprint"] = "firefox"
    settings_file.write_text(json.dumps(protected_values))

    settings.activate_secret_vault()

    persisted = json.loads(settings_file.read_text())
    for name in vault.SECRET_KEYS:
        assert name not in persisted
    vault_file_text = secrets_vault.read_text()
    for name, value in protected_values.items():
        if name == "xray_fingerprint":
            continue
        assert value not in vault_file_text
        assert settings.load()[name] == value


def test_secret_vault_updates_without_restoring_plaintext(monkeypatch, tmp_path):
    settings_file, _configs_file, _config_vault, _secrets_vault = _patch_vault_paths(monkeypatch, tmp_path)
    settings_file.write_text(json.dumps({"ikev2_password": "old"}))
    settings.activate_secret_vault()

    settings.set_value("ikev2_password", "new")

    assert settings.load()["ikev2_password"] == "new"
    assert "new" not in settings_file.read_text()


def test_empty_secret_vault_encrypts_credentials_added_later(monkeypatch, tmp_path):
    settings_file, _configs_file, _config_vault, secrets_vault = _patch_vault_paths(monkeypatch, tmp_path)
    settings_file.write_text(json.dumps({"xray_fingerprint": "chrome"}))
    settings.activate_secret_vault()

    settings.set_value("softether_password", "added-later")

    assert secrets_vault.exists()
    assert settings.load()["softether_password"] == "added-later"
    assert "added-later" not in settings_file.read_text()
    assert json.loads(settings_file.read_text())["secrets_vault_enabled"] is True


def test_encrypted_config_manager_round_trip_without_plaintext(monkeypatch, tmp_path):
    _settings_file, configs_file, config_vault, _secrets_vault = _patch_vault_paths(monkeypatch, tmp_path)
    manager.save_configs([
        manager.ProxyConfig(protocol="vless", address="example.com", port=443, raw_uri="vless://secret@example.com:443")
    ])
    vault.write_config_bytes(configs_file.read_bytes())
    vault.secure_remove_plaintext(configs_file)

    configs = manager.load_configs()
    manager.save_configs(configs)

    assert not configs_file.exists()
    assert config_vault.exists()
    assert manager.load_configs()[0].raw_uri == "vless://secret@example.com:443"


def test_vault_tampering_fails_closed(monkeypatch, tmp_path):
    _settings_file, _configs_file, config_vault, _secrets_vault = _patch_vault_paths(monkeypatch, tmp_path)
    vault.write_config_bytes(b"vless://secret@example.com:443")
    config_vault.write_bytes(config_vault.read_bytes()[:-1] + b"x")

    try:
        vault.read_config_bytes()
    except vault.VaultError:
        pass
    else:
        raise AssertionError("tampered authenticated ciphertext was accepted")


def test_v3_uses_a_distinct_salt_per_file():
    """A constant salt let two files share a key stream; v3 must not."""
    import base64

    from blackoutkit import vault

    first = base64.b64decode(vault.encrypt_bytes("configs", b"same-plaintext")[len(vault._HEADER):])
    second = base64.b64decode(vault.encrypt_bytes("configs", b"same-plaintext")[len(vault._HEADER):])
    assert first[: vault._SALT_LEN] != second[: vault._SALT_LEN]
    assert first != second


def test_v3_round_trip_and_tamper_rejection():
    from blackoutkit import vault

    payload = vault.encrypt_bytes("configs", b"round-trip")
    assert vault.record_format(payload) == "v3"
    assert vault.decrypt_bytes("configs", payload) == b"round-trip"

    tampered = bytearray(payload)
    tampered[-1] ^= 0xFF
    try:
        vault.decrypt_bytes("configs", bytes(tampered))
    except vault.VaultError:
        pass
    else:  # pragma: no cover - a silent pass here would be a security bug
        raise AssertionError("tampered vault payload was accepted")


def test_v2_payload_still_decrypts():
    """Files written before the v3 migration must stay readable."""
    import base64
    import os

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from blackoutkit import vault

    nonce = os.urandom(12)
    key = vault._aes_key(salt=vault._PBKDF2_SALT, iterations=vault._PBKDF2_ITERS)
    ciphertext = AESGCM(key).encrypt(nonce, b"legacy", vault._aad("configs"))
    legacy = vault._HEADER_V2 + base64.b64encode(nonce + ciphertext)

    assert vault.record_format(legacy) == "v2"
    assert vault.decrypt_bytes("configs", legacy) == b"legacy"
