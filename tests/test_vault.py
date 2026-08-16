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
    settings_file.write_text(json.dumps({
        "ikev2_password": "vpn-secret",
        "ikev2_psk": "psk-secret",
        "softether_password": "softether-secret",
        "xray_fingerprint": "firefox",
    }))

    settings.activate_secret_vault()

    persisted = json.loads(settings_file.read_text())
    assert "ikev2_password" not in persisted
    assert "ikev2_psk" not in persisted
    assert "softether_password" not in persisted
    assert "vpn-secret" not in secrets_vault.read_text()
    assert settings.load()["ikev2_password"] == "vpn-secret"
    assert settings.load()["softether_password"] == "softether-secret"


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
