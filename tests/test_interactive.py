import base64
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from blackoutkit import interactive, settings
from blackoutkit.config.manager import ProxyConfig
from blackoutkit.terminal_menu import Key


def scripted_menu(*choices):
    values = iter(choices)
    return lambda *_args, **_kwargs: next(values)


def test_setting_groups_cover_each_default_once():
    groups = settings.iter_setting_groups()
    keys = [key for _name, group in groups for key in group]

    assert set(keys) == set(settings.DEFAULTS)
    assert len(keys) == len(set(keys))


def test_setting_input_uses_boolean_menu():
    menu = scripted_menu("false")

    assert interactive._setting_input("auto_set_proxy", True, menu, None, None) == "false"


def test_edit_setting_persists_through_settings_api(monkeypatch):
    set_value = Mock()
    monkeypatch.setattr(interactive.cfg, "set_value", set_value)
    monkeypatch.setattr(interactive.cfg, "coerce_value", lambda _key, value: value)

    interactive._edit_setting(
        "proxy_host",
        {"proxy_host": "127.0.0.1"},
        None,
        lambda *_args, **_kwargs: "localhost",
        None,
    )

    set_value.assert_called_once_with("proxy_host", "localhost")


def test_invalid_setting_does_not_report_success(monkeypatch):
    set_value = Mock(side_effect=ValueError("bad value"))
    monkeypatch.setattr(interactive.cfg, "set_value", set_value)
    acknowledged = Mock(return_value="continue")

    interactive._edit_setting(
        "proxy_port",
        {"proxy_port": 10809},
        acknowledged,
        lambda *_args, **_kwargs: "not-a-port",
        None,
    )

    set_value.assert_called_once_with("proxy_port", "not-a-port")
    acknowledged.assert_called_once()


def test_secret_setting_never_prefills_editor(monkeypatch):
    text_editor = Mock(return_value="new-secret")

    result = interactive._setting_input(
        "ikev2_password",
        "old-secret",
        scripted_menu("replace"),
        text_editor,
        None,
    )

    assert result == "new-secret"
    text_editor.assert_called_once_with("ikev2_password", initial="", secret=True)
    assert "old-secret" not in str(text_editor.call_args)


def test_settings_menu_back_does_not_write(monkeypatch):
    set_value = Mock()
    monkeypatch.setattr(interactive.cfg, "set_value", set_value)

    interactive.run_settings_menu(menu_runner=scripted_menu("back"))

    set_value.assert_not_called()


def test_settings_menu_edits_a_value_and_returns(monkeypatch):
    set_value = Mock()
    monkeypatch.setattr(interactive.cfg, "set_value", set_value)
    monkeypatch.setattr(interactive.cfg, "load", lambda: dict(interactive.cfg.DEFAULTS))
    choices = iter(["Network Ports", "proxy_port", "back", "back"])

    interactive.run_settings_menu(
        menu_runner=lambda *_args, **_kwargs: next(choices),
        text_editor=lambda *_args, **_kwargs: "12345",
    )

    set_value.assert_called_once_with("proxy_port", "12345")


def test_config_labels_do_not_include_raw_uri_credentials():
    config = ProxyConfig(
        protocol="vless",
        address="example.com",
        port=443,
        uuid="secret-uuid",
        raw_uri="vless://secret-uuid@example.com:443?security=tls#private",
        name="private",
    )

    label = interactive._config_label(0, config)

    assert "secret-uuid" not in label
    assert "vless://" not in label
    assert "private" in label


def test_replace_config_workflow_does_not_prefill_old_uri(monkeypatch):
    config = ProxyConfig(
        protocol="vless",
        address="old.example",
        port=443,
        raw_uri="vless://old-uuid@old.example:443",
        name="old",
    )
    monkeypatch.setattr(interactive.manager, "load_configs", lambda: [config])
    replace = Mock(return_value=config)
    monkeypatch.setattr(interactive.manager, "replace_config", replace)
    editor = Mock(return_value="vless://new-uuid@new.example:443")

    interactive._replace_config(editor, scripted_menu("0"))

    editor.assert_called_once_with("New V2Ray URI", initial="", secret=False)
    replace.assert_called_once_with(0, "vless://new-uuid@new.example:443")


def test_remove_config_requires_confirmation(monkeypatch):
    config = ProxyConfig(
        protocol="vless",
        address="example.com",
        port=443,
        raw_uri="vless://uuid@example.com:443",
    )
    monkeypatch.setattr(interactive.manager, "load_configs", lambda: [config])
    remove = Mock()
    monkeypatch.setattr(interactive.manager, "remove_config", remove)

    interactive._remove_config(scripted_menu("0"), lambda _question: False)

    remove.assert_not_called()


def test_setup_import_validates_before_confirmation_or_writes(monkeypatch):
    payload = {
        "configs": ["vless://uuid@example.com:443"],
        "settings": {"proxy_port": "not-an-int"},
    }
    blob = base64.b64encode(json.dumps(payload).encode()).decode()
    confirm = Mock(return_value=True)
    save_configs = Mock()
    save_settings = Mock()
    monkeypatch.setattr(interactive.manager, "save_configs", save_configs)
    monkeypatch.setattr(interactive.cfg, "save", save_settings)

    interactive._import_setup(lambda *_args, **_kwargs: blob, None, confirm)

    confirm.assert_not_called()
    save_configs.assert_not_called()
    save_settings.assert_not_called()


def test_setup_import_cancel_does_not_write(monkeypatch):
    payload = {
        "configs": ["vless://uuid@example.com:443"],
        "settings": {"proxy_port": 12345},
    }
    blob = base64.b64encode(json.dumps(payload).encode()).decode()
    confirm = Mock(return_value=False)
    save_configs = Mock()
    save_settings = Mock()
    monkeypatch.setattr(interactive.manager, "save_configs", save_configs)
    monkeypatch.setattr(interactive.cfg, "save", save_settings)

    interactive._import_setup(lambda *_args, **_kwargs: blob, None, confirm)

    confirm.assert_called_once()
    save_configs.assert_not_called()
    save_settings.assert_not_called()


def test_config_menu_back_does_not_touch_config_manager(monkeypatch):
    load_configs = Mock()
    monkeypatch.setattr(interactive.manager, "load_configs", load_configs)

    interactive.run_config_menu(menu_runner=scripted_menu("back"))

    load_configs.assert_not_called()


def test_text_editor_supports_injected_printable_input(monkeypatch):
    monkeypatch.setattr(interactive, "is_interactive", lambda: True)
    events = iter([("other", "a"), (Key.ENTER, None)])

    result = interactive.edit_text(
        "Value",
        key_source=lambda: next(events),
    )

    assert result == "a"


def test_text_editor_escape_cancels(monkeypatch):
    monkeypatch.setattr(interactive, "is_interactive", lambda: True)

    assert interactive.edit_text("Value", key_source=lambda: Key.ESCAPE) is None
