from blackoutkit import settings
from blackoutkit import theme


def test_terminal_theme_validation_and_description():
    assert settings.validate("terminal_theme", "light") == (True, "")
    assert settings.validate("terminal_theme", "blue") == (False, "must be: dark / light")
    assert "does not change your terminal app" in settings.describe("terminal_theme")


def test_light_palette_uses_dark_foreground(monkeypatch):
    monkeypatch.setattr(theme._cfg, "load", lambda: {"color_theme": "blue", "terminal_theme": "light"})

    rich_theme = theme.build_theme()

    assert rich_theme.styles["heading"].color.name == "black"
    assert rich_theme.styles["panel.border"].color.name == "blue"


def test_prompts_use_defaults_when_not_interactive(monkeypatch):
    monkeypatch.setattr(theme, "is_interactive", lambda: False)

    assert theme.ask_choice("Choose", ["a", "b"], default="b") == "b"
    assert theme.ask_text("Value", default="saved") == "saved"
    assert theme.ask_int("Count", default=3) == 3
    assert theme.confirm("Proceed", default=True) is True


def test_friendly_error_panel_redacts_exception_text():
    panel = theme.friendly_error_panel(RuntimeError("vless://secret@example.test:443?token=secret"))

    rendered = str(panel.renderable)
    assert "vless://" not in rendered
    assert "secret" not in rendered
    assert "blackout doctor" in rendered
