"""Keyboard-driven settings and saved-config workflows."""
import base64
import json
import sys
from pathlib import Path
from typing import Callable, Optional

from rich.markup import escape
from rich.panel import Panel

from . import settings as cfg
from . import vault
from .config import manager
from .terminal_menu import Key, KeyReader, MenuItem, run_menu
from .theme import console, is_interactive, refresh_console_theme


MenuRunner = Callable[..., Optional[str]]
TextEditor = Callable[..., Optional[str]]
ConfirmRunner = Callable[[str], bool]


def _menu(
    runner: Optional[MenuRunner],
    title: str,
    items: list[MenuItem],
) -> Optional[str]:
    return (runner or run_menu)(title, items)


def _confirm(
    question: str,
    runner: Optional[MenuRunner],
    confirm_runner: Optional[ConfirmRunner],
) -> bool:
    if confirm_runner is not None:
        return bool(confirm_runner(question))
    choice = _menu(
        runner,
        question,
        [
            MenuItem("yes", "Yes", "Continue with this change"),
            MenuItem("no", "No", "Keep the current data"),
        ],
    )
    return choice == "yes"


def _acknowledge(title: str, runner: Optional[MenuRunner]) -> None:
    _menu(runner, title, [MenuItem("continue", "Continue", "Return to the previous menu")])


def _safe_value(key: str, value) -> str:
    if isinstance(value, list):
        value = ", ".join(str(item) for item in value)
    return escape(str(cfg.display_value(key, value)))


def _truncate(value: str, limit: int = 76) -> str:
    return value if len(value) <= limit else value[: limit - 1] + "…"


def _normalize_text_event(event) -> tuple[Key, str | None]:
    if isinstance(event, tuple):
        key, text = event
        return key, text
    if isinstance(event, Key):
        return event, None
    if isinstance(event, str):
        return Key.OTHER, event
    return Key.OTHER, None


def edit_text(
    prompt: str,
    initial: str = "",
    secret: bool = False,
    key_source: Optional[Callable[[], object]] = None,
) -> Optional[str]:
    """Edit one value using only keyboard input; Escape cancels the edit."""
    if key_source is None and not is_interactive():
        return None

    reader = KeyReader()
    chars = list(initial)
    cursor = len(chars)

    def read_event() -> tuple[Key, str | None]:
        event = key_source() if key_source is not None else reader.read_text_key()
        return _normalize_text_event(event)

    def render():
        value = "".join(chars)
        before_value = value[:cursor]
        after_value = value[cursor:]
        before = "•" * len(before_value) if secret else escape(before_value)
        after = "•" * len(after_value) if secret else escape(after_value)
        return Panel(
            f"[bold cyan]{escape(prompt)}[/bold cyan]\n\n"
            f"[white]{before}[/white][bold cyan]▌[/bold cyan][white]{after}[/white]\n\n"
            "[muted]Enter Save    Esc Cancel    ←/→ Move    Backspace Delete    Ctrl+C Quit[/muted]",
            title="Keyboard Editor",
            border_style="cyan",
        )

    from rich.live import Live

    with Live(
        render(),
        console=console,
        screen=True,
        auto_refresh=True,
        transient=True,
        get_renderable=render,
    ) as live:
        while True:
            live.update(render(), refresh=True)
            key, text = read_event()
            if key == Key.ENTER:
                return "".join(chars)
            if key == Key.ESCAPE:
                return None
            if key == Key.CTRL_C:
                raise KeyboardInterrupt
            if key == Key.LEFT:
                cursor = max(0, cursor - 1)
            elif key == Key.RIGHT:
                cursor = min(len(chars), cursor + 1)
            elif key == Key.BACKSPACE and cursor:
                del chars[cursor - 1]
                cursor -= 1
            elif text is not None and text.isprintable():
                chars.insert(cursor, text)
                cursor += len(text)


def _setting_items(keys: list[str], values: dict) -> list[MenuItem]:
    return [
        MenuItem(
            key,
            f"{key} = {_safe_value(key, values.get(key, cfg.DEFAULTS[key]))}",
            _truncate(cfg.describe(key)),
        )
        for key in keys
    ]


def _setting_input(
    key: str,
    value,
    menu_runner: Optional[MenuRunner],
    text_editor: Optional[TextEditor],
    confirm_runner: Optional[ConfirmRunner],
):
    if key in cfg.SENSITIVE_KEYS:
        action = _menu(
            menu_runner,
            f"Edit {key} (current value hidden)",
            [
                MenuItem("keep", "Keep current value", "Do not change this secret"),
                MenuItem("replace", "Replace value", "Type a new masked value"),
                MenuItem("clear", "Clear value", "Remove the stored secret"),
            ],
        )
        if action in (None, "keep"):
            return None
        if action == "clear":
            return ""
        if text_editor is None:
            return edit_text(key, secret=True)
        return text_editor(key, initial="", secret=True)

    choices = cfg.SETTING_CHOICES.get(key)
    if choices is None and isinstance(value, bool):
        choices = ("true", "false")
    if choices:
        items = [
            MenuItem(choice, choice, "Current value" if str(value) == choice else "")
            for choice in choices
        ]
        return _menu(menu_runner, f"Set {key}", items)

    if isinstance(value, list):
        initial = ", ".join(str(item) for item in value)
    else:
        initial = str(value)
    if text_editor is None:
        return edit_text(key, initial=initial)
    return text_editor(key, initial=initial, secret=False)


def _edit_setting(
    key: str,
    values: dict,
    menu_runner: Optional[MenuRunner],
    text_editor: Optional[TextEditor],
    confirm_runner: Optional[ConfirmRunner],
    require_confirmation: bool = False,
) -> None:
    old_value = values.get(key, cfg.DEFAULTS[key])
    new_value = _setting_input(key, old_value, menu_runner, text_editor, confirm_runner)
    if new_value is None:
        return
    if require_confirmation and not _confirm(
        f"Save {key}?",
        menu_runner,
        confirm_runner,
    ):
        return
    try:
        cfg.set_value(key, new_value)
    except ValueError as exc:
        console.print(f"[error]{escape(str(exc))}[/error]")
        _acknowledge("Setting was not changed", menu_runner)
        return
    if key in {"color_theme", "terminal_theme"}:
        refresh_console_theme()
    values[key] = cfg.coerce_value(key, new_value)
    console.print(f"[success]✓ {escape(key)} = {_safe_value(key, values[key])}[/success]")


def run_settings_menu(
    *,
    menu_runner: Optional[MenuRunner] = None,
    text_editor: Optional[TextEditor] = None,
    confirm_runner: Optional[ConfirmRunner] = None,
    require_confirmation: bool = False,
) -> None:
    """Open the keyboard settings editor."""
    while True:
        groups = cfg.iter_setting_groups()
        root_items = [
            MenuItem(name, name, f"{len(keys)} setting(s)")
            for name, keys in groups
        ]
        root_items.extend(
            [
                MenuItem("reset", "Reset all settings", "Restore factory defaults"),
                MenuItem("back", "Back", "Return to the previous menu"),
            ]
        )
        choice = _menu(menu_runner, "Blackout Kit — Settings", root_items)
        if choice in (None, "back"):
            return
        if choice == "reset":
            if _confirm("Reset all settings?", menu_runner, confirm_runner):
                cfg.reset()
                console.print("[success]✓ All settings reset to defaults.[/success]")
            continue

        group_keys = dict(groups).get(choice)
        if not group_keys:
            continue
        while True:
            values = cfg.load()
            setting_choice = _menu(
                menu_runner,
                f"Settings — {choice}",
                _setting_items(group_keys, values) + [
                    MenuItem("back", "Back", "Return to settings categories")
                ],
            )
            if setting_choice in (None, "back"):
                break
            if setting_choice in group_keys:
                _edit_setting(
                    setting_choice,
                    values,
                    menu_runner,
                    text_editor,
                    confirm_runner,
                    require_confirmation=require_confirmation,
                )


def _config_label(index: int, config) -> str:
    name = config.name or f"{config.protocol} {config.address}:{config.port}"
    compatibility = "SNI" if config.is_sni_compatible() else "direct"
    return escape(f"#{index + 1}  {name} · {config.transport_label()} · {compatibility}")


def _select_config(
    title: str,
    configs: list,
    menu_runner: Optional[MenuRunner],
) -> Optional[int]:
    items = [
        MenuItem(str(index), _config_label(index, config), "Select this saved config")
        for index, config in enumerate(configs)
    ]
    items.append(MenuItem("back", "Back", "Return to config actions"))
    choice = _menu(menu_runner, title, items)
    if choice in (None, "back"):
        return None
    return int(choice)


def _show_configs(
    configs: list,
    menu_runner: Optional[MenuRunner],
) -> None:
    if not configs:
        console.print("[muted]No saved configs.[/muted]")
        _acknowledge("Saved configs", menu_runner)
        return
    index = _select_config("Saved Configs", configs, menu_runner)
    if index is not None:
        config = configs[index]
        console.print(
            Panel(
                f"[muted]Number:[/muted] {index + 1}\n"
                f"[muted]Protocol:[/muted] {escape(config.protocol)}\n"
                f"[muted]Transport:[/muted] {escape(config.transport_label())}\n"
                f"[muted]Name:[/muted] {escape(config.name or '—')}\n"
                f"[muted]Compatibility:[/muted] {'SNI' if config.is_sni_compatible() else 'direct'}",
                title="Saved Config",
                border_style="cyan",
            )
        )
        _acknowledge("Config details", menu_runner)


def _add_config(
    text_editor: Optional[TextEditor],
    menu_runner: Optional[MenuRunner],
    confirm_runner: Optional[ConfirmRunner] = None,
    require_confirmation: bool = False,
) -> None:
    if text_editor is None:
        uri = edit_text("V2Ray URI")
    else:
        uri = text_editor("V2Ray URI", initial="", secret=False)
    if not uri:
        return
    if require_confirmation and not _confirm(
        "Save this upstream configuration?",
        menu_runner,
        confirm_runner,
    ):
        return
    try:
        config = manager.add_config(uri)
    except ValueError as exc:
        console.print(f"[error]{escape(str(exc))}[/error]")
        _acknowledge("Config was not added", menu_runner)
        return
    console.print(
        f"[success]✓ Added {escape(config.protocol.upper())} · "
        f"{escape(config.transport_label())}[/success]"
    )


def _replace_config(
    text_editor: Optional[TextEditor],
    menu_runner: Optional[MenuRunner],
    confirm_runner: Optional[ConfirmRunner] = None,
    require_confirmation: bool = False,
) -> None:
    configs = manager.load_configs()
    if not configs:
        console.print("[muted]No saved configs to replace.[/muted]")
        _acknowledge("Replace Config", menu_runner)
        return
    index = _select_config("Select Config to Replace", configs, menu_runner)
    if index is None:
        return
    if text_editor is None:
        uri = edit_text("New V2Ray URI")
    else:
        uri = text_editor("New V2Ray URI", initial="", secret=False)
    if not uri:
        return
    if require_confirmation and not _confirm(
        f"Replace saved config #{index + 1}?",
        menu_runner,
        confirm_runner,
    ):
        return
    try:
        replacement = manager.replace_config(index, uri)
    except (IndexError, ValueError) as exc:
        console.print(f"[error]{escape(str(exc))}[/error]")
        _acknowledge("Config was not replaced", menu_runner)
        return
    console.print(
        f"[success]✓ Replaced config #{index + 1} with "
        f"{escape(replacement.protocol.upper())} · {escape(replacement.transport_label())}[/success]"
    )


def _remove_config(
    menu_runner: Optional[MenuRunner],
    confirm_runner: Optional[ConfirmRunner],
) -> None:
    configs = manager.load_configs()
    if not configs:
        console.print("[muted]No saved configs to remove.[/muted]")
        _acknowledge("Remove Config", menu_runner)
        return
    index = _select_config("Select Config to Remove", configs, menu_runner)
    if index is None:
        return
    if not _confirm(
        f"Remove saved config #{index + 1}?",
        menu_runner,
        confirm_runner,
    ):
        return
    manager.remove_config(index)
    console.print(f"[success]✓ Removed config #{index + 1}.[/success]")


def _import_subscription(
    text_editor: Optional[TextEditor],
    menu_runner: Optional[MenuRunner],
    confirm_runner: Optional[ConfirmRunner] = None,
    require_confirmation: bool = False,
) -> None:
    if text_editor is None:
        url = edit_text("Subscription URL")
    else:
        url = text_editor("Subscription URL", initial="", secret=False)
    if not url:
        return
    if require_confirmation and not _confirm(
        "Fetch and save configurations from this subscription?",
        menu_runner,
        confirm_runner,
    ):
        return
    console.print("[info]Importing from subscription URL...[/info]")
    added, total = manager.import_and_merge(url)
    console.print(f"[success]✓ Imported {added} new configs. Total: {total}.[/success]")


def _export_setup(
    text_editor: Optional[TextEditor],
    menu_runner: Optional[MenuRunner],
    confirm_runner: Optional[ConfirmRunner],
) -> None:
    choice = _menu(
        menu_runner,
        "Export Setup",
        [
            MenuItem("print", "Print setup string", "Displays an unencrypted string"),
            MenuItem("file", "Save setup to file", "Writes the setup string to a local file"),
            MenuItem("back", "Back", "Return to config actions"),
        ],
    )
    if choice in (None, "back"):
        return
    if not _confirm(
        "Setup export may contain proxy credentials. Continue?",
        menu_runner,
        confirm_runner,
    ):
        return
    setup_data = manager.serialize_setup()
    setup_string = base64.b64encode(
        json.dumps(setup_data, sort_keys=True).encode("utf-8")
    ).decode("ascii")
    if choice == "print":
        console.print("[warning]This setup string is not encrypted.[/warning]")
        console.print(setup_string)
        _acknowledge("Setup export", menu_runner)
        return

    if text_editor is None:
        output = edit_text("Output file path")
    else:
        output = text_editor("Output file path", initial="", secret=False)
    if not output:
        return
    output_path = Path(output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(setup_string, encoding="utf-8")
    console.print(f"[success]✓ Setup exported to {escape(str(output_path))}.[/success]")


def _validate_setup_settings(settings_data: dict) -> dict:
    return cfg.validate_updates(settings_data)



def _validate_imported_configs(configs: list) -> list:
    seen = set()
    for config in configs:
        if not config.raw_uri:
            raise ValueError("Setup contains a config without a URI")
        if config.raw_uri in seen:
            raise ValueError("Setup contains duplicate config URIs")
        seen.add(config.raw_uri)
    return configs


def _import_setup(
    text_editor: Optional[TextEditor],
    menu_runner: Optional[MenuRunner],
    confirm_runner: Optional[ConfirmRunner],
) -> None:
    if text_editor is None:
        setup_string = edit_text("Base64 setup string")
    else:
        setup_string = text_editor("Base64 setup string", initial="", secret=False)
    if not setup_string:
        return
    try:
        blob = base64.b64decode("".join(setup_string.split()).encode("ascii"), validate=True)
        setup_data = json.loads(blob.decode("utf-8"))
        configs, settings_data = manager.deserialize_setup(setup_data)
        configs = _validate_imported_configs(configs)
        normalized = _validate_setup_settings(settings_data)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError, base64.binascii.Error) as exc:
        console.print(f"[error]Invalid setup string: {escape(str(exc))}[/error]")
        _acknowledge("Setup import failed", menu_runner)
        return

    console.print(
        f"[info]Setup contains {len(configs)} config(s) and "
        f"{len(normalized)} exportable setting(s).[/info]"
    )
    if not _confirm(
        "Import setup and overwrite current configs/settings?",
        menu_runner,
        confirm_runner,
    ):
        return

    old_configs = manager.load_configs()
    old_settings = cfg.load()
    try:
        manager.save_configs(configs)
        updated = dict(old_settings)
        updated.update(normalized)
        cfg.save(updated)
    except Exception as exc:
        try:
            manager.save_configs(old_configs)
        except Exception:
            pass
        console.print(f"[error]Setup import failed: {escape(str(exc))}[/error]")
        _acknowledge("Setup import failed", menu_runner)
        return
    console.print("[success]✓ Setup imported successfully.[/success]")


def _protect_configs(
    action: str,
    menu_runner: Optional[MenuRunner],
    confirm_runner: Optional[ConfirmRunner],
) -> None:
    if action == "encrypt":
        if vault.config_vault_active():
            console.print("[warning]Encrypted config storage is already active.[/warning]")
            return
        question = "Encrypt saved proxy configs and supported secrets?"
    else:
        if not vault.config_vault_active():
            console.print("[warning]No encrypted proxy config storage was found.[/warning]")
            return
        question = "Decrypt saved proxy configs and supported secrets?"
    if not _confirm(question, menu_runner, confirm_runner):
        return

    from . import security

    if action == "encrypt":
        security.obfuscate_configs()
        console.print("[success]✓ Proxy configs and supported secrets are encrypted at rest.[/success]")
    elif security.deobfuscate_configs():
        console.print("[success]✓ Encrypted proxy configs and secrets restored.[/success]")
    else:
        console.print("[error]Decryption failed; encrypted files were preserved.[/error]")


def run_config_menu(
    *,
    menu_runner: Optional[MenuRunner] = None,
    text_editor: Optional[TextEditor] = None,
    confirm_runner: Optional[ConfirmRunner] = None,
    require_confirmation: bool = False,
) -> None:
    """Open the keyboard manager for saved proxy configuration data."""
    root_items = [
        MenuItem("list", "List saved configs", "View safe summaries without credentials"),
        MenuItem("add", "Add URI", "Save a new V2Ray share URI"),
        MenuItem("replace", "Replace URI", "Replace a selected URI without exposing the old one"),
        MenuItem("remove", "Remove config", "Delete a selected saved config"),
        MenuItem("import", "Import subscription", "Fetch and merge a subscription URL"),
        MenuItem("export", "Export setup", "Print or save the portable setup string"),
        MenuItem("import-setup", "Import setup", "Validate and apply a portable setup string"),
        MenuItem("encrypt", "Encrypt saved data", "Protect configs and supported secrets at rest"),
        MenuItem("decrypt", "Decrypt saved data", "Restore encrypted configs for recovery"),
        MenuItem("back", "Back", "Return to the previous menu"),
    ]
    while True:
        choice = _menu(menu_runner, "Blackout Kit — Config", root_items)
        if choice in (None, "back"):
            return
        if choice == "list":
            _show_configs(manager.load_configs(), menu_runner)
        elif choice == "add":
            _add_config(
                text_editor,
                menu_runner,
                confirm_runner,
                require_confirmation=require_confirmation,
            )
        elif choice == "replace":
            _replace_config(
                text_editor,
                menu_runner,
                confirm_runner,
                require_confirmation=require_confirmation,
            )
        elif choice == "remove":
            _remove_config(menu_runner, confirm_runner)
        elif choice == "import":
            _import_subscription(
                text_editor,
                menu_runner,
                confirm_runner,
                require_confirmation=require_confirmation,
            )
        elif choice == "export":
            _export_setup(text_editor, menu_runner, confirm_runner)
        elif choice == "import-setup":
            _import_setup(text_editor, menu_runner, confirm_runner)
        elif choice in {"encrypt", "decrypt"}:
            _protect_configs(choice, menu_runner, confirm_runner)
