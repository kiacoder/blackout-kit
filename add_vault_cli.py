with open("blackoutkit/typer_cli.py", "r") as f:
    code = f.read()

vault_cli_code = '''
# ── VAULT MANAGEMENT GROUP ──
vault_app = typer.Typer(help="Encrypted Vault Backup & Key Utility", no_args_is_help=False)
app.add_typer(vault_app, name="vault")

@vault_app.command("backup")
def vault_backup(
    output: str = typer.Option("blackout_vault_backup.json", "--output", "-o", help="Backup output path"),
):
    """Create an encrypted backup of the saved configs & settings vault."""
    from . import settings as cfg
    from .config.manager import load_configs, serialize_setup
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
    out_path = Path(output).expanduser().resolve()
    try:
        setup_data = serialize_setup()
        out_path.write_text(json.dumps(setup_data, indent=2), encoding="utf-8")
        console.print(f"[success]✓ Vault backup written to: {out_path}[/success]")
    except Exception as exc:
        console.print(f"[error]Failed to write vault backup: {exc}[/error]")

@vault_app.command("restore")
def vault_restore(
    path: str = typer.Argument(..., help="Path to backup file to restore"),
):
    """Restore vault configs & settings from a backup file."""
    from .typer_cli import _decode_setup, _apply_setup
    p = Path(path).expanduser().resolve()
    if not p.exists():
        console.print(f"[error]Backup file not found: {p}[/error]")
        return
    try:
        content = p.read_text(encoding="utf-8")
        setup_data = json.loads(content)
        from .typer_cli import _validate_setup_data
        configs, settings_data = _validate_setup_data(setup_data)
        _apply_setup(configs, settings_data)
        console.print(f"[success]✓ Vault restored successfully from {p} ({len(configs)} configs)![/success]")
    except Exception as exc:
        console.print(f"[error]Failed to restore vault backup: {exc}[/error]")
'''

if 'vault_app = typer.Typer' not in code:
    code += "\n" + vault_cli_code
    with open("blackoutkit/typer_cli.py", "w") as f:
        f.write(code)
    print("Added vault_app to blackoutkit/typer_cli.py")
